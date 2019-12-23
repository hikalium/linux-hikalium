#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>

#include "../nvdimm/pmem.h"

#include "ndckpt.h"

static const uint64_t kCacheLineSize = 64;
static const uint64_t kPageSizeExponent = 12;

static inline void ndckpt_clwb(volatile void *__p)
{
	asm volatile("clwb %0" : "+m"(*(volatile char __force *)__p));
}

static inline void ndckpt_invlpg(volatile void *__p)
{
	asm volatile("invlpg %0" : "+m"(*(volatile char __force *)__p));
}

static inline void ndckpt_clwb_range(volatile void *p, size_t byte_size)
{
	const uint64_t end_addr = (uint64_t)p + byte_size;
	const size_t num_of_lines =
		((end_addr - ((uint64_t)p & ~(kCacheLineSize - 1))) +
		 kCacheLineSize - 1) /
		kCacheLineSize;
	size_t i;
	for (i = 0; i < num_of_lines; i++) {
		ndckpt_clwb(p);
		p = (volatile uint8_t *)p + kCacheLineSize;
	}
}

static inline void memcpy_and_clwb(void *dst, void *src, size_t size)
{
	memcpy(dst, src, size);
	ndckpt_clwb_range(dst, size);
}

static inline void ndckpt_sfence(void)
{
	asm volatile("sfence");
}

static inline const char *get_str_dram_or_nvdimm(void *p)
{
	return ndckpt_is_virt_addr_in_nvdimm(p) ? "NVDIMM" : ">DRAM<";
}

static inline const char *get_str_dram_or_nvdimm_phys(uint64_t p)
{
	return ndckpt_is_phys_addr_in_nvdimm(p) ? "NVDIMM" : ">DRAM<";
}

static inline void switch_mm_context(struct mm_struct *mm, pgd_t *new_pgd)
{
	// Set mm->pgd and cr3
	// https://elixir.bootlin.com/linux/v5.1.3/source/arch/x86/include/asm/tlbflush.h#L131
	// TODO: We believe that we can specify CR3_NOFLUSH here,
	// but it does not work for now.
	uint64_t new_cr3 = (CR3_ADDR_MASK & ndckpt_virt_to_phys(new_pgd)) |
			   (CR3_PCID_MASK & __read_cr3()) /* | CR3_NOFLUSH */;
	pr_ndckpt("cr3(new)  = 0x%016llX\n", new_cr3);
	mm->pgd = new_pgd;
	write_cr3(new_cr3);
}

static inline bool is_vma_ndckpt_target(struct vm_area_struct *vma)
{
	BUG_ON(!vma);
	return vma->vm_ckpt_flags & VM_CKPT_TARGET;
}

#define POBJ_SIGNATURE 0x4F50534F6D75696CULL
struct PersistentObjectHeader {
	// This struct is placed at the end of the page,
	// just before the allocated pages.
	volatile uint64_t signature;
	volatile uint64_t id;
	volatile uint64_t num_of_pages;
	struct PersistentObjectHeader *volatile next;
};

#define PMAN_SIGNATURE 0x4D50534F6D75696CULL
struct PersistentMemoryManager {
	volatile uint64_t page_idx; // in virtual addr
	volatile uint64_t num_of_pages;
	struct PersistentObjectHeader *volatile head;
	struct PersistentProcessInfo *volatile last_proc_info;
	struct PersistentObjectHeader sentinel;
	// 2nd cache line begins here
	volatile uint64_t signature;
};

// @ndckpt.c
extern struct kobject *kobj_ndckpt;
extern struct pmem_device *first_pmem_device;

// @pgtable.c
/*
  Intel / Linux
  PML4: pgd_t[512];
  PDPT: pud_t[512];
  PD  : pmd_t[512];
  PT  : pte_t[512];
*/
#define PADDR_TO_IDX_IN_PML4(paddr) ((paddr >> (12 + 9 * 3)) & 0x1FF)
#define PADDR_TO_IDX_IN_PDPT(paddr) ((paddr >> (12 + 9 * 2)) & 0x1FF)
#define PADDR_TO_IDX_IN_PD(paddr) ((paddr >> (12 + 9 * 1)) & 0x1FF)
#define PADDR_TO_IDX_IN_PT(paddr) ((paddr >> (12 + 9 * 0)) & 0x1FF)

static inline void replace_pdpt_with_nvdimm_page(pgd_t *ent_of_page)
{
	void *old_page_vaddr = (void *)ndckpt_pgd_page_vaddr(*ent_of_page);
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	memcpy_and_clwb(new_page_vaddr, old_page_vaddr, PAGE_SIZE);
	ent_of_page->pgd = (ent_of_page->pgd & ~PTE_PFN_MASK) | new_page_paddr;
}

static inline void replace_pd_with_nvdimm_page(pud_t *ent_of_page)
{
	void *old_page_vaddr = (void *)ndckpt_pud_page_vaddr(*ent_of_page);
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	memcpy_and_clwb(new_page_vaddr, old_page_vaddr, PAGE_SIZE);
	ent_of_page->pud = (ent_of_page->pud & ~PTE_PFN_MASK) | new_page_paddr;
}

static inline void replace_pt_with_nvdimm_page(pmd_t *ent_of_page)
{
	void *old_page_vaddr = (void *)ndckpt_pmd_page_vaddr(*ent_of_page);
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	memcpy_and_clwb(new_page_vaddr, old_page_vaddr, PAGE_SIZE);
	ent_of_page->pmd = (ent_of_page->pmd & ~PTE_PFN_MASK) | new_page_paddr;
}

static inline void replace_page_with_nvdimm_page(pte_t *ent_of_page)
{
	void *old_page_vaddr = (void *)ndckpt_page_page_vaddr(*ent_of_page);
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	memcpy_and_clwb(new_page_vaddr, old_page_vaddr, PAGE_SIZE);
	ent_of_page->pte = (ent_of_page->pte & ~PTE_PFN_MASK) | new_page_paddr;
}

void ndckpt_print_pml4(pgd_t *pgd);
void erase_mappings_to_dram(pgd_t *t4, uint64_t start, uint64_t end);
void pr_ndckpt_pgtable_range(pgd_t *t4, uint64_t start, uint64_t end);

// @pman.c
bool pman_is_valid(struct PersistentMemoryManager *pman);
void pman_update_head(struct PersistentMemoryManager *pman,
		      struct PersistentObjectHeader *pobj);
void pman_set_last_proc_info(struct PersistentMemoryManager *pman,
			     struct PersistentProcessInfo *pproc);
void pman_init(struct pmem_device *pmem);
void *pman_alloc_pages(struct PersistentMemoryManager *pman,
		       uint64_t num_of_pages_requested);
void pman_printk(struct PersistentMemoryManager *pman);
void pman_print_last_proc_info(struct PersistentMemoryManager *pman);

// @pobj.c
bool pobj_is_valid(struct PersistentObjectHeader *pobj);
void pobj_init(struct PersistentObjectHeader *pobj, uint64_t id,
	       uint64_t num_of_pages, struct PersistentObjectHeader *next);
void *pobj_get_base(struct PersistentObjectHeader *pobj);
struct PersistentObjectHeader *pobj_get_header(void *addr);
void pobj_printk(struct PersistentObjectHeader *pobj);

// @pproc.c
struct PersistentProcessInfo;
bool pproc_is_valid(struct PersistentProcessInfo *pproc);
struct PersistentProcessInfo *pproc_alloc(void);
void pproc_set_pgd(struct PersistentProcessInfo *pproc, int ctx_idx,
		   pgd_t *pgd);
void pproc_set_valid_ctx(struct PersistentProcessInfo *pproc, int ctx_idx);
int pproc_get_running_ctx(struct PersistentProcessInfo *pproc);
void pproc_set_regs(struct PersistentProcessInfo *proc, int ctx_idx,
		    struct pt_regs *regs);
void pproc_restore_regs(struct pt_regs *regs,
			struct PersistentProcessInfo *proc, int ctx_idx);
void pproc_print_regs(struct PersistentProcessInfo *proc, int ctx_idx);
void pproc_printk(struct PersistentProcessInfo *pproc);
void pproc_commit(struct PersistentProcessInfo *pproc, struct mm_struct *mm,
		  struct pt_regs *regs);
void pproc_restore(struct task_struct *task,
		   struct PersistentProcessInfo *pproc);

// @sysfs.c
int sysfs_interface_init(void);
