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

static inline void ndckpt_mfence(void)
{
	asm volatile("mfence");
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

static inline uint64_t ndckpt_v2p(void *v)
{
	// v can be in NVDIMM or DRAM
	return ndckpt_is_virt_addr_in_nvdimm(v) ? ndckpt_virt_to_phys(v) :
						  __pa(v);
}

static inline void *ndckpt_p2v(uint64_t p)
{
	// v can be in NVDIMM or DRAM
	return ndckpt_is_phys_addr_in_nvdimm(p) ? ndckpt_phys_to_virt(p) :
						  __va(p);
}

#define TABLE_STATE_X 0
#define TABLE_STATE_Tn 2
#define TABLE_STATE_Tv 3

static inline int table_state(uint64_t ev)
{
	if ((ev & _PAGE_PRESENT) == 0) {
		return TABLE_STATE_X;
	}
	return ndckpt_is_phys_addr_in_nvdimm(ev & PTE_PFN_MASK) ?
		       TABLE_STATE_Tn :
		       TABLE_STATE_Tv;
}

#define PAGE_STATE_X 0
#define PAGE_STATE_Pv 4
#define PAGE_STATE_Pnc 6
#define PAGE_STATE_Pnd 7

static inline int page_state(uint64_t ev)
{
	if ((ev & _PAGE_PRESENT) == 0) {
		return PAGE_STATE_X;
	}
	if (ndckpt_is_phys_addr_in_nvdimm(ev & PTE_PFN_MASK)) {
		return PAGE_STATE_Pnc + ((ev & _PAGE_DIRTY) ? 1 : 0);
	}
	return PAGE_STATE_Pv;
}

static inline int table_state_pml4e(pgd_t *e)
{
	return table_state(e->pgd);
}

static inline int table_state_pdpte(pud_t *e)
{
	return table_state(e->pud);
}

static inline int table_state_pde(pmd_t *e)
{
	return table_state(e->pmd);
}

static inline int page_state_pte(pte_t *e)
{
	return page_state(e->pte);
}

static inline void traverse_pml4e(uint64_t addr, pgd_t *t4, pgd_t **e4,
				  pud_t **t3)
{
	(*e4) = &t4[PADDR_TO_IDX_IN_PML4(addr)];
	if (((*e4)->pgd & _PAGE_PRESENT) == 0) {
		*t3 = NULL;
		return;
	}
	*t3 = ndckpt_p2v((*e4)->pgd & PTE_PFN_MASK);
}

static inline void traverse_pdpte(uint64_t addr, pud_t *t3, pud_t **e3,
				  pmd_t **t2)
{
	(*e3) = &t3[PADDR_TO_IDX_IN_PDPT(addr)];
	if (((*e3)->pud & _PAGE_PRESENT) == 0) {
		*t2 = NULL;
		return;
	}
	*t2 = ndckpt_p2v((*e3)->pud & PTE_PFN_MASK);
}

static inline void traverse_pde(uint64_t addr, pmd_t *t2, pmd_t **e2,
				pte_t **t1)
{
	(*e2) = &t2[PADDR_TO_IDX_IN_PD(addr)];
	if (((*e2)->pmd & _PAGE_PRESENT) == 0) {
		*t1 = NULL;
		return;
	}
	*t1 = ndckpt_p2v((*e2)->pmd & PTE_PFN_MASK);
}

static inline void traverse_pte(uint64_t addr, pte_t *t1, pte_t **e1, void **t0)
{
	(*e1) = &t1[PADDR_TO_IDX_IN_PT(addr)];
	if (((*e1)->pte & _PAGE_PRESENT) == 0) {
		*t0 = NULL;
		return;
	}
	*t0 = ndckpt_p2v((*e1)->pte & PTE_PFN_MASK);
}

static inline uint64_t next_pml4e_addr(uint64_t addr)
{
	return (addr + PGDIR_SIZE) & PGDIR_MASK;
}
static inline uint64_t next_pdpte_addr(uint64_t addr)
{
	return (addr + PUD_SIZE) & PUD_MASK;
}
static inline uint64_t next_pde_addr(uint64_t addr)
{
	return (addr + PMD_SIZE) & PMD_MASK;
}
static inline uint64_t next_pte_addr(uint64_t addr)
{
	return (addr + PAGE_SIZE) & PAGE_MASK;
}

static inline void unmap_pdpt_and_clwb(pgd_t *ent_of_page)
{
	ent_of_page->pgd = 0;
	ndckpt_clwb(ent_of_page);
}

static inline void copy_pml4e_and_clwb(pgd_t *dst, pgd_t *src)
{
	*dst = *src;
	ndckpt_clwb(dst);
}

static inline void map_zeroed_nvdimm_page_pdpt(pgd_t *ent_of_page)
{
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	ent_of_page->pgd = (ent_of_page->pgd & ~PTE_PFN_MASK) | new_page_paddr |
			   _PAGE_PRESENT;
	ndckpt_clwb(ent_of_page);
}

static inline void replace_pdpt_with_nvdimm_page(pgd_t *ent_of_page)
{
	void *old_page_vaddr = (void *)ndckpt_pgd_page_vaddr(*ent_of_page);
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	if (old_page_vaddr)
		memcpy_and_clwb(new_page_vaddr, old_page_vaddr, PAGE_SIZE);
	ent_of_page->pgd = (ent_of_page->pgd & ~PTE_PFN_MASK) | new_page_paddr;
	ndckpt_clwb(ent_of_page);
}

static inline void unmap_pd_and_clwb(pud_t *ent_of_page)
{
	ent_of_page->pud = 0;
	ndckpt_clwb(ent_of_page);
}

static inline void copy_pdpte_and_clwb(pud_t *dst, pud_t *src)
{
	*dst = *src;
	ndckpt_clwb(dst);
}

static inline void map_zeroed_nvdimm_page_pd(pud_t *ent_of_page)
{
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	ent_of_page->pud = (ent_of_page->pud & ~PTE_PFN_MASK) | new_page_paddr |
			   _PAGE_PRESENT;
	ndckpt_clwb(ent_of_page);
}

static inline void replace_pd_with_nvdimm_page(pud_t *ent_of_page)
{
	void *old_page_vaddr = (void *)ndckpt_pud_page_vaddr(*ent_of_page);
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	memcpy_and_clwb(new_page_vaddr, old_page_vaddr, PAGE_SIZE);
	ent_of_page->pud = (ent_of_page->pud & ~PTE_PFN_MASK) | new_page_paddr;
	ndckpt_clwb(ent_of_page);
}

static inline void unmap_pt_and_clwb(pmd_t *ent_of_page)
{
	ent_of_page->pmd = 0;
	ndckpt_clwb(ent_of_page);
}

static inline void copy_pde_and_clwb(pmd_t *dst, pmd_t *src)
{
	*dst = *src;
	ndckpt_clwb(dst);
}

static inline void map_zeroed_nvdimm_page_pt(pmd_t *ent_of_page)
{
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	ent_of_page->pmd = (ent_of_page->pmd & ~PTE_PFN_MASK) | new_page_paddr |
			   _PAGE_PRESENT;
	ndckpt_clwb(ent_of_page);
}

static inline void replace_pt_with_nvdimm_page(pmd_t *ent_of_page)
{
	void *old_page_vaddr = (void *)ndckpt_pmd_page_vaddr(*ent_of_page);
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	memcpy_and_clwb(new_page_vaddr, old_page_vaddr, PAGE_SIZE);
	ent_of_page->pmd = (ent_of_page->pmd & ~PTE_PFN_MASK) | new_page_paddr;
	ndckpt_clwb(ent_of_page);
}

static inline void unmap_page_and_clwb(pte_t *ent_of_page)
{
	ent_of_page->pte = 0;
	ndckpt_clwb(ent_of_page);
}

static inline void copy_pte_and_clwb(pte_t *dst, pte_t *src)
{
	*dst = *src;
	ndckpt_clwb(dst);
}

static inline void map_zeroed_nvdimm_page_page(pte_t *ent_of_page)
{
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	ent_of_page->pte = (ent_of_page->pte & ~PTE_PFN_MASK) | new_page_paddr |
			   _PAGE_PRESENT;
	ndckpt_clwb(ent_of_page);
}

static inline void replace_page_with_nvdimm_page(pte_t *ent_of_page)
{
	void *old_page_vaddr = (void *)ndckpt_page_page_vaddr(*ent_of_page);
	void *new_page_vaddr = ndckpt_alloc_zeroed_page();
	uint64_t new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
	memcpy_and_clwb(new_page_vaddr, old_page_vaddr, PAGE_SIZE);
	ent_of_page->pte = (ent_of_page->pte & ~PTE_PFN_MASK) | new_page_paddr;
	ndckpt_clwb(ent_of_page);
}

void ndckpt_print_pml4(pgd_t *pgd);
void pr_ndckpt_pml4(pgd_t *pgd);
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
pgd_t *pproc_get_org_pgd(struct PersistentProcessInfo *pproc);
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
void pproc_commit(struct task_struct *target,
		  struct PersistentProcessInfo *pproc, struct mm_struct *mm,
		  struct pt_regs *regs);
int64_t pproc_restore(struct PersistentMemoryManager *, struct task_struct *,
		      struct PersistentProcessInfo *);
int64_t pproc_init(struct task_struct *, struct PersistentMemoryManager *,
		   struct mm_struct *, struct pt_regs *);

// @sysfs.c
int sysfs_interface_init(void);
