#include "ndckpt_internal.h"

struct kobject *kobj_ndckpt;
struct pmem_device *first_pmem_device;

void ndckpt_notify_pmem(struct pmem_device *pmem)
{
	if (!first_pmem_device) {
		printk("ndckpt: first pmem notified\n");
		first_pmem_device = pmem;
		printk("ndckpt: phys_addr: 0x%016llx\n", pmem->phys_addr);
		printk("ndckpt: size     : 0x%08lx\n", pmem->size);
		printk("ndckpt: virt_addr: 0x%016llx\n",
		       (unsigned long long)pmem->virt_addr);
	}
}
EXPORT_SYMBOL(ndckpt_notify_pmem);

int ndckpt_enable_checkpointing(struct task_struct *task, int restore_obj_id)
{
	if ((task->flags & PF_FORKNOEXEC) == 0) {
		// ndckpt can be enabled only before exec after fork.
		return -EINVAL;
	}
	task->flags |= PF_NDCKPT_ENABLED;
	printk("ndckpt: checkpoint enabled on pid=%d\n", task->pid);
	printk("ndckpt:   task flags = 0x%08X\n", task->flags);
	return 0;
}
EXPORT_SYMBOL(ndckpt_enable_checkpointing);

uint64_t ndckpt_alloc_phys_page(void)
{
	return ndckpt_virt_to_phys(
		pman_alloc_pages(first_pmem_device->virt_addr, 1));
}
EXPORT_SYMBOL(ndckpt_alloc_phys_page);

void *ndckpt_alloc_zeroed_page(void)
{
	void *page = pman_alloc_pages(first_pmem_device->virt_addr, 1);
	memset(page, 0, PAGE_SIZE);
	return page;
}
EXPORT_SYMBOL(ndckpt_alloc_zeroed_page);

uint64_t ndckpt_virt_to_phys(void *vaddr)
{
	return (uint64_t)vaddr - (uint64_t)first_pmem_device->virt_addr +
	       first_pmem_device->phys_addr;
}
EXPORT_SYMBOL(ndckpt_virt_to_phys);

void *ndckpt_phys_to_virt(uint64_t paddr)
{
	return (void *)(paddr + (uint64_t)first_pmem_device->virt_addr -
			first_pmem_device->phys_addr);
}
EXPORT_SYMBOL(ndckpt_phys_to_virt);

int ndckpt_is_phys_addr_in_nvdimm(uint64_t paddr)
{
	return first_pmem_device &&
	       (paddr - first_pmem_device->phys_addr) < first_pmem_device->size;
}
EXPORT_SYMBOL(ndckpt_is_phys_addr_in_nvdimm);

int ndckpt_is_virt_addr_in_nvdimm(void *vaddr)
{
	return first_pmem_device &&
	       ((uint64_t)vaddr - (uint64_t)first_pmem_device->virt_addr) <
		       first_pmem_device->size;
}
EXPORT_SYMBOL(ndckpt_is_virt_addr_in_nvdimm);

/*
  Intel / Linux
  PML4: pgd_t[512];
        p4d_t <- Only used when 5level paging is used.
  PDPT: pud_t[512];
  PD  : pmd_t[512];
  PT  : pte_t[512];

  @mm/memory.c
  zap_p*_range()
  free_p*_range()


*/

static inline const char *get_str_dram_or_nvdimm(void *p)
{
	return ndckpt_is_virt_addr_in_nvdimm(p) ? "NVDIMM" : ">DRAM<";
}

static inline const char *get_str_dram_or_nvdimm_phys(uint64_t p)
{
	return ndckpt_is_phys_addr_in_nvdimm(p) ? "NVDIMM" : ">DRAM<";
}

static void ndckpt_print_pt(pte_t *pte)
{
	int i;
	uint64_t e;
	printk("ndckpt:       PT   @ 0x%016llX on %s\n", (uint64_t)pte,
	       get_str_dram_or_nvdimm(pte));
	if (!ndckpt_is_virt_addr_in_nvdimm(pte))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pte_t); i++) {
		e = pte[i].pte;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt:       PAGE[0x%03X] = 0x%016llX on %s\n", i, e,
		       get_str_dram_or_nvdimm_phys(e & PTE_PFN_MASK));
	}
}

static void ndckpt_print_pd(pmd_t *pmd)
{
	int i;
	uint64_t e;
	printk("ndckpt:     PD   @ 0x%016llX on %s\n", (uint64_t)pmd,
	       get_str_dram_or_nvdimm(pmd));
	if (!ndckpt_is_virt_addr_in_nvdimm(pmd))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pmd_t); i++) {
		e = pmd[i].pmd;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt:     PD  [0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pt((pte_t *)ndckpt_pmd_page_vaddr(pmd[i]));
	}
}

static void ndckpt_print_pdpt(pud_t *pud)
{
	int i;
	uint64_t e;
	printk("ndckpt:   PDPT @ 0x%016llX on %s\n", (uint64_t)pud,
	       get_str_dram_or_nvdimm(pud));
	if (!ndckpt_is_virt_addr_in_nvdimm(pud))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pud_t); i++) {
		e = pud[i].pud;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt:   PDPT[0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pd((pmd_t *)ndckpt_pud_page_vaddr(pud[i]));
	}
}

void ndckpt_print_pml4(pgd_t *pgd)
{
	int i;
	uint64_t e;
	printk("ndckpt: PML4 @ 0x%016llX on %s\n", (uint64_t)pgd,
	       get_str_dram_or_nvdimm(pgd));
	if (!ndckpt_is_virt_addr_in_nvdimm(pgd))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pgd_t); i++) {
		e = (uint64_t)pgd[i].pgd;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt: PML4[0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pdpt((pud_t *)ndckpt_pgd_page_vaddr(pgd[i]));
	}
}

#define PADDR_TO_IDX_IN_PML4(paddr) ((paddr >> (12 + 9 * 3)) & 0x1FF)
#define PADDR_TO_IDX_IN_PDPT(paddr) ((paddr >> (12 + 9 * 2)) & 0x1FF)
#define PADDR_TO_IDX_IN_PD(paddr) ((paddr >> (12 + 9 * 1)) & 0x1FF)
#define PADDR_TO_IDX_IN_PT(paddr) ((paddr >> (12 + 9 * 0)) & 0x1FF)

static void replace_pages_with_nvdimm(pgd_t *t4, uint64_t start, uint64_t end)
{
	// Also replaces page table structures
	/*
  Intel / Linux
  PML4: pgd_t[512];
  PDPT: pud_t[512];
  PD  : pmd_t[512];
  PT  : pte_t[512];
  */
	uint64_t addr;
	pgd_t *e4;
	pud_t *t3 = NULL;
	pud_t *e3;
	pmd_t *t2 = NULL;
	pmd_t *e2;
	pte_t *t1 = NULL;
	pte_t *e1;
	uint64_t page_paddr;
	void *new_page_vaddr;
	uint64_t new_page_paddr;
	int i1 = -1, i2 = -1, i3 = -1, i4 = -1;
	for (addr = start; addr < end;) {
		if (i4 != PADDR_TO_IDX_IN_PML4(addr)) {
			i4 = PADDR_TO_IDX_IN_PML4(addr);
			printk("ndckpt: PML4[0x%03X]\n", i4);
			e4 = &t4[i4];
			if ((e4->pgd & _PAGE_PRESENT) == 0) {
				addr += PGDIR_SIZE;
				continue;
			}
			t3 = (void *)ndckpt_pgd_page_vaddr(*e4);
			if (!ndckpt_is_virt_addr_in_nvdimm(t3)) {
				new_page_vaddr = ndckpt_alloc_zeroed_page();
				new_page_paddr =
					ndckpt_virt_to_phys(new_page_vaddr);
				memcpy(new_page_vaddr, t3, PAGE_SIZE);
				e4->pgd = (e4->pgd & ~PTE_PFN_MASK) |
					  new_page_paddr;
				i4 = -1;
				printk("ndckpt: replaced\n");
				continue;
			}
		}
		if (i3 != PADDR_TO_IDX_IN_PDPT(addr)) {
			i3 = PADDR_TO_IDX_IN_PDPT(addr);
			printk("ndckpt:  PDPT[0x%03X]\n", i3);
			e3 = &t3[i3];
			if ((e3->pud & _PAGE_PRESENT) == 0) {
				addr += PUD_SIZE;
				continue;
			}
			t2 = (void *)ndckpt_pud_page_vaddr(*e3);
			if (!ndckpt_is_virt_addr_in_nvdimm(t2)) {
				new_page_vaddr = ndckpt_alloc_zeroed_page();
				new_page_paddr =
					ndckpt_virt_to_phys(new_page_vaddr);
				memcpy(new_page_vaddr, t2, PAGE_SIZE);
				e3->pud = (e3->pud & ~PTE_PFN_MASK) |
					  new_page_paddr;
				i3 = -1;
				printk("ndckpt: replaced\n");
				continue;
			}
		}
		if (i2 != PADDR_TO_IDX_IN_PD(addr)) {
			i2 = PADDR_TO_IDX_IN_PD(addr);
			printk("ndckpt:   PD  [0x%03X]\n", i2);
			e2 = &t2[i2];
			if ((e2->pmd & _PAGE_PRESENT) == 0) {
				addr += PMD_SIZE;
				continue;
			}
			t1 = (void *)ndckpt_pmd_page_vaddr(*e2);
			if (!ndckpt_is_virt_addr_in_nvdimm(t1)) {
				new_page_vaddr = ndckpt_alloc_zeroed_page();
				new_page_paddr =
					ndckpt_virt_to_phys(new_page_vaddr);
				memcpy(new_page_vaddr, t1, PAGE_SIZE);
				e2->pmd = (e2->pmd & ~PTE_PFN_MASK) |
					  new_page_paddr;
				i2 = -1;
				printk("ndckpt: replaced\n");
				continue;
			}
		}
		i1 = PADDR_TO_IDX_IN_PT(addr);
		printk("ndckpt:    PT  [0x%03X]\n", i1);
		e1 = &t1[i1];
		if ((e1->pte & _PAGE_PRESENT) == 0) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = e1->pte & PTE_PFN_MASK;
		printk("ndckpt:     PAGE @ 0x%016llX v->p 0x%016llX\n", addr,
		       page_paddr);
		if (!ndckpt_is_phys_addr_in_nvdimm(page_paddr)) {
			new_page_vaddr = ndckpt_alloc_zeroed_page();
			new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
			memcpy(new_page_vaddr, __va(page_paddr), PAGE_SIZE);
			e1->pte = (e1->pte & ~PTE_PFN_MASK) | new_page_paddr;
			ndckpt_invlpg((void *)addr);
			printk("ndckpt: replaced\n");
			continue;
		}
		addr += PAGE_SIZE;
	}
}

static void
replace_stack_pages_with_nvdimm(struct PersistentMemoryManager *pman,
				struct mm_struct *mm,
				struct vm_area_struct *vma)
{
	printk("ndckpt: Replacing stack vma [0x%016lX - 0x%016lX) with NVDIMM...\n",
	       vma->vm_start, vma->vm_end);
	replace_pages_with_nvdimm(mm->pgd, vma->vm_start, vma->vm_end);
}

static void switch_pgd_to_pmem(struct mm_struct *mm)
{
	pgd_t *pgd_on_pmem;
	uint64_t new_cr3;
	printk("ndckpt: pgd       = 0x%016llX\n", (uint64_t)mm->pgd);
	printk("ndckpt: pgd(phys) = 0x%016llX\n", virt_to_phys(mm->pgd));
	printk("ndckpt: cr3       = 0x%016lX\n", __read_cr3());
	BUG_ON((__read_cr3() & CR3_ADDR_MASK) != virt_to_phys(mm->pgd));
	pgd_on_pmem = pman_alloc_pages(first_pmem_device->virt_addr, 1);

	memcpy(pgd_on_pmem, mm->pgd, PAGE_SIZE);

	// https://elixir.bootlin.com/linux/v5.1.3/source/arch/x86/include/asm/tlbflush.h#L131
	new_cr3 = (CR3_ADDR_MASK & ndckpt_virt_to_phys(pgd_on_pmem)) |
		  (CR3_PCID_MASK & __read_cr3()) | CR3_NOFLUSH;
	printk("ndckpt: cr3(new)  = 0x%016llX\n", new_cr3);
	mm->pgd = pgd_on_pmem;
	write_cr3(new_cr3);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
}

void ndckpt_handle_execve(struct task_struct *task)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct PersistentProcessInfo *pproc;
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct pt_regs *regs = current_pt_regs();
	mm = task->mm;
	vma = mm->mmap;
	printk("ndckpt: ndckpt_handle_execve: pid = %d\n", task->pid);
	printk("ndckpt: start_code  = 0x%016lX\n", mm->start_code);
	printk("ndckpt: end_code    = 0x%016lX\n", mm->end_code);
	printk("ndckpt: start_data  = 0x%016lX\n", mm->start_data);
	printk("ndckpt: end_data    = 0x%016lX\n", mm->end_data);
	printk("ndckpt: start_brk  = 0x%016lX\n", mm->start_brk);
	printk("ndckpt: brk    = 0x%016lX\n", mm->brk);
	printk("ndckpt: start_stack = 0x%016lX\n", mm->start_stack);
	printk("ndckpt: stack_vm    = %ld\n", mm->stack_vm);

	BUG_ON(pgtable_l5_enabled());
	switch_pgd_to_pmem(mm);

	while (vma) {
		printk("ndckpt: vm_area_struct@0x%016llX\n", (uint64_t)vma);
		printk("ndckpt:   vm_start = 0x%016llX\n",
		       (uint64_t)vma->vm_start);
		printk("ndckpt:   vm_end   = 0x%016llX\n",
		       (uint64_t)vma->vm_end);
		printk("ndckpt:   vm_next   = 0x%016llX\n",
		       (uint64_t)vma->vm_next);
		printk("ndckpt:   vm_prev   = 0x%016llX\n",
		       (uint64_t)vma->vm_prev);
		printk("ndckpt:   vm_flags   = 0x%016llX\n",
		       (uint64_t)vma->vm_flags);
		vma->vm_ckpt_flags = 0;
		if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
			printk("ndckpt:   This is heap vma. Set VM_CKPT_TARGET.\n");
			vma->vm_ckpt_flags |= VM_CKPT_TARGET;
		}
		if (vma->vm_start <= mm->start_stack &&
		    mm->start_stack <= vma->vm_end) {
			printk("ndckpt:   This is stack vma. Set VM_CKPT_TARGET.\n");
			vma->vm_ckpt_flags |= VM_CKPT_TARGET;
			replace_stack_pages_with_nvdimm(pman, mm, vma);
		}
		vma = vma->vm_next;
	}
	// Set pproc
	pproc = pproc_alloc();
	pproc_set_pgd(pproc, 0, mm->pgd);
	pproc_set_regs(pproc, 0, regs);
	pproc_print_regs(pproc, 0);
	pproc_set_regs(pproc, 1, regs);
	pproc_print_regs(pproc, 1);
	pman_set_last_proc_info(pman, pproc);
	printk("pproc: pobj #%lld\n",
	       pobj_get_header(pman->last_proc_info)->id);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
}
EXPORT_SYMBOL(ndckpt_handle_execve);

int ndckpt_handle_checkpoint(void)
{
	// This function should be called under the pt_regs is fully saved on the stack.
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct PersistentProcessInfo *pproc = pman->last_proc_info;
	struct pt_regs *regs = current_pt_regs();
	if (!(current->flags & PF_NDCKPT_ENABLED))
		return -EINVAL;
	pproc_set_regs(pproc, 0, regs);
	/*
	printk("ndckpt_handle_checkpoint:\n");
	printk("  ip  = 0x%016lX\n", regs->ip);
	printk("  sp  = 0x%016lX\n", regs->sp);
	printk("  cr3 = 0x%016lX\n", __read_cr3());
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
	regs->ip -= 0x27;
  */
	return 0;
}
EXPORT_SYMBOL(ndckpt_handle_checkpoint);

static int __init ndckpt_module_init(void)
{
	BUILD_BUG_ON((sizeof(struct PersistentObjectHeader) > kCacheLineSize));
	BUILD_BUG_ON(
		(sizeof(struct PersistentMemoryManager) > 2 * kCacheLineSize));

	printk("ndckpt: module init\n");
	kobj_ndckpt = kobject_create_and_add("ndckpt", kernel_kobj);
	if (!kobj_ndckpt) {
		printk("ndckpt: kobject_create_and_add failed.\n");
		return -ENOMEM;
	}
	return sysfs_interface_init();
}
static void __exit ndckpt_module_cleanup(void)
{
	printk("ndckpt: module cleanup\n");
	kobject_put(kobj_ndckpt);
	return;
}

module_init(ndckpt_module_init);
module_exit(ndckpt_module_cleanup);
MODULE_LICENSE("GPL");
