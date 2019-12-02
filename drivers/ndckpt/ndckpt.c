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

static void ndckpt_print_pt(pte_t *pte)
{
	int i;
	uint64_t e;
	printk("ndckpt:       PT   @ 0x%016llX %s\n", (uint64_t)pte,
	       ndckpt_is_virt_addr_in_nvdimm(pte) ? "(on NVDIMM)" : "");
	for (i = 0; i < PAGE_SIZE / sizeof(pte_t); i++) {
		e = pte[i].pte;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt:       PAGE[0x%03X] = 0x%016llX %s\n", i, e,
		       ndckpt_is_phys_addr_in_nvdimm(e & PTE_PFN_MASK) ?
			       "(on NVDIMM)" :
			       "");
	}
}

static void ndckpt_print_pd(pmd_t *pmd)
{
	int i;
	uint64_t e;
	printk("ndckpt:     PD   @ 0x%016llX %s\n", (uint64_t)pmd,
	       ndckpt_is_virt_addr_in_nvdimm(pmd) ? "(on NVDIMM)" : "");
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
	printk("ndckpt:   PDPT @ 0x%016llX %s\n", (uint64_t)pud,
	       ndckpt_is_virt_addr_in_nvdimm(pud) ? "(on NVDIMM)" : "");
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

static void ndckpt_print_pml4(pgd_t *pgd)
{
	int i;
	uint64_t e;
	printk("ndckpt: PML4 @ 0x%016llX %s\n", (uint64_t)pgd,
	       ndckpt_is_virt_addr_in_nvdimm(pgd) ? "(on NVDIMM)" : "");
	for (i = 0; i < PAGE_SIZE / sizeof(pgd_t); i++) {
		e = (uint64_t)pgd[i].pgd;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt: PML4[0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pdpt((pud_t *)ndckpt_pgd_page_vaddr(pgd[i]));
	}
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
		vma = vma->vm_next;
	}
	pproc = pproc_alloc();
	pproc_set_pgd(pproc, 0, mm->pgd);
	pman_set_last_proc_info(pman, pproc);
	printk("pproc: pobj #%lld\n",
	       pobj_get_header(pman->last_proc_info)->id);
}
EXPORT_SYMBOL(ndckpt_handle_execve);

int ndckpt_handle_checkpoint(void)
{
	// This function should be called under the pt_regs is fully saved on the stack.
	//struct pt_regs *regs = current_pt_regs();
	if (!(current->flags & PF_NDCKPT_ENABLED))
		return -EINVAL;
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
	BUILD_BUG_ON((sizeof(struct PersistentProcessInfo) > kCacheLineSize));
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
