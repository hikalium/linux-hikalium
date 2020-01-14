#include "ndckpt_internal.h"

struct kobject *kobj_ndckpt;
struct pmem_device *first_pmem_device;

void ndckpt_notify_pmem(struct pmem_device *pmem)
{
	if (!first_pmem_device) {
		pr_ndckpt("first pmem notified\n");
		first_pmem_device = pmem;
		pr_ndckpt("phys_addr: 0x%016llx\n", pmem->phys_addr);
		pr_ndckpt("size     : 0x%08lx\n", pmem->size);
		pr_ndckpt("virt_addr: 0x%016llx\n",
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
	task->ndckpt_id = restore_obj_id;
	pr_ndckpt("checkpoint enabled on pid=%d\n", task->pid);
	pr_ndckpt("  task flags = 0x%08X\n", task->flags);
	if (task->ndckpt_id)
		pr_ndckpt("  restore from obj id = 0x%016llX\n",
			  task->ndckpt_id);
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
	ndckpt_clwb_range(page, PAGE_SIZE);
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

static int handle_execve_resotre(struct task_struct *task,
				 uint64_t pproc_obj_id)
{
	// TODO: use pproc_obj_id to select pobj being restored
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct PersistentProcessInfo *pproc = pman->last_proc_info;
	return pproc_restore(pman, task, pproc);
}

int64_t ndckpt_handle_execve(struct task_struct *task)
{
	struct mm_struct *mm;
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct pt_regs *regs = current_pt_regs();
	mm = task->mm;
	pr_ndckpt("pid = %d\n", task->pid);
	if (task->ndckpt_id) {
		return handle_execve_resotre(task, task->ndckpt_id);
	}
	BUG_ON(pgtable_l5_enabled());
	return pproc_init(task, pman, mm, regs);
}
EXPORT_SYMBOL(ndckpt_handle_execve);

static int do_ndckpt(struct task_struct *target)
{
	// This can be called from any 'current' task.
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct PersistentProcessInfo *pproc = pman->last_proc_info;
	struct pt_regs *regs = task_pt_regs(target);
	if (!(target->flags & PF_NDCKPT_ENABLED))
		return -EINVAL;
	pproc_commit(target, pproc, target->mm, regs);
	return 0;
}

int ndckpt_handle_checkpoint(void)
{
	// This function should be called under the pt_regs is fully saved on the stack.
	return do_ndckpt(current);
}
EXPORT_SYMBOL(ndckpt_handle_checkpoint);

void ndckpt_exit_mm(struct task_struct *target)
{
	struct PersistentMemoryManager *pman;
	struct PersistentProcessInfo *pproc;
	if (!ndckpt_is_enabled_on_task(target))
		return;
	pman = first_pmem_device->virt_addr;
	pproc = pman->last_proc_info;

	target->mm->pgd =
		pproc_get_org_pgd(pproc); // To avoid pproc ctx destruction
}
EXPORT_SYMBOL(ndckpt_exit_mm);

int ndckpt___pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address,
		       struct vm_area_struct *vma)
{
	// Alloc PDPT (2nd page table structure)
	pud_t *new;
	uint64_t pud_phys;
	if (!is_vma_ndckpt_target(vma)) {
		// Alloc on DRAM
		return __pud_alloc(mm, p4d, address);
	}
	// Alloc on NVDIMM
	// https://elixir.bootlin.com/linux/v5.1.3/source/mm/memory.c#L4017
	new = ndckpt_alloc_zeroed_page();
	if (!new)
		return -EINVAL;
	smp_wmb(); /* See comment in __pte_alloc */
	spin_lock(&mm->page_table_lock);
	pud_phys = ndckpt_virt_to_phys(new);
	pr_ndckpt_pgalloc("vaddr: 0x%016llX\n", (uint64_t) new);
	paravirt_alloc_pud(mm, pud_phys >> PAGE_SHIFT);
	set_p4d(p4d, __p4d(_PAGE_TABLE | pud_phys));
	ndckpt_clwb(p4d);
	spin_unlock(&mm->page_table_lock);
	return 0;
}
EXPORT_SYMBOL(ndckpt___pud_alloc);

int ndckpt___pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address,
		       struct vm_area_struct *vma)
{
	// Alloc PD (3rd page table structure)
	pmd_t *new;
	uint64_t phys;
	if (!is_vma_ndckpt_target(vma)) {
		// Alloc on DRAM
		return __pmd_alloc(mm, pud, address);
	}
	// Alloc on NVDIMM
	// https://elixir.bootlin.com/linux/v5.1.3/source/mm/memory.c#L4017
	new = ndckpt_alloc_zeroed_page();
	if (!new)
		return -EINVAL;
	smp_wmb(); /* See comment in __pte_alloc */
	spin_lock(&mm->page_table_lock);
	phys = ndckpt_virt_to_phys(new);
	pr_ndckpt_pgalloc("vaddr: 0x%016llX\n", (uint64_t) new);
	paravirt_alloc_pud(mm, phys >> PAGE_SHIFT);
	set_pud(pud, __pud(_PAGE_TABLE | phys));
	ndckpt_clwb(pud);
	spin_unlock(&mm->page_table_lock);
	return 0;
}
EXPORT_SYMBOL(ndckpt___pmd_alloc);

void ndckpt__pte_alloc(struct vm_fault *vmf)
{
	// Alloc leaf pages
	pte_t pte;
	uint64_t paddr;
	paddr = ndckpt_alloc_phys_page();
	pr_ndckpt_pgalloc("paddr=0x%08llX\n", paddr);
	// https://elixir.bootlin.com/linux/v5.1.3/source/mm/memory.c#L2965
	pte = pfn_pte(PHYS_PFN(paddr), vmf->vma->vm_page_prot);
	/* No need to invalidate - it was non-present before */
	*vmf->pte = pte;
	ndckpt_clwb(vmf->pte);
}
EXPORT_SYMBOL(ndckpt__pte_alloc);

int ndckpt___pte_alloc(struct mm_struct *mm, pmd_t *pmd,
		       struct vm_area_struct *vma)
{
	// Alloc PT (4th page table structure)
	if (!is_vma_ndckpt_target(vma)) {
		// Alloc on DRAM
		return __pte_alloc(mm, pmd);
	}
	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */
	if (likely(pmd_none(*pmd))) { /* Has another populated it ? */
		ndckpt_pmd_populate(mm, pmd,
				    (pte_t *)ndckpt_alloc_zeroed_page());
		ndckpt_clwb(pmd);
	}
	return 0;
}
EXPORT_SYMBOL(ndckpt___pte_alloc);

int ndckpt_do_ndckpt(struct task_struct *target)
{
	BUG_ON(!task_is_traced(target));
	return do_ndckpt(target);
}
EXPORT_SYMBOL(ndckpt_do_ndckpt);

static int __init ndckpt_module_init(void)
{
	BUILD_BUG_ON((sizeof(struct PersistentObjectHeader) > kCacheLineSize));
	BUILD_BUG_ON(
		(sizeof(struct PersistentMemoryManager) > 2 * kCacheLineSize));

	pr_ndckpt("module init\n");
	kobj_ndckpt = kobject_create_and_add("ndckpt", kernel_kobj);
	if (!kobj_ndckpt) {
		pr_ndckpt("kobject_create_and_add failed.\n");
		return -ENOMEM;
	}
	return sysfs_interface_init();
}
static void __exit ndckpt_module_cleanup(void)
{
	pr_ndckpt("module cleanup\n");
	kobject_put(kobj_ndckpt);
	return;
}

module_init(ndckpt_module_init);
module_exit(ndckpt_module_cleanup);
MODULE_LICENSE("GPL");
