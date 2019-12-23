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

static void replace_pages_with_nvdimm(pgd_t *t4, uint64_t start, uint64_t end)
{
	// Also replaces page table structures
	uint64_t addr;
	pgd_t *e4;
	pud_t *t3 = NULL;
	pud_t *e3;
	pmd_t *t2 = NULL;
	pmd_t *e2;
	pte_t *t1 = NULL;
	pte_t *e1;
	uint64_t page_paddr;
	int i1 = -1, i2 = -1, i3 = -1, i4 = -1;
	for (addr = start; addr < end;) {
		if (i4 != PADDR_TO_IDX_IN_PML4(addr)) {
			i4 = PADDR_TO_IDX_IN_PML4(addr);
			pr_ndckpt("PML4[0x%03X]\n", i4);
			e4 = &t4[i4];
			if ((e4->pgd & _PAGE_PRESENT) == 0) {
				addr += PGDIR_SIZE;
				continue;
			}
			t3 = (void *)ndckpt_pgd_page_vaddr(*e4);
			if (!ndckpt_is_virt_addr_in_nvdimm(t3)) {
				replace_pdpt_with_nvdimm_page(e4);
				ndckpt_invlpg((void *)addr);
				i4 = -1;
				continue;
			}
		}
		if (i3 != PADDR_TO_IDX_IN_PDPT(addr)) {
			i3 = PADDR_TO_IDX_IN_PDPT(addr);
			pr_ndckpt(" PDPT[0x%03X]\n", i3);
			e3 = &t3[i3];
			if ((e3->pud & _PAGE_PRESENT) == 0) {
				addr += PUD_SIZE;
				continue;
			}
			t2 = (void *)ndckpt_pud_page_vaddr(*e3);
			if (!ndckpt_is_virt_addr_in_nvdimm(t2)) {
				replace_pd_with_nvdimm_page(e3);
				ndckpt_invlpg((void *)addr);
				i3 = -1;
				continue;
			}
		}
		if (i2 != PADDR_TO_IDX_IN_PD(addr)) {
			i2 = PADDR_TO_IDX_IN_PD(addr);
			pr_ndckpt("  PD  [0x%03X]\n", i2);
			e2 = &t2[i2];
			if ((e2->pmd & _PAGE_PRESENT) == 0) {
				addr += PMD_SIZE;
				continue;
			}
			t1 = (void *)ndckpt_pmd_page_vaddr(*e2);
			if (!ndckpt_is_virt_addr_in_nvdimm(t1)) {
				replace_pt_with_nvdimm_page(e2);
				ndckpt_invlpg((void *)addr);
				i2 = -1;
				continue;
			}
		}
		i1 = PADDR_TO_IDX_IN_PT(addr);
		pr_ndckpt("   PT  [0x%03X]\n", i1);
		e1 = &t1[i1];
		if ((e1->pte & _PAGE_PRESENT) == 0) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = e1->pte & PTE_PFN_MASK;
		pr_ndckpt("    PAGE @ 0x%016llX v->p 0x%016llX\n", addr,
			  page_paddr);
		if (!ndckpt_is_phys_addr_in_nvdimm(page_paddr)) {
			replace_page_with_nvdimm_page(e1);
			ndckpt_invlpg((void *)addr);
			continue;
		}
		addr += PAGE_SIZE;
	}
}

static void
replace_stack_pages_with_nvdimm(struct PersistentMemoryManager *pman,
				pgd_t *pgd, struct vm_area_struct *vma)
{
	pr_ndckpt("Replacing stack vma [0x%016lX - 0x%016lX) with NVDIMM...\n",
		  vma->vm_start, vma->vm_end);
	replace_pages_with_nvdimm(pgd, vma->vm_start, vma->vm_end);
}

static void handle_execve_resotre(struct task_struct *task,
				  uint64_t pproc_obj_id)
{
	// TODO: use pproc_obj_id to select pobj being restored
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct PersistentProcessInfo *pproc = pman->last_proc_info;
	pproc_restore(task, pproc);
}

static void init_pproc(struct PersistentMemoryManager *pman,
		       struct mm_struct *mm, struct pt_regs *regs)
{
	struct vm_area_struct *vma = mm->mmap;
	pgd_t *pgd_ctx0;
	pgd_t *pgd_ctx1;
	struct PersistentProcessInfo *pproc = pproc_alloc();
	pr_ndckpt("pproc pobj #%lld\n",
		  pobj_get_header(pman->last_proc_info)->id);
	// ctx 0
	pgd_ctx0 = ndckpt_alloc_zeroed_page();
	memcpy(pgd_ctx0, mm->pgd, PAGE_SIZE);
	pproc_set_pgd(pproc, 0, pgd_ctx0);
	pproc_set_regs(pproc, 0, regs);
	pproc_print_regs(pproc, 0);
	// ctx 1
	pgd_ctx1 = ndckpt_alloc_zeroed_page();
	memcpy(pgd_ctx1, mm->pgd, PAGE_SIZE);
	pproc_set_pgd(pproc, 1, pgd_ctx1);
	pproc_set_regs(pproc, 1, regs);
	pproc_print_regs(pproc, 1);
	// Set vma flags and replace stack pages with NVDIMM
	while (vma) {
		pr_ndckpt("vm_area_struct@0x%016llX\n", (uint64_t)vma);
		pr_ndckpt("  vm_start = 0x%016llX\n", (uint64_t)vma->vm_start);
		pr_ndckpt("  vm_end   = 0x%016llX\n", (uint64_t)vma->vm_end);
		pr_ndckpt("  vm_next   = 0x%016llX\n", (uint64_t)vma->vm_next);
		pr_ndckpt("  vm_prev   = 0x%016llX\n", (uint64_t)vma->vm_prev);
		pr_ndckpt("  vm_flags   = 0x%016llX\n",
			  (uint64_t)vma->vm_flags);
		vma->vm_ckpt_flags = 0;
		if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
			pr_ndckpt("  This is heap vma. Set VM_CKPT_TARGET.\n");
			vma->vm_ckpt_flags |= VM_CKPT_TARGET;
		}
		if (vma->vm_start <= mm->start_stack &&
		    mm->start_stack <= vma->vm_end) {
			pr_ndckpt("  This is stack vma. Set VM_CKPT_TARGET.\n");
			vma->vm_ckpt_flags |= VM_CKPT_TARGET;
			replace_stack_pages_with_nvdimm(pman, pgd_ctx0, vma);
			replace_stack_pages_with_nvdimm(pman, pgd_ctx1, vma);
		}
		vma = vma->vm_next;
	}
	// Set ctx 0: running, ctx 1: valid
	switch_mm_context(mm, pgd_ctx0);
	pproc_set_valid_ctx(pproc, 1);
	// At this point, this process can be recovered from pproc
	pman_set_last_proc_info(pman, pproc);
}

void ndckpt_handle_execve(struct task_struct *task)
{
	struct mm_struct *mm;
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct pt_regs *regs = current_pt_regs();
	mm = task->mm;
	pr_ndckpt("pid = %d\n", task->pid);
	if (task->ndckpt_id) {
		handle_execve_resotre(task, task->ndckpt_id);
		return;
	}
	pr_ndckpt(" start_code  = 0x%016lX\n", mm->start_code);
	pr_ndckpt(" end_code    = 0x%016lX\n", mm->end_code);
	pr_ndckpt(" start_data  = 0x%016lX\n", mm->start_data);
	pr_ndckpt(" end_data    = 0x%016lX\n", mm->end_data);
	pr_ndckpt(" start_brk  = 0x%016lX\n", mm->start_brk);
	pr_ndckpt(" brk    = 0x%016lX\n", mm->brk);
	pr_ndckpt(" start_stack = 0x%016lX\n", mm->start_stack);
	pr_ndckpt(" stack_vm    = %ld\n", mm->stack_vm);

	BUG_ON(pgtable_l5_enabled());

	init_pproc(pman, mm, regs);
}
EXPORT_SYMBOL(ndckpt_handle_execve);

int ndckpt_handle_checkpoint(void)
{
	// This function should be called under the pt_regs is fully saved on the stack.
	struct task_struct *task = current;
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct PersistentProcessInfo *pproc = pman->last_proc_info;
	struct pt_regs *regs = task_pt_regs(task);
	if (!(current->flags & PF_NDCKPT_ENABLED))
		return -EINVAL;
	pproc_commit(pproc, task->mm, regs);
	return 0;
}
EXPORT_SYMBOL(ndckpt_handle_checkpoint);

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
	mm_inc_nr_puds(mm);
	pud_phys = ndckpt_virt_to_phys(new);
	pr_ndckpt_pgalloc("vaddr: 0x%016llX\n", (uint64_t) new);
	paravirt_alloc_pud(mm, pud_phys >> PAGE_SHIFT);
	set_p4d(p4d, __p4d(_PAGE_TABLE | pud_phys));
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
	mm_inc_nr_puds(mm);
	phys = ndckpt_virt_to_phys(new);
	pr_ndckpt_pgalloc("vaddr: 0x%016llX\n", (uint64_t) new);
	paravirt_alloc_pud(mm, phys >> PAGE_SHIFT);
	set_pud(pud, __pud(_PAGE_TABLE | phys));
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
	update_mmu_cache(vmf->vma, vmf->address, vmf->pte);
}
EXPORT_SYMBOL(ndckpt__pte_alloc);

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
