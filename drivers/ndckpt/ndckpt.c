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
			pr_ndckpt("PML4[0x%03X]\n", i4);
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
				pr_ndckpt("replaced\n");
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
				new_page_vaddr = ndckpt_alloc_zeroed_page();
				new_page_paddr =
					ndckpt_virt_to_phys(new_page_vaddr);
				memcpy(new_page_vaddr, t2, PAGE_SIZE);
				e3->pud = (e3->pud & ~PTE_PFN_MASK) |
					  new_page_paddr;
				i3 = -1;
				pr_ndckpt("replaced\n");
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
				new_page_vaddr = ndckpt_alloc_zeroed_page();
				new_page_paddr =
					ndckpt_virt_to_phys(new_page_vaddr);
				memcpy(new_page_vaddr, t1, PAGE_SIZE);
				e2->pmd = (e2->pmd & ~PTE_PFN_MASK) |
					  new_page_paddr;
				i2 = -1;
				pr_ndckpt("replaced\n");
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
			new_page_vaddr = ndckpt_alloc_zeroed_page();
			new_page_paddr = ndckpt_virt_to_phys(new_page_vaddr);
			memcpy(new_page_vaddr, __va(page_paddr), PAGE_SIZE);
			e1->pte = (e1->pte & ~PTE_PFN_MASK) | new_page_paddr;
			ndckpt_invlpg((void *)addr);
			pr_ndckpt("replaced\n");
			continue;
		}
		addr += PAGE_SIZE;
	}
}

static void pr_ndckpt_pt_range(pgd_t *t4, uint64_t start, uint64_t end)
{
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
		}
		i1 = PADDR_TO_IDX_IN_PT(addr);
		pr_ndckpt("   PT  [0x%03X]\n", i1);
		e1 = &t1[i1];
		if ((e1->pte & _PAGE_PRESENT) == 0) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = e1->pte & PTE_PFN_MASK;
		pr_ndckpt("    PAGE @ 0x%016llX v->p 0x%016llX on %s\n", addr,
			  page_paddr, get_str_dram_or_nvdimm_phys(page_paddr));
		addr += PAGE_SIZE;
	}
}

static void flush_dirty_pages(pgd_t *t4, uint64_t start, uint64_t end)
{
	uint64_t addr;
	pgd_t *e4;
	pud_t *t3 = NULL;
	pud_t *e3;
	pmd_t *t2 = NULL;
	pmd_t *e2;
	pte_t *t1 = NULL;
	pte_t *e1;
	uint64_t page_paddr;
	void *page_kernel_vaddr;
	int i1 = -1, i2 = -1, i3 = -1, i4 = -1;
	pr_ndckpt("flush_dirty_pages: [0x%016llX, 0x%016llX)\n", start, end);
	for (addr = start; addr < end;) {
		if (i4 != PADDR_TO_IDX_IN_PML4(addr)) {
			i4 = PADDR_TO_IDX_IN_PML4(addr);
			e4 = &t4[i4];
			if ((e4->pgd & _PAGE_PRESENT) == 0) {
				addr += PGDIR_SIZE;
				continue;
			}
			t3 = (void *)ndckpt_pgd_page_vaddr(*e4);
		}
		if (i3 != PADDR_TO_IDX_IN_PDPT(addr)) {
			i3 = PADDR_TO_IDX_IN_PDPT(addr);
			e3 = &t3[i3];
			if ((e3->pud & _PAGE_PRESENT) == 0) {
				addr += PUD_SIZE;
				continue;
			}
			t2 = (void *)ndckpt_pud_page_vaddr(*e3);
		}
		if (i2 != PADDR_TO_IDX_IN_PD(addr)) {
			i2 = PADDR_TO_IDX_IN_PD(addr);
			e2 = &t2[i2];
			if ((e2->pmd & _PAGE_PRESENT) == 0) {
				addr += PMD_SIZE;
				continue;
			}
			t1 = (void *)ndckpt_pmd_page_vaddr(*e2);
		}
		i1 = PADDR_TO_IDX_IN_PT(addr);
		e1 = &t1[i1];
		if ((e1->pte & _PAGE_PRESENT) == 0) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = e1->pte & PTE_PFN_MASK;
		page_kernel_vaddr = ndckpt_phys_to_virt(page_paddr);
		pr_ndckpt("    PAGE @ 0x%016llX v->p 0x%016llX\n", addr,
			  page_paddr);
		if (e1->pte & _PAGE_DIRTY) {
			ndckpt_clwb_range(page_kernel_vaddr, PAGE_SIZE);
			e1->pte &= ~(uint64_t)_PAGE_DIRTY;
			pr_ndckpt(
				"flushed dirty page @ 0x%016llX v->p 0x%016llX\n",
				addr, page_paddr);
		}
		addr += PAGE_SIZE;
	}
	ndckpt_sfence();
	pr_ndckpt("SFENCE() done\n");
}

static void flush_target_vmas(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) == 0) {
			continue;
		}
		flush_dirty_pages(mm->pgd, vma->vm_start, vma->vm_end);
	}
}

static void
replace_stack_pages_with_nvdimm(struct PersistentMemoryManager *pman,
				struct mm_struct *mm,
				struct vm_area_struct *vma)
{
	pr_ndckpt("Replacing stack vma [0x%016lX - 0x%016lX) with NVDIMM...\n",
		  vma->vm_start, vma->vm_end);
	replace_pages_with_nvdimm(mm->pgd, vma->vm_start, vma->vm_end);
}

static void switch_pgd_to_pmem(struct mm_struct *mm)
{
	pgd_t *pgd_on_pmem;
	uint64_t new_cr3;
	pr_ndckpt("pgd       = 0x%016llX\n", (uint64_t)mm->pgd);
	pr_ndckpt("pgd(phys) = 0x%016llX\n", virt_to_phys(mm->pgd));
	pr_ndckpt("cr3       = 0x%016lX\n", __read_cr3());
	BUG_ON((__read_cr3() & CR3_ADDR_MASK) != virt_to_phys(mm->pgd));
	pgd_on_pmem = pman_alloc_pages(first_pmem_device->virt_addr, 1);

	memcpy(pgd_on_pmem, mm->pgd, PAGE_SIZE);

	// https://elixir.bootlin.com/linux/v5.1.3/source/arch/x86/include/asm/tlbflush.h#L131
	new_cr3 = (CR3_ADDR_MASK & ndckpt_virt_to_phys(pgd_on_pmem)) |
		  (CR3_PCID_MASK & __read_cr3()) | CR3_NOFLUSH;
	pr_ndckpt("cr3(new)  = 0x%016llX\n", new_cr3);
	mm->pgd = pgd_on_pmem;
	write_cr3(new_cr3);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
}

static void merge_pgd_with_pmem(struct mm_struct *mm, pgd_t *pgd_on_pmem)
{
	uint64_t new_cr3;
	pr_ndckpt("merge_pgd_with_pmem\n");
	new_cr3 = (CR3_ADDR_MASK & ndckpt_virt_to_phys(pgd_on_pmem)) |
		  (CR3_PCID_MASK & __read_cr3()) | CR3_NOFLUSH;
	pr_ndckpt("cr3(new)  = 0x%016llX\n", new_cr3);
	mm->pgd = pgd_on_pmem;
	write_cr3(new_cr3);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
}

static void erase_mappings_to_dram(pgd_t *t4, uint64_t start, uint64_t end)
{
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
	pr_ndckpt("erase_mappings_to_dram: [0x%016llX, 0x%016llX)\n", start,
		  end);
	for (addr = start; addr < end;) {
		if (i4 != PADDR_TO_IDX_IN_PML4(addr)) {
			i4 = PADDR_TO_IDX_IN_PML4(addr);
			e4 = &t4[i4];
			if ((e4->pgd & _PAGE_PRESENT) == 0) {
				addr += PGDIR_SIZE;
				continue;
			}
			t3 = (void *)ndckpt_pgd_page_vaddr(*e4);
		}
		if (i3 != PADDR_TO_IDX_IN_PDPT(addr)) {
			i3 = PADDR_TO_IDX_IN_PDPT(addr);
			e3 = &t3[i3];
			if ((e3->pud & _PAGE_PRESENT) == 0) {
				addr += PUD_SIZE;
				continue;
			}
			t2 = (void *)ndckpt_pud_page_vaddr(*e3);
		}
		if (i2 != PADDR_TO_IDX_IN_PD(addr)) {
			i2 = PADDR_TO_IDX_IN_PD(addr);
			e2 = &t2[i2];
			if ((e2->pmd & _PAGE_PRESENT) == 0) {
				addr += PMD_SIZE;
				continue;
			}
			t1 = (void *)ndckpt_pmd_page_vaddr(*e2);
			if (!ndckpt_is_virt_addr_in_nvdimm(t1)) {
				e2->pmd = 0;
				ndckpt_invlpg((void *)addr);
				addr += PMD_SIZE;
				continue;
			}
		}
		i1 = PADDR_TO_IDX_IN_PT(addr);
		e1 = &t1[i1];
		if ((e1->pte & _PAGE_PRESENT) == 0) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = e1->pte & PTE_PFN_MASK;
		if (!ndckpt_is_phys_addr_in_nvdimm(page_paddr)) {
			pr_ndckpt(
				"clear mapping to DRAM page @ 0x%016llX v->p 0x%016llX\n",
				addr, page_paddr);
			e1->pte = 0;
			ndckpt_invlpg((void *)addr);
		}
		addr += PAGE_SIZE;
	}
	ndckpt_sfence();
	pr_ndckpt("SFENCE() done\n");
}

static void handle_execve_resotre(struct task_struct *task,
				  uint64_t pproc_obj_id)
{
	// TODO: use pproc_obj_id to select pobj being restored
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	struct PersistentProcessInfo *pproc = pman->last_proc_info;
	struct pt_regs *regs = task_pt_regs(task);
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	mm = task->mm;
	vma = mm->mmap;
	pr_ndckpt("restore from obj id = %016llX\n", task->ndckpt_id);
	pproc_printk(pproc);
	merge_pgd_with_pmem(task->mm, pproc->ctx[0].pgd);
	pproc_print_regs(pproc, 0);
	pproc_restore_regs(regs, pproc, 0);
	while (vma) {
		pr_ndckpt("vm_area_struct@0x%016llX\n", (uint64_t)vma);
		pr_ndckpt("  vm_start = 0x%016llX\n", (uint64_t)vma->vm_start);
		pr_ndckpt("  vm_end   = 0x%016llX\n", (uint64_t)vma->vm_end);
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
		}
		if (vma->vm_start <= mm->start_code &&
		    mm->start_code <= vma->vm_end) {
			pr_ndckpt("  This is code vma. clear old mappings.\n");
			pr_ndckpt_pt_range(mm->pgd, vma->vm_start, vma->vm_end);
			erase_mappings_to_dram(mm->pgd, vma->vm_start,
					       vma->vm_end);
		}
		vma = vma->vm_next;
	}
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
	switch_pgd_to_pmem(mm);

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
	pr_ndckpt("pproc pobj #%lld\n",
		  pobj_get_header(pman->last_proc_info)->id);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
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
	pproc_set_regs(pproc, 0, regs);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
	flush_target_vmas(task->mm);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
	for (;;) {
	}
	regs->ip -= 0x27;
	return 0;
}
EXPORT_SYMBOL(ndckpt_handle_checkpoint);

int ndckpt___pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
{
	// Alloc PDPT (2nd page table structure)
	pud_t *new;
	uint64_t pud_phys;
	if (!ndckpt_is_enabled_on_current()) {
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

int ndckpt___pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	// Alloc PD (3rd page table structure)
	pmd_t *new;
	uint64_t phys;
	if (!ndckpt_is_enabled_on_current()) {
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
