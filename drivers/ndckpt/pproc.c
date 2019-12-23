#include "ndckpt_internal.h"

#define PPROC_SIGNATURE 0x5050534f6d75696cULL
#define PCTX_REG_IDX_RAX 0
#define PCTX_REG_IDX_RCX 1
#define PCTX_REG_IDX_RDX 2
#define PCTX_REG_IDX_RBX 3
#define PCTX_REG_IDX_RSP 4
#define PCTX_REG_IDX_RBP 5
#define PCTX_REG_IDX_RSI 6
#define PCTX_REG_IDX_RDI 7
#define PCTX_REG_IDX_RIP 16
#define PCTX_REG_IDX_RFLAGS 17
// gregs[16] + RIP + RFLAGS
#define PCTX_REGS (16 + 1 + 1)

struct PersistentProcessInfo {
	struct PersistentExecutionContext {
		pgd_t *volatile pgd;
		uint64_t regs[PCTX_REGS];
	} ctx[2];
	int valid_ctx_idx;
	volatile uint64_t signature;
};

bool pproc_is_valid(struct PersistentProcessInfo *pproc)
{
	return pproc && pproc->signature == PPROC_SIGNATURE;
}

struct PersistentProcessInfo *pproc_alloc(void)
{
	struct PersistentProcessInfo *pproc = ndckpt_alloc_zeroed_page();
	pproc->ctx[0].pgd = NULL;
	pproc->ctx[1].pgd = NULL;
	pproc->valid_ctx_idx = -1;
	pproc->signature = PPROC_SIGNATURE;
	ndckpt_clwb(&pproc->signature);
	ndckpt_sfence();
	return pproc;
}

void pproc_set_pgd(struct PersistentProcessInfo *pproc, int ctx_idx, pgd_t *pgd)
{
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	BUG_ON(!ndckpt_is_virt_addr_in_nvdimm(pgd));
	pproc->ctx[ctx_idx].pgd = pgd;
	ndckpt_clwb(&pproc->ctx[ctx_idx].pgd);
	ndckpt_sfence();
}

void pproc_set_valid_ctx(struct PersistentProcessInfo *pproc, int ctx_idx)
{
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	pproc->valid_ctx_idx = ctx_idx;
	ndckpt_clwb(&pproc->valid_ctx_idx);
	ndckpt_sfence();
	pr_ndckpt("Ctx #%d is marked as valid\n", ctx_idx);
}

int pproc_get_running_ctx(struct PersistentProcessInfo *pproc)
{
	BUG_ON(pproc->valid_ctx_idx < 0 || 2 <= pproc->valid_ctx_idx);
	return (1 - pproc->valid_ctx_idx);
}

void pproc_set_regs(struct PersistentProcessInfo *proc, int ctx_idx,
		    struct pt_regs *regs)
{
	// It assumes pt_regs is fully saved.
	struct PersistentExecutionContext *ctx;
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	ctx = &proc->ctx[ctx_idx];
	ctx->regs[PCTX_REG_IDX_RAX] = regs->ax;
	ctx->regs[PCTX_REG_IDX_RCX] = regs->cx;
	ctx->regs[PCTX_REG_IDX_RDX] = regs->dx;
	ctx->regs[PCTX_REG_IDX_RBX] = regs->bx;
	ctx->regs[PCTX_REG_IDX_RSP] = regs->sp;
	ctx->regs[PCTX_REG_IDX_RBP] = regs->bp;
	ctx->regs[PCTX_REG_IDX_RSI] = regs->si;
	ctx->regs[PCTX_REG_IDX_RDI] = regs->di;
	ctx->regs[8] = regs->r8;
	ctx->regs[9] = regs->r9;
	ctx->regs[10] = regs->r10;
	ctx->regs[11] = regs->r11;
	ctx->regs[12] = regs->r12;
	ctx->regs[13] = regs->r13;
	ctx->regs[14] = regs->r14;
	ctx->regs[15] = regs->r15;
	ctx->regs[PCTX_REG_IDX_RIP] = regs->ip;
	ctx->regs[PCTX_REG_IDX_RFLAGS] = regs->flags;
	ndckpt_clwb_range(&ctx->regs[0], sizeof(ctx->regs));
	ndckpt_sfence();
}

void pproc_restore_regs(struct pt_regs *regs,
			struct PersistentProcessInfo *proc, int ctx_idx)
{
	// It assumes pt_regs is fully saved.
	struct PersistentExecutionContext *ctx;
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	ctx = &proc->ctx[ctx_idx];
	regs->ax = ctx->regs[PCTX_REG_IDX_RAX];
	regs->cx = ctx->regs[PCTX_REG_IDX_RCX];
	regs->dx = ctx->regs[PCTX_REG_IDX_RDX];
	regs->bx = ctx->regs[PCTX_REG_IDX_RBX];
	regs->sp = ctx->regs[PCTX_REG_IDX_RSP];
	regs->bp = ctx->regs[PCTX_REG_IDX_RBP];
	regs->si = ctx->regs[PCTX_REG_IDX_RSI];
	regs->di = ctx->regs[PCTX_REG_IDX_RDI];
	regs->r8 = ctx->regs[8];
	regs->r9 = ctx->regs[9];
	regs->r10 = ctx->regs[10];
	regs->r11 = ctx->regs[11];
	regs->r12 = ctx->regs[12];
	regs->r13 = ctx->regs[13];
	regs->r14 = ctx->regs[14];
	regs->r15 = ctx->regs[15];
	regs->ip = ctx->regs[PCTX_REG_IDX_RIP];
	regs->flags = ctx->regs[PCTX_REG_IDX_RFLAGS];
}

static const char *pctx_reg_names[PCTX_REGS] = {
	"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8",
	"R9",  "R10", "R11", "R12", "R13", "R14", "R15", "RIP", "RFLAGS",
};

void pproc_print_regs(struct PersistentProcessInfo *proc, int ctx_idx)
{
	struct PersistentExecutionContext *ctx;
	int i;
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	ctx = &proc->ctx[ctx_idx];
	printk("regs in ctx[%d]\n", ctx_idx);
	for (i = 0; i < PCTX_REGS; i++) {
		printk("  %6s: 0x%016llX\n", pctx_reg_names[i], ctx->regs[i]);
	}
}

void pproc_printk(struct PersistentProcessInfo *pproc)
{
	int i;
	if (!pproc_is_valid(pproc)) {
		printk("invalid last_proc_info\n");
		return;
	}
	printk("PersistentProcessInfo at pobj #%lld:\n",
	       pobj_get_header(pproc)->id);
	printk("  Ctx #%d is valid\n", pproc->valid_ctx_idx);
	for (i = 0; i < 2; i++) {
		pr_ndckpt("Ctx #%d:\n", i);
		ndckpt_print_pml4(pproc->ctx[i].pgd);
		pproc_print_regs(pproc, i);
	}
}

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

static void sync_pages(pgd_t *src_t4, pgd_t *dst_t4, uint64_t start,
		       uint64_t end, struct vm_area_struct *vma)
{
	uint64_t addr;
	//
	pgd_t *src_e4;
	pud_t *src_t3 = NULL;
	pud_t *src_e3;
	pmd_t *src_t2 = NULL;
	pmd_t *src_e2;
	pte_t *src_t1 = NULL;
	pte_t *src_e1;
	void *src_page_vaddr;
	//
	pgd_t *dst_e4;
	pud_t *dst_t3 = NULL;
	pud_t *dst_e3;
	pmd_t *dst_t2 = NULL;
	pmd_t *dst_e2;
	pte_t *dst_t1 = NULL;
	pte_t *dst_e1;
	void *dst_page_vaddr;
	//
	void *tmp_page_addr;
	pr_ndckpt("sync_pages: [0x%016llX, 0x%016llX)\n", start, end);
	for (addr = start; addr < end;) {
		traverse_pml4e(addr, src_t4, &src_e4, &src_t3);
		traverse_pml4e(addr, dst_t4, &dst_e4, &dst_t3);
		if (!src_t3) {
			addr += PGDIR_SIZE;
			continue;
		}
		if (!dst_t3 || !ndckpt_is_virt_addr_in_nvdimm(dst_t3)) {
			pr_ndckpt("Alloc PDPT for 0x%016llX on NVDIMM.\n",
				  addr);
			tmp_page_addr = ndckpt_alloc_zeroed_page();
			if (dst_t3) {
				memcpy(tmp_page_addr, dst_t3, PAGE_SIZE);
			}
			*(p4d_t *)dst_e4 =
				__p4d(_PAGE_TABLE |
				      ndckpt_virt_to_phys(tmp_page_addr));
			continue; // Retry
		}
		traverse_pdpte(addr, src_t3, &src_e3, &src_t2);
		traverse_pdpte(addr, dst_t3, &dst_e3, &dst_t2);
		if (!src_t2) {
			addr += PUD_SIZE;
			continue;
		}
		if (!dst_t2 || !ndckpt_is_virt_addr_in_nvdimm(dst_t2)) {
			pr_ndckpt("Alloc PD for 0x%016llX on NVDIMM.\n", addr);
			tmp_page_addr = ndckpt_alloc_zeroed_page();
			if (dst_t2) {
				memcpy(tmp_page_addr, dst_t2, PAGE_SIZE);
			}
			*dst_e3 = __pud(_PAGE_TABLE |
					ndckpt_virt_to_phys(tmp_page_addr));
			continue; // Retry
		}
		traverse_pde(addr, src_t2, &src_e2, &src_t1);
		traverse_pde(addr, dst_t2, &dst_e2, &dst_t1);
		if (!src_t1) {
			addr += PMD_SIZE;
			continue;
		}
		if (!dst_t1 || !ndckpt_is_virt_addr_in_nvdimm(dst_t1)) {
			pr_ndckpt("Alloc PT for 0x%016llX on NVDIMM.\n", addr);
			tmp_page_addr = ndckpt_alloc_zeroed_page();
			if (dst_t1) {
				memcpy(tmp_page_addr, dst_t1, PAGE_SIZE);
			}
			*dst_e2 = __pmd(_PAGE_TABLE |
					ndckpt_virt_to_phys(tmp_page_addr));
			continue; // Retry
		}
		traverse_pte(addr, src_t1, &src_e1, &src_page_vaddr);
		traverse_pte(addr, dst_t1, &dst_e1, &dst_page_vaddr);
		if (!src_page_vaddr) {
			addr += PAGE_SIZE;
			continue;
		}
		if (!dst_page_vaddr ||
		    !ndckpt_is_virt_addr_in_nvdimm(dst_page_vaddr)) {
			pr_ndckpt("Alloc PAGE for 0x%016llX on NVDIMM.\n",
				  addr);
			tmp_page_addr = ndckpt_alloc_zeroed_page();
			if (dst_page_vaddr) {
				memcpy(tmp_page_addr, dst_page_vaddr,
				       PAGE_SIZE);
			}
			*dst_e1 = pfn_pte(
				PHYS_PFN(ndckpt_virt_to_phys(tmp_page_addr)),
				vma->vm_page_prot);
			update_mmu_cache(vma, addr, dst_e1);
			continue; // Retry
		}
		// TODO: Reduce copy with dirty flag
		memcpy(dst_page_vaddr, src_page_vaddr, PAGE_SIZE);
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
	void *page_vaddr;
	uint64_t page_paddr;
	pr_ndckpt("flush_dirty_pages: [0x%016llX, 0x%016llX)\n", start, end);
	for (addr = start; addr < end;) {
		traverse_pml4e(addr, t4, &e4, &t3);
		if (!t3) {
			addr += PGDIR_SIZE;
			continue;
		}
		traverse_pdpte(addr, t3, &e3, &t2);
		if (!t2) {
			addr += PUD_SIZE;
			continue;
		}
		traverse_pde(addr, t2, &e2, &t1);
		if (!t1) {
			addr += PMD_SIZE;
			continue;
		}
		traverse_pte(addr, t1, &e1, &page_vaddr);
		if (!page_vaddr) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = ndckpt_v2p(page_vaddr);
		page_vaddr = ndckpt_p2v(page_paddr);
		pr_ndckpt("    PAGE @ 0x%016llX v->p 0x%016llX\n", addr,
			  page_paddr);
		if (e1->pte & _PAGE_DIRTY) {
			ndckpt_clwb_range(page_vaddr, PAGE_SIZE);
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

static void sync_target_vmas(struct mm_struct *mm, pgd_t *dst_pgd)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) == 0) {
			continue;
		}
		sync_pages(mm->pgd, dst_pgd, vma->vm_start, vma->vm_end, vma);
	}
}

void pproc_commit(struct PersistentProcessInfo *pproc, struct mm_struct *mm,
		  struct pt_regs *regs)
{
	const int prev_running_ctx_idx = pproc_get_running_ctx(pproc);
	const int next_running_ctx_idx = 1 - prev_running_ctx_idx;
	pproc_set_regs(pproc, prev_running_ctx_idx, regs);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
	flush_target_vmas(mm);
	ndckpt_print_pml4(ndckpt_phys_to_virt(__read_cr3() & CR3_ADDR_MASK));
	pr_ndckpt("Ctx #%d has been committed\n", prev_running_ctx_idx);
	// At this point, running ctx has become clean so both context is valid.
	pproc_set_valid_ctx(pproc, prev_running_ctx_idx);
	// prepare next running context
	pr_ndckpt("Sync Ctx #%d -> Ctx #%d\n", prev_running_ctx_idx,
		  next_running_ctx_idx);
	sync_target_vmas(mm, pproc->ctx[next_running_ctx_idx].pgd);
	// Finally, switch the cr3 to the new running context's pgd.
	switch_mm_context(mm, pproc->ctx[next_running_ctx_idx].pgd);
}

void pproc_restore(struct task_struct *task,
		   struct PersistentProcessInfo *pproc)
{
	struct pt_regs *regs = task_pt_regs(task);
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma = mm->mmap;
	const int valid_ctx_idx = pproc->valid_ctx_idx;
	pr_ndckpt("restore from obj id = %016llX\n", task->ndckpt_id);
	pproc_printk(pproc);
	BUG_ON(valid_ctx_idx < 0 || 2 <= valid_ctx_idx);
	pr_ndckpt("  valid_ctx_idx: %d\n", valid_ctx_idx);
	pproc_print_regs(pproc, valid_ctx_idx);
	pproc_restore_regs(regs, pproc, valid_ctx_idx);
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
			erase_mappings_to_dram(pproc->ctx[0].pgd, vma->vm_start,
					       vma->vm_end);
			erase_mappings_to_dram(pproc->ctx[1].pgd, vma->vm_start,
					       vma->vm_end);
		}
		vma = vma->vm_next;
	}
	switch_mm_context(task->mm, pproc->ctx[valid_ctx_idx].pgd);
	sync_target_vmas(mm, pproc->ctx[1 - valid_ctx_idx].pgd);
	pproc_set_regs(pproc, 1 - valid_ctx_idx, regs);
	pproc_set_valid_ctx(pproc, 1 - valid_ctx_idx);
}
