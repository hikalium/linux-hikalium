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

struct PersistentVMARange {
	// Corresponds to vma->vm_start/end
	uint64_t start, end;
};

struct PersistentProcessInfo {
	struct PersistentExecutionContext {
		pgd_t *volatile pgd;
		uint64_t regs[PCTX_REGS];
		struct PersistentVMARange heap;
		struct PersistentVMARange stack;
	} ctx[2];
	pgd_t *volatile org_pgd; // on DRAM
	int valid_ctx_idx;
	spinlock_t ckpt_lock;
	volatile uint64_t signature;
};

bool pproc_is_valid(struct PersistentProcessInfo *pproc)
{
	return pproc && pproc->signature == PPROC_SIGNATURE;
}

pgd_t *pproc_get_org_pgd(struct PersistentProcessInfo *pproc)
{
	return pproc->org_pgd;
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
	ndckpt_mfence();
	pproc->valid_ctx_idx = ctx_idx;
	ndckpt_clwb(&pproc->valid_ctx_idx);
	ndckpt_sfence();
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

void pproc_set_vma_range(struct PersistentProcessInfo *pproc,
			 struct mm_struct *mm, int ctx_idx)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
			pproc->ctx[ctx_idx].heap.start = vma->vm_start;
			pproc->ctx[ctx_idx].heap.end = vma->vm_end;
			continue;
		}
		if (vma->vm_start <= mm->start_stack &&
		    mm->start_stack <= vma->vm_end) {
			pproc->ctx[ctx_idx].stack.start = vma->vm_start;
			pproc->ctx[ctx_idx].stack.end = vma->vm_end;
			continue;
		}
	}
	ndckpt_clwb_range(&pproc->ctx[ctx_idx].heap,
			  sizeof(struct PersistentVMARange));
	ndckpt_clwb_range(&pproc->ctx[ctx_idx].stack,
			  sizeof(struct PersistentVMARange));
}

#ifdef NDCKPT_DEBUG
static const char *pctx_reg_names[PCTX_REGS] = {
	"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8",
	"R9",  "R10", "R11", "R12", "R13", "R14", "R15", "RIP", "RFLAGS",
};
#endif

void pproc_print_regs(struct PersistentProcessInfo *proc, int ctx_idx)
{
	struct PersistentExecutionContext *ctx;
	int i;
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	ctx = &proc->ctx[ctx_idx];
	pr_ndckpt("regs in ctx[%d]\n", ctx_idx);
	for (i = 0; i < PCTX_REGS; i++) {
		pr_ndckpt("  %6s: 0x%016llX%c", pctx_reg_names[i], ctx->regs[i],
			  (i & 1) ? '\n' : ' ');
	}
}

void pproc_printk(struct PersistentProcessInfo *pproc)
{
	int i;
	if (!pproc_is_valid(pproc)) {
		pr_ndckpt("invalid last_proc_info\n");
		return;
	}
	pr_ndckpt("PersistentProcessInfo at pobj #%lld:\n",
		  pobj_get_header(pproc)->id);
	pr_ndckpt("  Ctx #%d is valid\n", pproc->valid_ctx_idx);
	for (i = 0; i < 2; i++) {
		pr_ndckpt("Ctx #%d:\n", i);
		//pr_ndckpt_pml4(pproc->ctx[i].pgd);
		ndckpt_print_pml4(pproc->ctx[i].pgd);
		pproc_print_regs(pproc, i);
	}
}

static void sync_nvdimm_pages(pgd_t *dst_t4, pgd_t *src_t4, uint64_t start,
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
	for (addr = start; addr < end;) {
		traverse_pml4e(addr, src_t4, &src_e4, &src_t3);
		traverse_pml4e(addr, dst_t4, &dst_e4, &dst_t3);
		if (!src_t3) {
			addr += PGDIR_SIZE;
			continue;
		}
		if (!dst_t3 || !ndckpt_is_virt_addr_in_nvdimm(dst_t3)) {
			// Alloc
			tmp_page_addr = ndckpt_alloc_zeroed_page();
			if (dst_t3) {
				memcpy(tmp_page_addr, dst_t3, PAGE_SIZE);
				ndckpt_clwb_range(tmp_page_addr, PAGE_SIZE);
			}
			*(p4d_t *)dst_e4 =
				__p4d(_PAGE_TABLE |
				      ndckpt_virt_to_phys(tmp_page_addr));
			ndckpt_clwb(dst_e4);
			continue; // Retry
		}
		traverse_pdpte(addr, src_t3, &src_e3, &src_t2);
		traverse_pdpte(addr, dst_t3, &dst_e3, &dst_t2);
		if (!src_t2) {
			addr += PUD_SIZE;
			continue;
		}
		if (!dst_t2 || !ndckpt_is_virt_addr_in_nvdimm(dst_t2)) {
			// Alloc
			tmp_page_addr = ndckpt_alloc_zeroed_page();
			if (dst_t2) {
				memcpy(tmp_page_addr, dst_t2, PAGE_SIZE);
				ndckpt_clwb_range(tmp_page_addr, PAGE_SIZE);
			}
			*dst_e3 = __pud(_PAGE_TABLE |
					ndckpt_virt_to_phys(tmp_page_addr));
			ndckpt_clwb(dst_e3);
			continue; // Retry
		}
		traverse_pde(addr, src_t2, &src_e2, &src_t1);
		traverse_pde(addr, dst_t2, &dst_e2, &dst_t1);
		if (!src_t1) {
			addr += PMD_SIZE;
			continue;
		}
		if (!dst_t1 || !ndckpt_is_virt_addr_in_nvdimm(dst_t1)) {
			// Alloc
			tmp_page_addr = ndckpt_alloc_zeroed_page();
			if (dst_t1) {
				memcpy(tmp_page_addr, dst_t1, PAGE_SIZE);
				ndckpt_clwb_range(tmp_page_addr, PAGE_SIZE);
			}
			*dst_e2 = __pmd(_PAGE_TABLE |
					ndckpt_virt_to_phys(tmp_page_addr));
			ndckpt_clwb(dst_e2);
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
			// Alloc
			tmp_page_addr = ndckpt_alloc_zeroed_page();
			if (dst_page_vaddr) {
				memcpy(tmp_page_addr, dst_page_vaddr,
				       PAGE_SIZE);
				ndckpt_clwb_range(tmp_page_addr, PAGE_SIZE);
			}
			*dst_e1 = pfn_pte(
				PHYS_PFN(ndckpt_virt_to_phys(tmp_page_addr)),
				vma->vm_page_prot);
			ndckpt_clwb(dst_e1);
			update_mmu_cache(vma, addr, dst_e1);
			continue; // Retry
		}
		// TODO: Reduce copy with dirty flag
		memcpy(dst_page_vaddr, src_page_vaddr, PAGE_SIZE);
		// Do not clwb dst_pages at this time because dst will be running ctx
		// and they will be flushed on the next checkpoint.
		addr += PAGE_SIZE;
	}
	ndckpt_sfence();
}

static void sync_dram_pages(pgd_t *dst_t4, pgd_t *src_t4, uint64_t start,
			    uint64_t end, struct vm_area_struct *vma)
{
	// Do sync_nvdimm_pages first to ensure
	// the node which have child node on nvdimm is on nvdimm.
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

	for (addr = start; addr < end;) {
		traverse_pml4e(addr, src_t4, &src_e4, &src_t3);
		traverse_pml4e(addr, dst_t4, &dst_e4, &dst_t3);
		if (!src_t3) {
			addr += PGDIR_SIZE;
			continue;
		}
		if (!dst_t3) {
			*dst_e4 = *src_e4;
			ndckpt_clwb(dst_e4);
			continue; // Retry
		}
		traverse_pdpte(addr, src_t3, &src_e3, &src_t2);
		traverse_pdpte(addr, dst_t3, &dst_e3, &dst_t2);
		if (!src_t2) {
			addr += PUD_SIZE;
			continue;
		}
		if (!dst_t2) {
			*dst_e3 = *src_e3;
			ndckpt_clwb(dst_e3);
			continue; // Retry
		}
		traverse_pde(addr, src_t2, &src_e2, &src_t1);
		traverse_pde(addr, dst_t2, &dst_e2, &dst_t1);
		if (!src_t1) {
			addr += PMD_SIZE;
			continue;
		}
		if (!dst_t1) {
			// Alloc
			*dst_e2 = *src_e2;
			ndckpt_clwb(dst_e2);
			continue; // Retry
		}
		traverse_pte(addr, src_t1, &src_e1, &src_page_vaddr);
		traverse_pte(addr, dst_t1, &dst_e1, &dst_page_vaddr);
		if (!src_page_vaddr) {
			addr += PAGE_SIZE;
			continue;
		}
		if (!dst_page_vaddr) {
			*dst_e1 = *src_e1;
			ndckpt_clwb(dst_e1);
			continue; // Retry
		}
		addr += PAGE_SIZE;
	}
	ndckpt_sfence();
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
	pr_ndckpt_flush("flush_dirty_pages: [0x%016llX, 0x%016llX)\n", start,
			end);
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
		BUG_ON(!ndckpt_is_virt_addr_in_nvdimm(page_vaddr));
		if ((e1->pte & _PAGE_DIRTY) == 0) {
			// Page is clean. Skip flushing
		}
		ndckpt_clwb_range(page_vaddr, PAGE_SIZE);
		e1->pte &= ~(uint64_t)_PAGE_DIRTY;
		ndckpt_clwb(&e1->pte);
		pr_ndckpt_flush(
			"flushed dirty page @ 0x%016llX v->p 0x%016llX\n", addr,
			page_paddr);
		addr += PAGE_SIZE;
	}
	ndckpt_sfence();
	pr_ndckpt_flush("SFENCE() done\n");
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

static void sync_target_vmas(struct mm_struct *mm, pgd_t *dst_pgd,
			     pgd_t *src_pgd)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) == 0) {
			continue;
		}
		sync_nvdimm_pages(dst_pgd, src_pgd, vma->vm_start, vma->vm_end,
				  vma);
	}
}

static void sync_normal_vmas(struct mm_struct *mm, pgd_t *dst_pgd,
			     pgd_t *src_pgd)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) != 0) {
			continue;
		}
		// first, erase existed dram mappings
		erase_mappings_to_dram(dst_pgd, vma->vm_start, vma->vm_end);
	}
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) != 0) {
			continue;
		}
		sync_dram_pages(dst_pgd, src_pgd, vma->vm_start, vma->vm_end,
				vma);
	}
}

static inline void switch_mm_context(struct task_struct *target,
				     struct mm_struct *mm, pgd_t *new_pgd)
{
	// Set mm->pgd and cr3
	mm->pgd = new_pgd;
	if (target != current) {
		// skip updating cr3 because current context is not a target.
		mm->ndckpt_flags |= MM_NDCKPT_FLUSH_CR3;
		return;
	}
	// https://elixir.bootlin.com/linux/v5.1.3/source/arch/x86/include/asm/tlbflush.h#L131
	// We can't specify CR3_NOFLUSH here
	// because mappings may be different between two contexts.
	write_cr3((CR3_ADDR_MASK & ndckpt_virt_to_phys(new_pgd)) |
		  (CR3_PCID_MASK & __read_cr3()) /* | CR3_NOFLUSH */);
}

void pproc_commit(struct task_struct *target,
		  struct PersistentProcessInfo *pproc, struct mm_struct *mm,
		  struct pt_regs *regs)
{
	const int prev_running_ctx_idx = pproc_get_running_ctx(pproc);
	const int next_running_ctx_idx = 1 - prev_running_ctx_idx;

	if (!spin_trylock(&pproc->ckpt_lock)) {
		printk("Failed to pproc_commit\n");
		return;
	}

	pproc_set_regs(pproc, prev_running_ctx_idx, regs);
	flush_target_vmas(mm);
	pproc_set_vma_range(pproc, mm, prev_running_ctx_idx);
	pr_ndckpt_ckpt("Ctx #%d has been committed\n", prev_running_ctx_idx);
	// At this point, running ctx has become clean so both context is valid.
	pproc_set_valid_ctx(pproc, prev_running_ctx_idx);
	// prepare next running context
	pr_ndckpt_ckpt("Sync Ctx #%d -> Ctx #%d\n", prev_running_ctx_idx,
		       next_running_ctx_idx);
	sync_target_vmas(mm, pproc->ctx[next_running_ctx_idx].pgd,
			 pproc->ctx[prev_running_ctx_idx].pgd);
	// Finally, switch the cr3 to the new running context's pgd.
	switch_mm_context(target, mm, pproc->ctx[next_running_ctx_idx].pgd);
	spin_unlock(&pproc->ckpt_lock);
}

static void copy_pml4_kernel_map(pgd_t *ctx_pgd, pgd_t *mm_pgd)
{
	int i;
	pr_ndckpt(
		"copy kernel map to ctx_pgd @ 0x%016llX from mm_pgd 0x%016llX\n",
		(uint64_t)ctx_pgd, (uint64_t)mm_pgd);
	for (i = PAGE_SIZE / sizeof(pgd_t) / 2; i < PAGE_SIZE / sizeof(pgd_t);
	     i++) {
		ctx_pgd[i].pgd = mm_pgd[i].pgd;
	}
}

static bool verify_pml4_kernel_map(pgd_t *mm_pgd, pgd_t *ctx_pgd)
{
	int i;
	bool is_invalid = false;
	pr_ndckpt("verify ctx_pgd @ 0x%016llX with mm_pgd 0x%016llX\n",
		  (uint64_t)ctx_pgd, (uint64_t)mm_pgd);
	for (i = PAGE_SIZE / sizeof(pgd_t) / 2; i < PAGE_SIZE / sizeof(pgd_t);
	     i++) {
		if (mm_pgd[i].pgd == ctx_pgd[i].pgd)
			continue;
		pr_ndckpt(
			"PML4[0x%03X]: ctx_pgd != mm_pgd!! 0x%016lX vs 0x%016lX\n",
			i, ctx_pgd[i].pgd, mm_pgd[i].pgd);
		is_invalid = true;
	}
	return is_invalid;
}

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
		e1 = &t1[i1];
		if ((e1->pte & _PAGE_PRESENT) == 0) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = e1->pte & PTE_PFN_MASK;
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

static void mark_target_vmas(struct mm_struct *mm)
{
	struct vm_area_struct *vma = mm->mmap;
	pr_ndckpt("mm->brk = 0x%016llX\n", (uint64_t)mm->brk);
	pr_ndckpt("mm->start_brk = 0x%016llX\n", (uint64_t)mm->start_brk);
	while (vma) {
		pr_ndckpt("vma@0x%016llX [0x%016llX - 0x%016llX] 0x%016llX\n",
			  (uint64_t)vma, (uint64_t)vma->vm_start,
			  (uint64_t)vma->vm_end, (uint64_t)vma->vm_flags);
		vma->vm_ckpt_flags = 0;
		if ((vma->vm_flags & VM_WRITE) == 0) {
			// No need to save readonly vma.
			pr_ndckpt("  This vma is readonly. skip.\n");
		} else if (vma->vm_start <= mm->brk &&
			   vma->vm_end >= mm->start_brk) {
			pr_ndckpt("  This is heap vma. Set VM_CKPT_TARGET.\n");
			//vma->vm_ckpt_flags |= VM_CKPT_TARGET;
		} else if (vma->vm_start <= mm->start_stack &&
			   mm->start_stack <= vma->vm_end) {
			pr_ndckpt("  This is stack vma. Set VM_CKPT_TARGET.\n");
			vma->vm_ckpt_flags |= VM_CKPT_TARGET;
		}
		vma = vma->vm_next;
	}
}

static void fix_dram_part_of_ctx(struct mm_struct *mm,
				 struct PersistentProcessInfo *pproc, int idx)
{
	// This funcion fixes dram mappings of ctx to match with given mm.
	copy_pml4_kernel_map(pproc->ctx[idx].pgd, mm->pgd);
	sync_normal_vmas(mm, pproc->ctx[idx].pgd, mm->pgd);
}

static void fix_pmem_part_of_ctx(struct PersistentMemoryManager *pman, struct mm_struct *mm,
				 struct PersistentProcessInfo *pproc, int idx)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) == 0) {
			continue;
		}
	  replace_stack_pages_with_nvdimm(pman, pproc->ctx[idx].pgd, vma);
	}
}

int64_t pproc_init(struct task_struct *target,
		   struct PersistentMemoryManager *pman, struct mm_struct *mm,
		   struct pt_regs *regs)
{
	struct vm_area_struct *vma;
	pgd_t *pgd_ctx0;
	pgd_t *pgd_ctx1;
	struct PersistentProcessInfo *pproc = pproc_alloc();

	BUG_ON(!pproc);
	pr_ndckpt("pproc pobj #%lld\n", pobj_get_header(pproc)->id);

	// ctx 0 (This ctx will be valid first)
	pgd_ctx0 = ndckpt_alloc_zeroed_page();
	pproc_set_pgd(pproc, 0, pgd_ctx0);
	// ctx 1 (dummy)
	pgd_ctx1 = ndckpt_alloc_zeroed_page();
	pproc_set_pgd(pproc, 1, pgd_ctx1);

	// Setup non-volatile part of ctx0
	memcpy(pgd_ctx0, mm->pgd, PAGE_SIZE);
	ndckpt_clwb_range(pgd_ctx0, PAGE_SIZE);
	memcpy(pgd_ctx1, mm->pgd, PAGE_SIZE);
	ndckpt_clwb_range(pgd_ctx1, PAGE_SIZE);

	pproc_set_regs(pproc, 0, regs);
	pproc_set_valid_ctx(pproc, 0); // dummy

	return pproc_restore(pman, target, pproc);
}

int64_t pproc_restore(struct PersistentMemoryManager *pman,
		      struct task_struct *target,
		      struct PersistentProcessInfo *pproc)
{
	struct pt_regs *regs = task_pt_regs(target);
	struct mm_struct *mm = target->mm;
	const int valid_ctx_idx = pproc->valid_ctx_idx;

	spin_lock_init(&pproc->ckpt_lock);

	pr_ndckpt_restore("restore from obj id = %016llX\n", target->ndckpt_id);
	pproc_printk(pproc);
	BUG_ON(valid_ctx_idx < 0 || 2 <= valid_ctx_idx);
	// Copy data to running ctx to valid ctx and adjust dram mappings
	pr_ndckpt_restore("  valid_ctx_idx: %d\n", valid_ctx_idx);
	pproc_print_regs(pproc, valid_ctx_idx);
	pproc_restore_regs(regs, pproc, valid_ctx_idx);

	// Save original mm->pgd to pproc
	// This is only valid while the power is on, so there is no need to flush.
	pproc->org_pgd = mm->pgd;
	mark_target_vmas(mm);

	fix_pmem_part_of_ctx(pman, mm, pproc, 0);
	fix_pmem_part_of_ctx(pman, mm, pproc, 1);
	//fix_dram_part_of_ctx(mm, pproc, 0);
	//fix_dram_part_of_ctx(mm, pproc, 1);
	pproc_set_vma_range(pproc, mm, 0);
	pproc_set_vma_range(pproc, mm, 1);

	pman_set_last_proc_info(pman, NULL);
	// THIS IS FAKE: we set ctx[1] as valid to commit ctx[0]
	pproc_set_valid_ctx(pproc, 1 - valid_ctx_idx);
	mm->pgd = pproc->ctx[valid_ctx_idx].pgd;
	pproc_commit(target, pproc, target->mm, regs);

	// At this point, ctx[0] is commited and marked as valid,
	// and ctx[1] is synced with ctx[0] and ready to go
	pman_set_last_proc_info(pman, pproc);

	// Sanity check...
	pr_ndckpt_pml4(mm->pgd);
	pr_ndckpt_pml4(pproc->ctx[0].pgd);
	pr_ndckpt_pml4(pproc->ctx[1].pgd);
	BUG_ON(verify_pml4_kernel_map(pproc->ctx[0].pgd, mm->pgd));
	BUG_ON(verify_pml4_kernel_map(pproc->ctx[1].pgd, mm->pgd));
	return regs->ax;
}
