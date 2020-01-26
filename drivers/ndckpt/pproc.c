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
#define PCTX_REG_IDX_FSBASE 18
#define PCTX_REG_IDX_GSBASE 19
// gregs[16] + RIP + RFLAGS + FS/GS
#define PCTX_REGS (16 + 1 + 1 + 2)

struct PersistentVMARange {
	// Corresponds to vma->vm_start/end
	uint64_t vm_start, vm_end, vm_flags;
	pgprot_t vm_page_prot;
};

#define PCTX_NUM_OF_VMAS 16

struct PersistentProcessInfo {
	struct PersistentExecutionContext {
		pgd_t *volatile pgd;
		uint64_t regs[PCTX_REGS];
		int vma_idx_stack;
		int vma_idx_heap;
		int vma_idx_data;
		int end_vma_idx;
		struct PersistentVMARange vmas[PCTX_NUM_OF_VMAS];
		struct fpu fpu;
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

static struct PersistentProcessInfo *
pproc_alloc(struct PersistentMemoryManager *pman)
{
	struct PersistentProcessInfo *pproc = pman_alloc_zeroed_pages(
		pman, (sizeof(struct PersistentProcessInfo) + PAGE_SIZE - 1) >>
			      PAGE_SHIFT);
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
		    struct task_struct *src)
{
	// It assumes pt_regs is fully saved.
	struct pt_regs *regs = task_pt_regs(src);
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
	ctx->regs[PCTX_REG_IDX_FSBASE] = x86_fsbase_read_task(src);
	ctx->regs[PCTX_REG_IDX_GSBASE] = x86_gsbase_read_task(src);
	pr_ndckpt("fs: %016llX\n", ctx->regs[PCTX_REG_IDX_FSBASE]);
	pr_ndckpt("gs: %016llX\n", ctx->regs[PCTX_REG_IDX_GSBASE]);
	BUG_ON(!src->thread.fpu.initialized);
	memcpy_and_clwb(&ctx->fpu, &src->thread.fpu, sizeof(ctx->fpu));
	ndckpt_clwb_range(&ctx->regs[0], sizeof(ctx->regs));
	ndckpt_sfence();
}

void pproc_restore_vm_area_struct(struct vm_area_struct *dst,
				  struct PersistentExecutionContext *ectx,
				  int vma_idx)
{
	// This believes there is no need to remap this vma.
	// We may need to remap vmas to treat modification properly
	struct PersistentVMARange *src;
	pr_ndckpt("  restoring from vmas[%d]\n", vma_idx);
	BUG_ON(vma_idx < 0);
	src = &ectx->vmas[vma_idx];
	dst->vm_start = src->vm_start;
	dst->vm_end = src->vm_end;
	dst->vm_flags = src->vm_flags;
	dst->vm_page_prot = src->vm_page_prot;
}

static void pproc_restore_vmas(struct mm_struct *mm,
			       struct PersistentProcessInfo *proc, int ctx_idx)
{
	struct PersistentExecutionContext *ctx;
	struct vm_area_struct *vma;
	int i;
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	ctx = &proc->ctx[ctx_idx];
	pr_ndckpt("Restoring vmas saved in ctx[%d]: %d\n", ctx_idx,
		  ctx->end_vma_idx);
	pr_ndckpt("mm->brk = 0x%016llX\n", (uint64_t)mm->brk);
	pr_ndckpt("mm->start_brk = 0x%016llX\n", (uint64_t)mm->start_brk);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_WRITE) == 0) {
			continue;
		}
		if (vma->vm_file && ctx->vma_idx_data >= 0) {
			pr_ndckpt("data vma\n");
			pproc_restore_vm_area_struct(vma, ctx,
						     ctx->vma_idx_data);
			continue;
		}
		if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk &&
		    ctx->vma_idx_heap >= 0) {
			pr_ndckpt("heap vma\n");
			pproc_restore_vm_area_struct(vma, ctx,
						     ctx->vma_idx_heap);
			continue;
		}
		if (vma->vm_start <= mm->start_stack &&
		    mm->start_stack <= vma->vm_end && ctx->vma_idx_stack >= 0) {
			pr_ndckpt("stack vma\n");
			pproc_restore_vm_area_struct(vma, ctx,
						     ctx->vma_idx_stack);
			continue;
		}
	}
	for (i = 0; i < ctx->end_vma_idx; i++) {
		if (i == ctx->vma_idx_stack || i == ctx->vma_idx_heap ||
		    i == ctx->vma_idx_data)
			continue;
		vma = vm_area_alloc(mm);
		pr_ndckpt("ANONYMOUS vma\n");
		vma->vm_ops = NULL;
		pproc_restore_vm_area_struct(vma, ctx, i);
		insert_vm_struct(mm, vma);
	}
}

extern void fpu__restore(struct fpu *fpu);
void pproc_restore_regs(struct task_struct *dst,
			struct PersistentProcessInfo *proc, int ctx_idx)
{
	// It assumes pt_regs is fully saved.
	struct pt_regs *regs = task_pt_regs(dst);
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

	// https://elixir.bootlin.com/linux/v5.1.3/source/arch/x86/kernel/process_64.c#L712
	do_arch_prctl_64(dst, ARCH_SET_FS, ctx->regs[PCTX_REG_IDX_FSBASE]);
	do_arch_prctl_64(dst, ARCH_SET_GS, ctx->regs[PCTX_REG_IDX_GSBASE]);

	BUG_ON(!dst->thread.fpu.initialized);
	memcpy(&dst->thread.fpu, &ctx->fpu, sizeof(ctx->fpu));
	dst->thread.fpu.last_cpu = -1;
	fpu__restore(&dst->thread.fpu);
}

void pproc_save_vmas(struct PersistentProcessInfo *pproc, int ctx_idx,
		     struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct PersistentExecutionContext *ctx = &pproc->ctx[ctx_idx];
	int used = 0;

	ctx->vma_idx_stack = -1;
	ndckpt_clwb(&ctx->vma_idx_stack);
	ctx->vma_idx_heap = -1;
	ndckpt_clwb(&ctx->vma_idx_heap);
	ctx->vma_idx_data = -1;
	ndckpt_clwb(&ctx->vma_idx_data);

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		pr_ndckpt_vma(vma);
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) == 0) {
			pr_ndckpt("  This is not a target. skip.\n");
			continue;
		}
		if (used >= PCTX_NUM_OF_VMAS) {
			printk("Too many vmas\n");
			BUG();
		}
		ctx->vmas[used].vm_start = vma->vm_start;
		ctx->vmas[used].vm_end = vma->vm_end;
		ctx->vmas[used].vm_flags = vma->vm_flags;
		ctx->vmas[used].vm_page_prot = vma->vm_page_prot;
		if (!vma_is_anonymous(vma)) {
			pr_ndckpt("  vma[%d] is .data\n", used);
			BUG_ON(ctx->vma_idx_data != -1);
			ctx->vma_idx_data = used;
			ndckpt_clwb(&ctx->vma_idx_data);
		}
		if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
			pr_ndckpt("  vma[%d] is heap.\n", used);
			BUG_ON(ctx->vma_idx_heap != -1);
			ctx->vma_idx_heap = used;
			ndckpt_clwb(&ctx->vma_idx_heap);
		} else if (vma->vm_start <= mm->start_stack &&
			   mm->start_stack <= vma->vm_end) {
			pr_ndckpt("  vma[%d] is stack.\n", used);
			BUG_ON(ctx->vma_idx_stack != -1);
			ctx->vma_idx_stack = used;
			ndckpt_clwb(&ctx->vma_idx_stack);
		} else {
			pr_ndckpt("  vma[%d] is UNKNOWN but target.\n", used);
		}
		ndckpt_clwb_range(&ctx->vmas[used],
				  sizeof(struct PersistentVMARange));
		used++;
	}
	ctx->end_vma_idx = used;
	ndckpt_clwb(&ctx->end_vma_idx);
	pr_ndckpt("Saved %d vmas\n", ctx->end_vma_idx);
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

void pproc_print_vmas(struct PersistentProcessInfo *proc, int ctx_idx)
{
	struct PersistentExecutionContext *ctx;
	int i;
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	ctx = &proc->ctx[ctx_idx];
	pr_ndckpt("vmas saved in ctx[%d]: %d\n", ctx_idx, ctx->end_vma_idx);
	for (i = 0; i < ctx->end_vma_idx; i++) {
		pr_ndckpt_vma((&ctx->vmas[i]));
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
		pr_ndckpt_pml4(pproc->ctx[i].pgd);
		pproc_print_regs(pproc, i);
		pproc_print_vmas(pproc, i);
	}
}

//#define DEBUG_SYNC_DRAM_PAGES
static void sync_dram_pages(pgd_t *dst_t4, pgd_t *src_t4, uint64_t start,
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

	int count = 0;

#ifdef DEBUG_SYNC_DRAM_PAGES
	pr_ndckpt("sync src");
	pr_ndckpt_pgtable_range(src_t4, start, end);
	pr_ndckpt("begin");
	pr_ndckpt_pgtable_range(dst_t4, start, end);
#endif

	for (addr = start; addr < end;) {
		traverse_pml4e(addr, src_t4, &src_e4, &src_t3);
		traverse_pml4e(addr, dst_t4, &dst_e4, &dst_t3);
		if (!src_t3) {
			addr = next_pml4e_addr(addr);
			continue;
		}
		if (!ndckpt_is_virt_addr_in_nvdimm(dst_t3) &&
		    dst_t3 != src_t3) {
			*dst_e4 = *src_e4;
			ndckpt_clwb(dst_e4);
			count++;
			continue; // Retry
		}
		traverse_pdpte(addr, src_t3, &src_e3, &src_t2);
		traverse_pdpte(addr, dst_t3, &dst_e3, &dst_t2);
		if (!src_t2) {
			addr = next_pdpte_addr(addr);
			continue;
		}
		if (!ndckpt_is_virt_addr_in_nvdimm(dst_t2) &&
		    dst_t2 != src_t2) {
			*dst_e3 = *src_e3;
			ndckpt_clwb(dst_e3);
			count++;
			continue; // Retry
		}
		traverse_pde(addr, src_t2, &src_e2, &src_t1);
		traverse_pde(addr, dst_t2, &dst_e2, &dst_t1);
		if (!src_t1) {
			addr = next_pde_addr(addr);
			continue;
		}
		if (!ndckpt_is_virt_addr_in_nvdimm(dst_t1) &&
		    dst_t1 != src_t1) {
			*dst_e2 = *src_e2;
			ndckpt_clwb(dst_e2);
			count++;
			continue; // Retry
		}
		traverse_pte(addr, src_t1, &src_e1, &src_page_vaddr);
		traverse_pte(addr, dst_t1, &dst_e1, &dst_page_vaddr);
		if (!src_page_vaddr) {
			addr = next_pte_addr(addr);
			continue;
		}
		BUG_ON(ndckpt_is_virt_addr_in_nvdimm(dst_page_vaddr));
		if (dst_page_vaddr != src_page_vaddr) {
			*dst_e1 = *src_e1;
			ndckpt_clwb(dst_e1);
			count++;
			continue; // Retry
		}
		addr = next_pte_addr(addr);
	}
	ndckpt_sfence();
#ifdef DEBUG_SYNC_DRAM_PAGES
	pr_ndckpt("after");
	pr_ndckpt_pgtable_range(dst_t4, start, end);
	pr_ndckpt("end count=%d\n", count);
#endif
}

//#define DEBUG_FLUSH_DIRTY_PAGES
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
#ifdef DEBUG_FLUSH_DIRTY_PAGES
	pr_ndckpt_pgtable_range(t4, start, end);
	pr_ndckpt("flush_dirty_pages: [0x%016llX, 0x%016llX)\n", start, end);
#endif
	BUG_ON(!ndckpt_is_virt_addr_in_nvdimm(t4));
	for (addr = start; addr < end;) {
		traverse_pml4e(addr, t4, &e4, &t3);
		if (!t3) {
			addr = next_pml4e_addr(addr);
			continue;
		}
		traverse_pdpte(addr, t3, &e3, &t2);
		if (!t2) {
			addr = next_pdpte_addr(addr);
			continue;
		}
		traverse_pde(addr, t2, &e2, &t1);
		if (!t1) {
			addr = next_pde_addr(addr);
			continue;
		}
		traverse_pte(addr, t1, &e1, &page_vaddr);
		if (!page_vaddr) {
			addr = next_pte_addr(addr);
			continue;
		}
		page_paddr = ndckpt_v2p(page_vaddr);
		if (!ndckpt_is_virt_addr_in_nvdimm(page_vaddr)) {
			if (!pte_write(*e1)) {
				// Read only, before CoW. Skip flush.
				addr = next_pte_addr(addr);
				continue;
			}
			pr_ndckpt_pgtable_range(t4, addr, addr + 1);
			BUG();
		}
		if ((e1->pte & _PAGE_DIRTY) == 0) {
			// Page is clean. Skip flushing
		}
		ndckpt_clwb_range(page_vaddr, PAGE_SIZE);
		e1->pte &= ~(uint64_t)_PAGE_DIRTY;
		ndckpt_clwb(&e1->pte);
#ifdef DEBUG_FLUSH_DIRTY_PAGES
		pr_ndckpt("flushed dirty page @ 0x%016llX v->p 0x%016llX\n",
			  addr, page_paddr);
#endif
		addr = next_pte_addr(addr);
	}
	ndckpt_sfence();
}

//#define DEBUG_ERASE_DRAM_MAPPINGS
static void erase_dram_mappings(pgd_t *t4, uint64_t start, uint64_t end)
{
	// This only erase entry on NVDIMM to avoid SEGV after reboot.
	uint64_t addr;
	pgd_t *e4;
	pud_t *t3 = NULL;
	pud_t *e3;
	pmd_t *t2 = NULL;
	pmd_t *e2;
	pte_t *t1 = NULL;
	pte_t *e1;
	void *page_vaddr;
#ifdef DEBUG_ERASE_DRAM_MAPPINGS
	pr_ndckpt("[0x%016llX, 0x%016llX)\n", start, end);
	pr_ndckpt("begin");
	pr_ndckpt_pgtable_range(t4, start, end);
#endif
	BUG_ON(!ndckpt_is_virt_addr_in_nvdimm(t4));
	for (addr = start; addr < end;) {
		traverse_pml4e(addr, t4, &e4, &t3);
		if (!ndckpt_is_virt_addr_in_nvdimm(t3)) {
			unmap_pdpt_and_clwb(e4);
			addr = next_pml4e_addr(addr);
			continue;
		}
		traverse_pdpte(addr, t3, &e3, &t2);
		if (!ndckpt_is_virt_addr_in_nvdimm(t2)) {
			unmap_pd_and_clwb(e3);
			addr = next_pdpte_addr(addr);
			continue;
		}
		traverse_pde(addr, t2, &e2, &t1);
		if (!ndckpt_is_virt_addr_in_nvdimm(t1)) {
			unmap_pt_and_clwb(e2);
			addr = next_pde_addr(addr);
			continue;
		}
		traverse_pte(addr, t1, &e1, &page_vaddr);
		if (!ndckpt_is_virt_addr_in_nvdimm(page_vaddr)) {
			unmap_page_and_clwb(e1);
		}
		addr = next_pte_addr(addr);
	}
	ndckpt_sfence();
#ifdef DEBUG_ERASE_DRAM_MAPPINGS
	pr_ndckpt("after");
	pr_ndckpt_pgtable_range(t4, start, end);
	pr_ndckpt("end");
#endif
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

static void sync_normal_vmas(struct mm_struct *mm, pgd_t *dst_pgd,
			     pgd_t *src_pgd)
{
	// Remove dram mappings for Lower half of mapping (for user space)
	// Upper half of mapping for kernel is replaced in copy_pml4_kernel_map
	struct vm_area_struct *vma;
	erase_dram_mappings(dst_pgd, 0, 1ULL << 47);
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

#define ASSERT_SYNC_PAGES
#ifdef ASSERT_SYNC_PAGES
#define ASSERT(x)                                                              \
	do {                                                                   \
		if (x)                                                         \
			break;                                                 \
		printk(KERN_EMERG "### ASSERTION FAILED %s: %s: %d: %s\n",     \
		       __FILE__, __func__, __LINE__, #x);                      \
		dump_stack();                                                  \
		BUG();                                                         \
	} while (0)
#else
#define ASSERT(x)
#endif

static inline void sync_pages_pte(struct mm_struct *mm, pte_t *t, pte_t *ref_t,
				  uint64_t addr, uint64_t end)
{
	while (addr < end) {
		pte_t *e, *ref_e;
		void *page_vaddr, *ref_page_vaddr;
		uint8_t prev_state, next_state;

		traverse_pte(addr, ref_t, &ref_e, &ref_page_vaddr);
		traverse_pte(addr, t, &e, &page_vaddr);
		prev_state = page_state_pte(e);
		next_state = page_state_pte(ref_e);

		if (prev_state == next_state && next_state != PAGE_STATE_Pnd &&
		    next_state != PAGE_STATE_Pnc) {
			// (X, X) -> Not mapped
			// (Pv, Pv) -> Shared. No need to sync
			// (Pnc, Pnc) -> Clean. No need to sync
			if (prev_state == PAGE_STATE_Pv &&
			    (page_vaddr != ref_page_vaddr ||
			     page_fixed_attr_pte(e) !=
				     page_fixed_attr_pte(ref_e))) {
#ifdef NDCKPT_PRINT_SYNC_PAGES
				pr_ndckpt(
					"%016llX: %d -> %d (update mapping)\n",
					addr, prev_state, next_state);
#endif
				// DRAM page update. copy ent.
				copy_pte_and_clwb(e, ref_e);
			}
		} else if (next_state == PAGE_STATE_X) {
#ifdef NDCKPT_PRINT_SYNC_PAGES
			pr_ndckpt("%016llX: %d -> %d\n", addr, prev_state,
				  next_state);
#endif
			unmap_page_and_clwb(e);
		} else if (next_state == PAGE_STATE_Pv) {
#ifdef NDCKPT_PRINT_SYNC_PAGES
			pr_ndckpt("%016llX: %d -> %d ent@0x%016llX\n", addr,
				  prev_state, next_state, ndckpt_v2p(e));
#endif
			unmap_page_and_clwb(e);
			copy_pte_and_clwb(e, ref_e);
		} else {
#ifdef NDCKPT_PRINT_SYNC_PAGES
			pr_ndckpt("%016llX: %d -> %d\n", addr, prev_state,
				  next_state);
#endif
			if (prev_state == PAGE_STATE_X ||
			    prev_state == PAGE_STATE_Pv) {
				map_zeroed_nvdimm_page_page(
					e, page_fixed_attr_pte(ref_e));
				traverse_pte(addr, t, &e, &page_vaddr);
			}
			if (page_fixed_attr_pte(e) !=
			    page_fixed_attr_pte(ref_e)) {
#ifdef NDCKPT_PRINT_SYNC_PAGES
				pr_ndckpt("  attr synced\n");
#endif
				sync_fixed_attr_pte(e, ref_e);
			}
			memcpy(page_vaddr, ref_page_vaddr, PAGE_SIZE);
			// Following bits are only referenced in the power cycle, so no need to flush
			e->pte |= _PAGE_DIRTY;
			ref_e->pte &= ~_PAGE_DIRTY;
		}
		addr = next_pte_addr(addr);
	}
}

#define table_state_not_changed(s) (s == 0b0000 || s == 0b1010 || s == 0b1111)

//#define DEBUG_NDCKPT_SYNC_PAGES_TABLES
#ifdef DEBUG_NDCKPT_SYNC_PAGES_TABLES
#define pr_ndckpt_sync_state_trans(addr, prev_state, next_state)               \
	pr_ndckpt("%016llX: %d -> %d\n", addr, prev_state, next_state)
#else
#define pr_ndckpt_sync_state_trans(addr, prev_state, next_state)
#endif

#define def_sync_pages(ename, ctname, ttype, cttype, nextfunc)                     \
	static inline void sync_pages_##ename(struct mm_struct *mm, ttype *t,      \
					      ttype *ref_t, uint64_t addr,         \
					      uint64_t end)                        \
	{                                                                          \
		while (addr < end) {                                               \
			const uint64_t next_addr = next_##ename##_addr(addr);      \
			ttype *e, *ref_e;                                          \
			cttype *ct, *ref_ct;                                       \
			uint8_t prev_state, next_state;                            \
                                                                                   \
			traverse_##ename(addr, ref_t, &ref_e, &ref_ct);            \
			traverse_##ename(addr, t, &e, &ct);                        \
			prev_state = table_state_##ename(e);                       \
			next_state = table_state_##ename(ref_e);                   \
			pr_ndckpt_sync_state_trans(addr, prev_state,               \
						   next_state);                    \
                                                                                   \
			if (prev_state ^ next_state) {                             \
				if (next_state == TABLE_STATE_X) {                 \
					unmap_##ctname##_and_clwb(e);              \
				} else if (next_state == TABLE_STATE_Tv) {         \
					copy_##ename##_and_clwb(e, ref_e);         \
				} else {                                           \
					/* ASSERT(next_state == TABLE_STATE_Tn);*/ \
					BUG_ON(!ndckpt_is_virt_addr_in_nvdimm(     \
						e));                               \
					map_zeroed_nvdimm_page_##ctname(           \
						e, table_fixed_attr_##ename(       \
							   ref_e));                \
					traverse_##ename(addr, t, &e, &ct);        \
				}                                                  \
			} else if (prev_state == TABLE_STATE_Tv &&                 \
				   ct != ref_ct) {                                 \
				copy_##ename##_and_clwb(e, ref_e);                 \
			}                                                          \
			if (next_state == TABLE_STATE_Tn) {                        \
				nextfunc(mm, ct, ref_ct, addr,                     \
					 end < next_addr ? end : next_addr);       \
			}                                                          \
			addr = next_addr;                                          \
		}                                                                  \
	}

// sync_pages_pde
def_sync_pages(pde, pt, pmd_t, pte_t, sync_pages_pte);
// sync_pages_pdpte
def_sync_pages(pdpte, pd, pud_t, pmd_t, sync_pages_pde);
// sync_pages_pml4e
def_sync_pages(pml4e, pdpt, pgd_t, pud_t, sync_pages_pdpte);

static void sync_pages(struct mm_struct *mm, pgd_t *t4, pgd_t *ref_t4,
		       uint64_t start, uint64_t end)
{
	sync_pages_pml4e(mm, t4, ref_t4, start, end);
	ndckpt_sfence();
}

#ifdef NDCKPT_CHECK_SYNC_ON_COMMIT

static void check_failed(struct mm_struct *mm, pgd_t *t4, pgd_t *ref_t4,
			 uint64_t addr)
{
	struct vm_area_struct *vma = find_vma(mm, addr);
	pr_ndckpt("table:\n");
	pr_ndckpt_pgtable_range(t4, addr, addr + 1);
	pr_ndckpt("ref_table:\n");
	pr_ndckpt_pgtable_range(ref_t4, addr, addr + 1);
	if (vma)
		pr_ndckpt_mm_vma(vma);
	BUG();
}

static void check_page_is_synced(struct mm_struct *mm, pgd_t *t4, pgd_t *ref_t4,
				 uint64_t start, uint64_t end)
{
	// FOR DEBUG
	uint64_t addr;
	//
	pgd_t *ref_e4;
	pud_t *ref_t3 = NULL;
	pud_t *ref_e3;
	pmd_t *ref_t2 = NULL;
	pmd_t *ref_e2;
	pte_t *ref_t1 = NULL;
	pte_t *ref_e1;
	void *ref_page_vaddr;
	//
	pgd_t *e4;
	pud_t *t3 = NULL;
	pud_t *e3;
	pmd_t *t2 = NULL;
	pmd_t *e2;
	pte_t *t1 = NULL;
	pte_t *e1;
	void *page_vaddr;

	pr_ndckpt("SYNC CHECK BEGIN\n");

	for (addr = start; addr < end;) {
		traverse_pml4e(addr, ref_t4, &ref_e4, &ref_t3);
		traverse_pml4e(addr, t4, &e4, &t3);
		if (table_state_pml4e(e4) != table_state_pml4e(ref_e4)) {
			pr_ndckpt("state diff:\n");
			check_failed(mm, t4, ref_t4, addr);
		}
		if (table_state_pml4e(e4) == TABLE_STATE_X) {
			addr = next_pml4e_addr(addr);
			continue;
		}
		if (table_state_pml4e(e4) == TABLE_STATE_Tv && t3 != ref_t3) {
			pr_ndckpt("Tv mapping diff:\n");
			check_failed(mm, t4, ref_t4, addr);
		}
		if (table_fixed_attr_pml4e(e4) !=
		    table_fixed_attr_pml4e(ref_e4)) {
			pr_ndckpt(
				"PML4E attr diff: 0x%016llX but expected 0x%016llX\n",
				table_fixed_attr_pml4e(e4),
				table_fixed_attr_pml4e(ref_e4));
			check_failed(mm, t4, ref_t4, addr);
		}

		traverse_pdpte(addr, ref_t3, &ref_e3, &ref_t2);
		traverse_pdpte(addr, t3, &e3, &t2);
		if (table_state_pdpte(e3) != table_state_pdpte(ref_e3)) {
			check_failed(mm, t4, ref_t4, addr);
			pr_ndckpt("state diff:\n");
			check_failed(mm, t4, ref_t4, addr);
		}
		if (table_state_pdpte(e3) == TABLE_STATE_X) {
			addr = next_pdpte_addr(addr);
			continue;
		}
		if (table_state_pdpte(e3) == TABLE_STATE_Tv && t2 != ref_t2) {
			pr_ndckpt("Tv mapping diff:\n");
			check_failed(mm, t4, ref_t4, addr);
		}
		if (table_fixed_attr_pdpte(e3) !=
		    table_fixed_attr_pdpte(ref_e3)) {
			pr_ndckpt(
				"PDPTE attr diff: 0x%016llX but expected 0x%016llX\n",
				table_fixed_attr_pdpte(e3),
				table_fixed_attr_pdpte(ref_e3));
			check_failed(mm, t4, ref_t4, addr);
		}

		traverse_pde(addr, ref_t2, &ref_e2, &ref_t1);
		traverse_pde(addr, t2, &e2, &t1);
		if (table_state_pde(e2) != table_state_pde(ref_e2)) {
			pr_ndckpt("state diff:\n");
			check_failed(mm, t4, ref_t4, addr);
		}
		if (table_state_pde(e2) == TABLE_STATE_X) {
			addr = next_pde_addr(addr);
			continue;
		}
		if (table_state_pde(e2) == TABLE_STATE_Tv && t1 != ref_t1) {
			pr_ndckpt("Tv mapping diff:\n");
			check_failed(mm, t4, ref_t4, addr);
		}
		if (table_fixed_attr_pde(e2) != table_fixed_attr_pde(ref_e2)) {
			pr_ndckpt(
				"PDE attr diff: 0x%016llX but expected 0x%016llX\n",
				table_fixed_attr_pde(e2),
				table_fixed_attr_pde(ref_e2));
			check_failed(mm, t4, ref_t4, addr);
		}

		traverse_pte(addr, ref_t1, &ref_e1, &ref_page_vaddr);
		traverse_pte(addr, t1, &e1, &page_vaddr);

		if ((page_state_pte(e1) != page_state_pte(ref_e1)) &&
		    !(page_state_pte(ref_e1) == PAGE_STATE_Pnc &&
		      page_state_pte(e1) == PAGE_STATE_Pnd)) {
			// Latter case is ok because allocated page in sync must be dirty.
			pr_ndckpt("state diff: expected %d but %d\n",
				  page_state_pte(ref_e1), page_state_pte(e1));
			check_failed(mm, t4, ref_t4, addr);
		}
		if (page_state_pte(e1) == TABLE_STATE_X) {
			addr = next_pte_addr(addr);
			continue;
		}
		if (page_state_pte(e1) == PAGE_STATE_Pv &&
		    page_vaddr != ref_page_vaddr) {
			pr_ndckpt("Page mapping diff:\n");
			check_failed(mm, t4, ref_t4, addr);
		}
		if (page_fixed_attr_pte(e1) != page_fixed_attr_pte(ref_e1)) {
			pr_ndckpt(
				"Page attr diff: 0x%016llX but expected 0x%016llX\n",
				page_fixed_attr_pte(e1),
				page_fixed_attr_pte(ref_e1));
			check_failed(mm, t4, ref_t4, addr);
		}
		if (IS_PAGE_STATE_ON_NVDIMM(page_state_pte(e1)) &&
		    memcmp(page_vaddr, ref_page_vaddr, PAGE_SIZE) != 0) {
			pr_ndckpt("Page on NVDIMM data diff:\n");
			check_failed(mm, t4, ref_t4, addr);
		}
		addr = next_pte_addr(addr);
	}
	pr_ndckpt("SYNC CHECK END\n");
}
#endif

void mark_target_vmas(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	pr_ndckpt("mm->brk = 0x%016llX\n", (uint64_t)mm->brk);
	pr_ndckpt("mm->start_brk = 0x%016llX\n", (uint64_t)mm->start_brk);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		vma->vm_ckpt_flags = 0;
		if ((vma->vm_flags & VM_WRITE) == 0) {
			// No need to save readonly vma.
			continue;
		}
		if (vma->vm_file) {
			// .data
			//vma->vm_ckpt_flags |= VM_CKPT_TARGET;
			continue;
		}
		if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
			// heap
			//vma->vm_ckpt_flags |= VM_CKPT_TARGET;
			continue;
		}
		if (vma->vm_start <= mm->start_stack &&
		    mm->start_stack <= vma->vm_end) {
			// stack
			//vma->vm_ckpt_flags |= VM_CKPT_TARGET;
			continue;
		}
		// anonymous
		vma->vm_ckpt_flags |= VM_CKPT_TARGET;
	}
	pr_ndckpt("vma marked as follows: \n");
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		pr_ndckpt_mm_vma(vma);
	}
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

	mark_target_vmas(mm);
	pproc_save_vmas(pproc, prev_running_ctx_idx, mm);

	pproc_set_regs(pproc, prev_running_ctx_idx, target);
	flush_target_vmas(mm);
	// TODO: Save vmas here
	pr_ndckpt_ckpt("Ctx #%d has been committed\n", prev_running_ctx_idx);
	// At this point, running ctx has become clean so both context is valid.
	pproc_set_valid_ctx(pproc, prev_running_ctx_idx);
	// prepare next running context
	pr_ndckpt_ckpt("Sync Ctx #%d -> Ctx #%d\n", prev_running_ctx_idx,
		       next_running_ctx_idx);
	sync_pages(mm, pproc->ctx[next_running_ctx_idx].pgd,
		   pproc->ctx[prev_running_ctx_idx].pgd, 0, 1ULL << 47);
#ifdef NDCKPT_CHECK_SYNC_ON_COMMIT
	check_page_is_synced(mm, pproc->ctx[next_running_ctx_idx].pgd,
			     pproc->ctx[prev_running_ctx_idx].pgd, 0,
			     1ULL << 47);
#endif
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

static void replace_pages_with_nvdimm(pgd_t *t4, uint64_t start, uint64_t end,
				      bool exclude_leaf_page)
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
#ifdef DEBUG_REPLACE_PAGES_WITH_NVDIMM
	pr_ndckpt("[0x%016llX, 0x%016llX) of pgd@0x%016llx\n", start, end,
		  (uint64_t)t4);
#endif
	for (addr = start; addr < end;) {
		traverse_pml4e(addr, t4, &e4, &t3);
		if (!t3) {
			addr = next_pml4e_addr(addr);
			continue;
		}
		if (!ndckpt_is_virt_addr_in_nvdimm(t3)) {
			replace_pdpt_with_nvdimm_page(e4);
			ndckpt_invlpg((void *)addr);
			continue;
		}
		traverse_pdpte(addr, t3, &e3, &t2);
		if (!t2) {
			addr = next_pdpte_addr(addr);
			continue;
		}
		if (!ndckpt_is_virt_addr_in_nvdimm(t2)) {
			replace_pd_with_nvdimm_page(e3);
			ndckpt_invlpg((void *)addr);
			continue;
		}
		traverse_pde(addr, t2, &e2, &t1);
		if (!t1) {
			addr = next_pde_addr(addr);
			continue;
		}
		if (!ndckpt_is_virt_addr_in_nvdimm(t1)) {
			replace_pt_with_nvdimm_page(e2);
			ndckpt_invlpg((void *)addr);
			continue;
		}
		traverse_pte(addr, t1, &e1, &page_vaddr);
		if (!page_vaddr) {
			addr = next_pte_addr(addr);
			continue;
		}
		if (!exclude_leaf_page &&
		    !ndckpt_is_virt_addr_in_nvdimm(page_vaddr)) {
			replace_page_with_nvdimm_page(e1);
			ndckpt_invlpg((void *)addr);
		}
		addr = next_pte_addr(addr);
	}
	ndckpt_sfence();
}

static void fix_dram_part_of_ctx(struct mm_struct *mm,
				 struct PersistentProcessInfo *pproc, int idx)
{
	// This funcion fixes dram mappings of ctx to match with given mm.
	// mm should be an original pgd on DRAM.
	BUG_ON(ndckpt_is_virt_addr_in_nvdimm(mm->pgd));
	copy_pml4_kernel_map(pproc->ctx[idx].pgd, mm->pgd);
	sync_normal_vmas(mm, pproc->ctx[idx].pgd, mm->pgd);
}

static void fix_pmem_part_of_ctx(struct mm_struct *mm,
				 struct PersistentProcessInfo *pproc, int idx)
{
	struct vm_area_struct *vma;
	// Replace page structures in lower half with nvdimm page
	// This does not replaces leaf page
	replace_pages_with_nvdimm(pproc->ctx[idx].pgd, 0, 1ULL << 47, true);
	// Replace leaf pages in target vma
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) == 0) {
			continue;
		}
		replace_pages_with_nvdimm(pproc->ctx[idx].pgd, vma->vm_start,
					  vma->vm_end, false);
	}
}

int64_t pproc_init(struct task_struct *target,
		   struct PersistentMemoryManager *pman, struct mm_struct *mm,
		   struct pt_regs *regs)
{
	pgd_t *pgd_ctx0;
	pgd_t *pgd_ctx1;
	struct PersistentProcessInfo *pproc = pproc_alloc(pman);

	BUG_ON(!pproc);
	pr_ndckpt("pproc pobj #%lld\n", pobj_get_header(pproc)->id);

	// ctx 0 (This ctx will be valid first)
	pgd_ctx0 = ndckpt_alloc_zeroed_virt_page();
	pproc_set_pgd(pproc, 0, pgd_ctx0);
	// ctx 1 (dummy)
	pgd_ctx1 = ndckpt_alloc_zeroed_virt_page();
	pproc_set_pgd(pproc, 1, pgd_ctx1);

	// Setup non-volatile part of ctx0
	memcpy(pgd_ctx0, mm->pgd, PAGE_SIZE);
	ndckpt_clwb_range(pgd_ctx0, PAGE_SIZE);
	memcpy(pgd_ctx1, mm->pgd, PAGE_SIZE);
	ndckpt_clwb_range(pgd_ctx1, PAGE_SIZE);

	mark_target_vmas(mm);
	pproc_save_vmas(pproc, 0, mm);
	pproc_set_regs(pproc, 0, target);
	pproc_set_valid_ctx(pproc, 0); // dummy

	return pproc_restore(pman, target, pproc);
}

//#define DEBUG_PPROC_RESTORE
#ifdef DEBUG_PPROC_RESTORE
static void print_target_vma_mapping(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) == 0) {
			continue;
		}
		pr_ndckpt_vma(vma);
		pr_ndckpt_pgtable_range(mm->pgd, vma->vm_start, vma->vm_end);
	}
}
#endif

int64_t pproc_restore(struct PersistentMemoryManager *pman,
		      struct task_struct *target,
		      struct PersistentProcessInfo *pproc)
{
	struct pt_regs *regs = task_pt_regs(target);
	struct mm_struct *mm = target->mm;
	const int valid_ctx_idx = pproc->valid_ctx_idx;

	spin_lock_init(&pproc->ckpt_lock);

	BUG_ON(valid_ctx_idx < 0 || 2 <= valid_ctx_idx);
#ifdef DEBUG_PPROC_RESTORE
	pr_ndckpt_restore("restore from obj id = %016llX\n", target->ndckpt_id);
	pproc_printk(pproc);
	pr_ndckpt_restore("  valid_ctx_idx: %d\n", valid_ctx_idx);
	pproc_print_regs(pproc, valid_ctx_idx);
#endif

	// Save original mm->pgd to pproc
	// This is only valid while the power is on, so there is no need to flush.
	pproc->org_pgd = mm->pgd;
	mark_target_vmas(mm);

	fix_pmem_part_of_ctx(mm, pproc, 0);
	fix_pmem_part_of_ctx(mm, pproc, 1);
	fix_dram_part_of_ctx(mm, pproc, 0);
	fix_dram_part_of_ctx(mm, pproc, 1);
	// TODO: Restore vmas here

	pman_set_last_proc_info(pman, NULL);
	// THIS IS FAKE: we set ctx[1] as valid to commit ctx[0]
	pproc_set_valid_ctx(pproc, 1 - valid_ctx_idx);
	mm->pgd = pproc->ctx[valid_ctx_idx].pgd;
	pproc_restore_regs(target, pproc, valid_ctx_idx);
	pproc_restore_vmas(mm, pproc, valid_ctx_idx);
	pproc_commit(target, pproc, target->mm, regs);

	// At this point, ctx[0] is commited and marked as valid,
	// and ctx[1] is synced with ctx[0] and ready to go
	pman_set_last_proc_info(pman, pproc);

#ifdef DEBUG_PPROC_RESTORE
	pr_ndckpt_pml4(mm->pgd);
	pr_ndckpt_pml4(pproc->ctx[0].pgd);
	pr_ndckpt_pml4(pproc->ctx[1].pgd);
	print_target_vma_mapping(mm);
#endif
	// Sanity check...
	BUG_ON(verify_pml4_kernel_map(pproc->ctx[0].pgd, mm->pgd));
	BUG_ON(verify_pml4_kernel_map(pproc->ctx[1].pgd, mm->pgd));
	return regs->ax;
}
