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
	merge_pgd_with_pmem(task->mm, pproc->ctx[valid_ctx_idx].pgd);
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
			pr_ndckpt_pgtable_range(mm->pgd, vma->vm_start,
						vma->vm_end);
			erase_mappings_to_dram(mm->pgd, vma->vm_start,
					       vma->vm_end);
		}
		vma = vma->vm_next;
	}
}
