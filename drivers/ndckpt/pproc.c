#include "ndckpt_internal.h"

bool pproc_is_valid(struct PersistentProcessInfo *pproc)
{
	return pproc && pproc->signature == PPROC_SIGNATURE;
}

struct PersistentProcessInfo *pproc_alloc(void)
{
	struct PersistentProcessInfo *pproc = ndckpt_alloc_zeroed_page();
	pproc->ctx[0].pgd = NULL;
	pproc->ctx[1].pgd = NULL;
	pproc->signature = PPROC_SIGNATURE;
	ndckpt_clwb(&pproc->signature);
	ndckpt_sfence();
	return pproc;
}

void pproc_set_pgd(struct PersistentProcessInfo *pproc, int ctx_idx, pgd_t *pgd)
{
	BUG_ON(ctx_idx < 0 || 2 <= ctx_idx);
	pproc->ctx[ctx_idx].pgd = pgd;
	ndckpt_clwb(&pproc->ctx[ctx_idx].pgd);
	ndckpt_sfence();
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
	if (!pproc_is_valid(pproc)) {
		printk("invalid last_proc_info\n");
		return;
	}
	printk("PersistentProcessInfo at pobj #%lld:\n",
	       pobj_get_header(pproc)->id);
	ndckpt_print_pml4(pproc->ctx[0].pgd);
	pproc_print_regs(pproc, 0);
}
