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

void pproc_printk(struct PersistentProcessInfo *pproc)
{
	if (!pproc_is_valid(pproc)) {
		printk("invalid last_proc_info\n");
		return;
	}
	printk("PersistentProcessInfo at pobj #%lld:\n",
	       pobj_get_header(pproc)->id);
	ndckpt_print_pml4(pproc->ctx[0].pgd);
}
