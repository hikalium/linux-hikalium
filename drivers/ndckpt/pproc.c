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
			addr = next_pml4e_addr(addr);
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
			addr = next_pdpte_addr(addr);
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
			addr = next_pde_addr(addr);
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
			addr = next_pte_addr(addr);
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
		addr = next_pte_addr(addr);
	}
	ndckpt_sfence();
}

//#define DEBUG_SYNC_DRAM_PAGES
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
			printk("flush_dirty_pages: addr 0x%016llx pgd@0x%016llx\n",
			       addr, (uint64_t)t4);
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

static inline void sync_pages_pte(struct mm_struct *mm,
				  struct vm_area_struct *vma, pte_t *t,
				  pte_t *ref_t, uint64_t addr, uint64_t end)
{
	while (addr < end) {
		pte_t *e, *ref_e;
		void *page_vaddr, *ref_page_vaddr;
		uint8_t prev_state, next_state;

		traverse_pte(addr, ref_t, &ref_e, &ref_page_vaddr);
		traverse_pte(addr, t, &e, &page_vaddr);
		addr = next_pte_addr(addr);
		prev_state = page_state_pte(e);
		next_state = page_state_pte(ref_e);

		if (prev_state == next_state && next_state != PAGE_STATE_Pnd) {
			// (X, X) -> Not mapped
			// (Pv, Pv) -> Shared. No need to sync
			// (Pnc, Pnc) -> Clean. No need to sync
		} else if (next_state == PAGE_STATE_X) {
			unmap_page_and_clwb(e);
		} else if (next_state == PAGE_STATE_Pv) {
			unmap_page_and_clwb(e);
			copy_pte_and_clwb(e, ref_e);
		} else {
			if (prev_state == PAGE_STATE_X ||
			    prev_state == PAGE_STATE_Pv) {
				map_zeroed_nvdimm_page_page(e);
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

#define def_sync_pages(ename, ctname, ttype, cttype, nextfunc)                     \
	static inline void sync_pages_##ename(struct mm_struct *mm,                \
					      struct vm_area_struct *vma,          \
					      ttype *t, ttype *ref_t,              \
					      uint64_t addr, uint64_t end)         \
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
                                                                                   \
			if (prev_state ^ next_state) {                             \
				if (next_state == TABLE_STATE_X) {                 \
					unmap_##ctname##_and_clwb(e);              \
				} else if (next_state == TABLE_STATE_Tv) {         \
					copy_##ename##_and_clwb(e, ref_e);         \
				} else {                                           \
					/* ASSERT(next_state == TABLE_STATE_Tn);*/ \
					map_zeroed_nvdimm_page_##ctname(e);        \
					traverse_##ename(addr, t, &e, &ct);        \
				}                                                  \
			}                                                          \
			if (next_state == TABLE_STATE_Tn) {                        \
				nextfunc(mm, vma, ct, ref_ct, addr,                \
					 end < next_addr ? end : next_addr);       \
			}                                                          \
			addr = next_addr;                                          \
		}                                                                  \
	}

def_sync_pages(pde, pt, pmd_t, pte_t, sync_pages_pte);
def_sync_pages(pdpte, pd, pud_t, pmd_t, sync_pages_pde);
def_sync_pages(pml4e, pdpt, pgd_t, pud_t, sync_pages_pdpte);

static void sync_pages(struct mm_struct *mm, struct vm_area_struct *vma,
		       pgd_t *t4, pgd_t *ref_t4, uint64_t start, uint64_t end)
{
	sync_pages_pml4e(mm, vma, t4, ref_t4, start, end);
	ndckpt_sfence();
}

static void sync_vmas(struct mm_struct *mm, pgd_t *dst_pgd, pgd_t *src_pgd)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_ckpt_flags & VM_CKPT_TARGET) != 0) {
			continue;
		}
		sync_pages(mm, vma, dst_pgd, src_pgd, vma->vm_start,
			   vma->vm_end);
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

	pproc_set_regs(pproc, prev_running_ctx_idx, regs);
	flush_target_vmas(mm);
	pproc_set_vma_range(pproc, mm, prev_running_ctx_idx);
	pr_ndckpt_ckpt("Ctx #%d has been committed\n", prev_running_ctx_idx);
	// At this point, running ctx has become clean so both context is valid.
	pproc_set_valid_ctx(pproc, prev_running_ctx_idx);
	// prepare next running context
	pr_ndckpt_ckpt("Sync Ctx #%d -> Ctx #%d\n", prev_running_ctx_idx,
		       next_running_ctx_idx);
	sync_vmas(mm, pproc->ctx[next_running_ctx_idx].pgd,
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
	uint64_t addr;
	pgd_t *e4;
	pud_t *t3 = NULL;
	pud_t *e3;
	pmd_t *t2 = NULL;
	pmd_t *e2;
	pte_t *t1 = NULL;
	pte_t *e1;
	void *page_vaddr;
	pr_ndckpt("[0x%016llX, 0x%016llX) of pgd@0x%016llx\n", start, end,
		  (uint64_t)t4);
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
		printk("checking addr=%016llx\n", addr);
		if (!ndckpt_is_virt_addr_in_nvdimm(page_vaddr)) {
			printk("replaced! addr=%016llx\n", addr);
			replace_page_with_nvdimm_page(e1);
			ndckpt_invlpg((void *)addr);
		}
		addr = next_pte_addr(addr);
	}
	ndckpt_sfence();
	pr_ndckpt_flush("SFENCE() done\n");
	pr_ndckpt_pgtable_range(t4, start, end);
}

static void
replace_stack_pages_with_nvdimm(struct PersistentMemoryManager *pman,
				pgd_t *pgd, struct vm_area_struct *vma)
{
	pr_ndckpt("Replacing vma [0x%016lX - 0x%016lX) with NVDIMM...\n",
		  vma->vm_start, vma->vm_end);
	replace_pages_with_nvdimm(pgd, vma->vm_start, vma->vm_end);
}

static void mark_target_vmas(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	pr_ndckpt("mm->brk = 0x%016llX\n", (uint64_t)mm->brk);
	pr_ndckpt("mm->start_brk = 0x%016llX\n", (uint64_t)mm->start_brk);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		pr_ndckpt("vma@0x%016llX [0x%016llX - 0x%016llX] 0x%016llX\n",
			  (uint64_t)vma, (uint64_t)vma->vm_start,
			  (uint64_t)vma->vm_end, (uint64_t)vma->vm_flags);
		vma->vm_ckpt_flags = 0;
		if ((vma->vm_flags & VM_WRITE) == 0) {
			// No need to save readonly vma.
			pr_ndckpt("  This vma is readonly. skip.\n");
			continue;
		}
		if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
			pr_ndckpt("  This is heap vma.\n");
			//vma->vm_ckpt_flags |= VM_CKPT_TARGET;
			continue;
		}
		if (vma->vm_start <= mm->start_stack &&
		    mm->start_stack <= vma->vm_end) {
			pr_ndckpt("  This is stack vma.\n");
			//vma->vm_ckpt_flags |= VM_CKPT_TARGET;
			continue;
		}
		pr_ndckpt("  This is UNKNOWN vma but writable.\n");
		pr_ndckpt_pgtable_range(mm->pgd, vma->vm_start, vma->vm_end);
	}
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

static void fix_pmem_part_of_ctx(struct PersistentMemoryManager *pman,
				 struct mm_struct *mm,
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

int64_t pproc_init(struct task_struct *target,
		   struct PersistentMemoryManager *pman, struct mm_struct *mm,
		   struct pt_regs *regs)
{
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
	fix_dram_part_of_ctx(mm, pproc, 0);
	fix_dram_part_of_ctx(mm, pproc, 1);
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
	print_target_vma_mapping(mm);
	BUG_ON(verify_pml4_kernel_map(pproc->ctx[0].pgd, mm->pgd));
	BUG_ON(verify_pml4_kernel_map(pproc->ctx[1].pgd, mm->pgd));
	return regs->ax;
}
