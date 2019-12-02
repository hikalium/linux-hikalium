#include "ndckpt_internal.h"

bool pman_is_valid(struct PersistentMemoryManager *pman)
{
	return pman && pman->signature == PMAN_SIGNATURE;
}

void pman_update_head(struct PersistentMemoryManager *pman,
		      struct PersistentObjectHeader *pobj)
{
	pman->head = pobj;
	ndckpt_clwb(&pman->head);
	ndckpt_sfence();
}

void pman_set_last_proc_info(struct PersistentMemoryManager *pman,
			     struct PersistentProcessInfo *pproc)
{
	pman->last_proc_info = pproc;
	ndckpt_clwb(&pman->last_proc_info);
	ndckpt_sfence();
}

void pman_init(struct pmem_device *pmem)
{
	struct PersistentMemoryManager *pman = pmem->virt_addr;
	// First, invalidate pman
	pman->signature = ~PMAN_SIGNATURE;
	ndckpt_clwb(&pman->signature);
	ndckpt_sfence();
	// Initialize metadata and flush
	pman->page_idx = (uint64_t)pmem->virt_addr >> kPageSizeExponent;
	pman->num_of_pages = pmem->size >> kPageSizeExponent;
	pman->head = NULL;
	pman->last_proc_info = NULL;
	ndckpt_clwb_range(pman, sizeof(*pman));
	ndckpt_sfence();

	// Set sentinel as head.
	// Head is always the last element in the pmem region and we can calcurate
	// a start address of the next free region by using head
	pobj_init(&pman->sentinel, 0, 0, NULL);
	pman_update_head(pman, &pman->sentinel);

	// Mark as valid and flush
	pman->signature = PMAN_SIGNATURE;
	ndckpt_clwb(&pman->signature);
	ndckpt_sfence();
	printk("ndckpt: pman init done\n");
}

void *pman_alloc_pages(struct PersistentMemoryManager *pman,
		       uint64_t num_of_pages_requested)
{
	struct PersistentObjectHeader *new_obj;
	struct PersistentObjectHeader *const head = pman->head;
	const uint64_t next_page_idx =
		((uint64_t)pobj_get_base(head) >> kPageSizeExponent) +
		head->num_of_pages;
	if (num_of_pages_requested > pman->num_of_pages ||
	    num_of_pages_requested + 1 + next_page_idx >=
		    pman->page_idx + pman->num_of_pages) {
		printk("ndckpt: !!!!!!!!!! No more pages\n");
		return NULL;
	}
	new_obj = (struct PersistentObjectHeader *)(((next_page_idx + 1)
						     << kPageSizeExponent) -
						    sizeof(*new_obj));
	pobj_init(new_obj, head->id + 1, num_of_pages_requested, head);
	pman_update_head(pman, new_obj);
	return pobj_get_base(new_obj);
}

void pman_printk(struct PersistentMemoryManager *pman)
{
	struct PersistentObjectHeader *pobj;
	printk("PMAN at 0x%016llX\n", (uint64_t)pman);
	if (!pman_is_valid(pman)) {
		printk("  INVALID\n");
		return;
	}
	printk("  region size in byte: %lld\n",
	       pman->num_of_pages << kPageSizeExponent);
	for (pobj = pman->head; pobj; pobj = pobj->next) {
		pobj_printk(pobj);
	}
}

void pman_print_last_proc_info(struct PersistentMemoryManager *pman)
{
	if (!pman_is_valid(pman)) {
		printk("invalid pman\n");
		return;
	}
	printk("pman is valid\n");
	if (!pproc_is_valid(pman->last_proc_info)) {
		printk("invalid last_proc_info\n");
		return;
	}
	printk("last_proc_info at pobj #%lld:\n",
	       pobj_get_header(pman->last_proc_info)->id);
}
