#include "ndckpt_internal.h"

bool pobj_is_valid(struct PersistentObjectHeader *pobj)
{
	return pobj && pobj->signature == POBJ_SIGNATURE;
}

void pobj_init(struct PersistentObjectHeader *pobj, uint64_t id,
	       uint64_t num_of_pages, struct PersistentObjectHeader *next)
{
	// First, invalidate pobj
	pobj->signature = ~POBJ_SIGNATURE;
	ndckpt_clwb(&pobj->signature);
	ndckpt_sfence();
	// Initialize metadata and flush
	pobj->id = id;
	pobj->num_of_pages = num_of_pages;
	pobj->next = next;
	ndckpt_clwb_range(pobj, sizeof(*pobj));
	ndckpt_sfence();
	// Mark as valid and flush
	pobj->signature = POBJ_SIGNATURE;
	ndckpt_clwb(&pobj->signature);
	ndckpt_sfence();
}

void *pobj_get_base(struct PersistentObjectHeader *pobj)
{
	return (uint8_t *)pobj + sizeof(struct PersistentObjectHeader);
}

struct PersistentObjectHeader *pobj_get_header(void *addr)
{
	return (struct PersistentObjectHeader
			*)((uint8_t *)addr -
			   sizeof(struct PersistentObjectHeader));
}

void pobj_printk(struct PersistentObjectHeader *pobj)
{
	printk("Object #%lld is %s\n", pobj->id,
	       pobj_is_valid(pobj) ? "valid" : "INVALID");
	printk("  base(virtual) 0x%016llX\n", (uint64_t)pobj_get_base(pobj));
	printk("  num_of_pages  %16lld\n", pobj->num_of_pages);
}
