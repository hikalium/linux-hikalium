#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>

#include "../nvdimm/pmem.h"

#include "ndckpt.h"

static const uint64_t kCacheLineSize = 64;
static const uint64_t kPageSizeExponent = 12;

static inline void ndckpt_clwb(volatile void *__p)
{
	asm volatile("clwb %0" : "+m"(*(volatile char __force *)__p));
}

static inline void ndckpt_clwb_range(volatile void *p, size_t byte_size)
{
	const uint64_t end_addr = (uint64_t)p + byte_size;
	const size_t num_of_lines =
		((end_addr - ((uint64_t)p & ~(kCacheLineSize - 1))) +
		 kCacheLineSize - 1) /
		kCacheLineSize;
	size_t i;
	for (i = 0; i < num_of_lines; i++) {
		ndckpt_clwb(p);
		p = (volatile uint8_t *)p + kCacheLineSize;
	}
}

static inline void ndckpt_sfence(void)
{
	asm volatile("sfence");
}

#define POBJ_SIGNATURE 0x4F50534F6D75696CULL
struct PersistentObjectHeader {
	// This struct is placed at the end of the page,
	// just before the allocated pages.
	volatile uint64_t signature;
	volatile uint64_t id;
	volatile uint64_t num_of_pages;
	struct PersistentObjectHeader *volatile next;
};

#define PPROC_SIGNATURE 0x5050534f6d75696cULL
struct PersistentProcessInfo {
	struct PersistentExecutionContext {
		pgd_t *volatile pgd;
	} ctx[2];
	volatile uint64_t signature;
};

#define PMAN_SIGNATURE 0x4D50534F6D75696CULL
struct PersistentMemoryManager {
	volatile uint64_t page_idx; // in virtual addr
	volatile uint64_t num_of_pages;
	struct PersistentObjectHeader *volatile head;
	struct PersistentProcessInfo *volatile last_proc_info;
	struct PersistentObjectHeader sentinel;
	// 2nd cache line begins here
	volatile uint64_t signature;
};

// @ndckpt.c
extern struct kobject *kobj_ndckpt;
extern struct pmem_device *first_pmem_device;

bool pproc_is_valid(struct PersistentProcessInfo *pproc);
struct PersistentProcessInfo *pproc_alloc(void);
void pproc_set_pgd(struct PersistentProcessInfo *pproc, int ctx_idx,
		   pgd_t *pgd);

// @pman.c
bool pman_is_valid(struct PersistentMemoryManager *pman);
void pman_update_head(struct PersistentMemoryManager *pman,
		      struct PersistentObjectHeader *pobj);
void pman_set_last_proc_info(struct PersistentMemoryManager *pman,
			     struct PersistentProcessInfo *pproc);
void pman_init(struct pmem_device *pmem);
void *pman_alloc_pages(struct PersistentMemoryManager *pman,
		       uint64_t num_of_pages_requested);
void pman_printk(struct PersistentMemoryManager *pman);
void pman_print_last_proc_info(struct PersistentMemoryManager *pman);

// @pobj.c
bool pobj_is_valid(struct PersistentObjectHeader *pobj);
void pobj_init(struct PersistentObjectHeader *pobj, uint64_t id,
	       uint64_t num_of_pages, struct PersistentObjectHeader *next);
void *pobj_get_base(struct PersistentObjectHeader *pobj);
struct PersistentObjectHeader *pobj_get_header(void *addr);
void pobj_printk(struct PersistentObjectHeader *pobj);

// @sysfs.c
int sysfs_interface_init(void);
