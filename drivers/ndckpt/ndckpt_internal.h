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

extern struct kobject *kobj_ndckpt;
extern struct pmem_device *first_pmem_device;

int sysfs_interface_init(void);

bool pman_is_valid(struct PersistentMemoryManager *pman);
void pman_printk(struct PersistentMemoryManager *pman);
void *pman_alloc_pages(struct PersistentMemoryManager *pman,
		       uint64_t num_of_pages_requested);
void pman_init(struct pmem_device *pmem);
void pman_print_last_proc_info(struct PersistentMemoryManager *pman);
