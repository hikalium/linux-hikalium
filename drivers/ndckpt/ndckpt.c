#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/timekeeping.h>

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
	volatile uint64_t signature;
	volatile uint64_t id;
	volatile uint64_t num_of_pages;
	struct PersistentObjectHeader *volatile next;
};

#define PMAN_SIGNATURE 0x4D50534F6D75696CULL
struct PersistentMemoryManager {
	volatile uint64_t page_idx; // in virtual addr
	volatile uint64_t num_of_pages;
	struct PersistentObjectHeader *volatile head;
	struct PersistentObjectHeader sentinel;
	volatile uint64_t signature;
};

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
	return (uint8_t *)pobj + sizeof(*pobj);
}

void pobj_printk(struct PersistentObjectHeader *pobj)
{
	printk("Object #%lld is %s\n", pobj->id,
	       pobj_is_valid(pobj) ? "valid" : "INVALID");
	printk("  base(virtual) 0x%016llX\n", (uint64_t)pobj_get_base(pobj));
	printk("  num_of_pages  %16lld\n", pobj->num_of_pages);
}

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

static struct pmem_device *first_pmem_device;
static struct kobject *kobj_ndckpt;

#define kRangeExpMin 10
#define kRangeExpMax 24
#define kDurationTick (2 * 1000 * 1000)
#define kRangeMin (1ULL << kRangeExpMin)
#define kRangeMax (1ULL << kRangeExpMax)

#define kResultArraySize (kRangeExpMax - kRangeExpMin + 2)
static uint64_t result_array[kResultArraySize][kResultArraySize];

static void set_cache_disable_bit(void)
{
	uint32_t cr0 = read_cr0();
	cr0 |= (1UL << 30);
	write_cr0(cr0);
	printk("ndckpt: cache disable\n");
}
static void clear_cache_disable_bit(void)
{
	uint32_t cr0 = read_cr0();
	cr0 &= ~(1UL << 30);
	write_cr0(cr0);
	printk("ndckpt: cache enable\n");
}

void TestMem(int *array)
{
	uint64_t nextstep, i, index;
	uint64_t csize, stride;
	uint64_t steps, tsteps;
	uint64_t t0, t1, tick_sum_overall, tick_sum_loop_only;
	int x, y;
	/*
	uint64_t array_size_in_pages =
		(sizeof(int) * kRangeMax + kPageSize - 1) >> kPageSizeExponent;
    */
	uint64_t tick_sum_of_mem_read;
	uint64_t tick_per_mem_read;

	for (y = 0; y < kResultArraySize; y++) {
		for (x = 0; x < kResultArraySize; x++) {
			result_array[y][x] = 0;
		}
	}

	y = 0;
	x = 1;
	result_array[0][0] = 0;
	for (x = 1; x < kResultArraySize; x++) {
		result_array[0][x] = x * sizeof(int);
	}

	//ClearIntFlag();
	set_cache_disable_bit();
	y = 0;
	for (csize = kRangeMin; csize <= kRangeMax; csize = csize * 2) {
		y++;
		x = 0;
		result_array[y][x++] = csize * sizeof(int);
		for (stride = 1; stride <= csize / 2; stride = stride * 2) {
			printk("ndckpt: csize = %lld, stride = %lld\n", csize,
			       stride);
			for (index = 0; index < csize; index = index + stride) {
				array[index] = (int)(index + stride);
			}
			array[index - stride] = 0;

			// measure time spent on (reading data from memory) + (loop, instrs,
			// etc...)
			steps = 0;
			nextstep = 0;
			t0 = ktime_get_ns();
			do {
				for (i = stride; i != 0; i = i - 1) {
					nextstep = 0;
					do
						nextstep = array[nextstep];
					while (nextstep != 0);
				}
				steps = steps + 1;
				t1 = ktime_get_ns();
			} while ((t1 - t0) < kDurationTick); // originary 20.0
			tick_sum_overall = t1 - t0;

			// measure time spent on (loop, instrs, etc...) only
			tsteps = 0;
			t0 = ktime_get_ns();
			do {
				for (i = stride; i != 0; i = i - 1) {
					index = 0;
					do
						index = index + stride;
					while (index < csize);
				}
				tsteps = tsteps + 1;
				t1 = ktime_get_ns();
			} while (tsteps < steps);
			tick_sum_loop_only = t1 - t0;

			// avoid negative value
			if (tick_sum_loop_only >= tick_sum_overall) {
				tick_sum_loop_only = tick_sum_overall;
			}

			tick_sum_of_mem_read =
				tick_sum_overall - tick_sum_loop_only;
			tick_per_mem_read =
				tick_sum_of_mem_read / (steps * csize);
			result_array[y][x++] =
				tick_per_mem_read > 0 ? tick_per_mem_read : 1;
		};
	};
	clear_cache_disable_bit();
	//StoreIntFlag();
}

static ssize_t cmd_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	ssize_t count_sum = 0;
	ssize_t count;
	int x, y;
	//pr_debug("ndckpt: read\n");
	for (y = 0; y < kResultArraySize; y++) {
		for (x = 0; x < kResultArraySize; x++) {
			count = sprintf(buf, "%lld,", result_array[y][x]);
			buf += count;
			count_sum += count;
		}
		count = sprintf(buf, "\n");
		buf += count;
		count_sum += count;
	}
	//count = sprintf(buf, "0x%08lx\n", read_cr0());
	return count_sum;
}
static ssize_t cmd_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	printk("ndckpt: write\n");
	if (strcmp(buf, "cache disable\n") == 0) {
		set_cache_disable_bit();
	}
	if (strcmp(buf, "cache enable\n") == 0) {
		clear_cache_disable_bit();
	}
	if (strcmp(buf, "memtest\n") == 0) {
		TestMem(first_pmem_device->virt_addr);
	}
	if (strcmp(buf, "init\n") == 0) {
		TestMem(first_pmem_device->virt_addr);
	}
	return count;
}
static struct kobj_attribute cmd_attribute =
	__ATTR(cmd, 0660, cmd_show, cmd_store);

static ssize_t objs_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	int count;
	count = sprintf(buf, "objs_show\n");
	return count;
}
static ssize_t objs_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	pman_printk(pman);
	return count;
}
static struct kobj_attribute objs_attribute =
	__ATTR(objs, 0660, objs_show, objs_store);

static ssize_t init_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	int count;
	if (pman_is_valid(pman)) {
		count = sprintf(buf, "pman is valid\n");
	} else {
		count = sprintf(buf, "pman is INVALID\n");
	}
	return count;
}
static ssize_t init_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	printk("ndckpt: init_store\n");
	pman_init(first_pmem_device);
	return count;
}
static struct kobj_attribute init_attribute =
	__ATTR(init, 0660, init_show, init_store);

static ssize_t alloc_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	return 0;
}
static ssize_t alloc_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	int pages;
	void *vaddr;
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	sscanf(buf, "%d", &pages);
	printk("ndckpt: alloc_store size=%d\n", pages);
	vaddr = pman_alloc_pages(pman, pages);
	printk("ndckpt: alloc_store vaddr=0x%08llX\n", (uint64_t)vaddr);
	return count;
}
static struct kobj_attribute alloc_attribute =
	__ATTR(alloc, 0660, alloc_show, alloc_store);

static ssize_t pid_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return 0;
}
static ssize_t pid_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	int pid;
	struct pid *p;
	struct task_struct *t;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	sscanf(buf, "%d", &pid);
	printk("ndckpt: pid_store pid=%d\n", pid);
	p = find_get_pid(pid);
	if (!p) {
		printk("ndckpt: pid not found\n");
		return count;
	}
	t = pid_task(p, PIDTYPE_PID);
	if (!t) {
		printk("ndckpt: task_struct not found\n");
		return count;
	}
	printk("ndckpt: task_struct found. pid = %d\n", t->pid);
	mm = t->mm;
	vma = mm->mmap;
	while (vma) {
		printk("ndckpt: vm_area_struct@0x%016llX\n", (uint64_t)vma);
		printk("ndckpt:   vm_start = 0x%016llX\n",
		       (uint64_t)vma->vm_start);
		printk("ndckpt:   vm_end   = 0x%016llX\n",
		       (uint64_t)vma->vm_end);
		printk("ndckpt:   vm_next   = 0x%016llX\n",
		       (uint64_t)vma->vm_next);
		printk("ndckpt:   vm_prev   = 0x%016llX\n",
		       (uint64_t)vma->vm_prev);
		printk("ndckpt:   vm_flags   = 0x%016llX\n",
		       (uint64_t)vma->vm_flags);
		vma = vma->vm_next;
	}
	return count;
}
static struct kobj_attribute pid_attribute =
	__ATTR(pid, 0660, pid_show, pid_store);

void ndckpt_notify_pmem(struct pmem_device *pmem)
{
	if (!first_pmem_device) {
		printk("ndckpt: first pmem notified\n");
		first_pmem_device = pmem;
		printk("ndckpt: phys_addr: 0x%016llx\n", pmem->phys_addr);
		printk("ndckpt: size     : 0x%08lx\n", pmem->size);
		printk("ndckpt: virt_addr: 0x%016llx\n",
		       (unsigned long long)pmem->virt_addr);
	}
}
EXPORT_SYMBOL(ndckpt_notify_pmem);

int ndckpt_enable_checkpointing(struct task_struct *task, int restore_obj_id)
{
	if ((task->flags & PF_FORKNOEXEC) == 0) {
		// ndckpt can be enabled only before exec after fork.
		return -EINVAL;
	}
  task->flags |= PF_NDCKPT_ENABLED;
	printk("ndckpt: checkpoint enabled on pid=%d\n", task->pid);
	printk("ndckpt:   task flags = 0x%08X\n", task->flags);
	return 0;
}
EXPORT_SYMBOL(ndckpt_enable_checkpointing);

void ndckpt_handle_execve(struct task_struct *task)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	printk("ndckpt: ndckpt_handle_execve: pid = %d\n", task->pid);
	mm = task->mm;
	vma = mm->mmap;
	while (vma) {
		printk("ndckpt: vm_area_struct@0x%016llX\n", (uint64_t)vma);
		printk("ndckpt:   vm_start = 0x%016llX\n",
		       (uint64_t)vma->vm_start);
		printk("ndckpt:   vm_end   = 0x%016llX\n",
		       (uint64_t)vma->vm_end);
		printk("ndckpt:   vm_next   = 0x%016llX\n",
		       (uint64_t)vma->vm_next);
		printk("ndckpt:   vm_prev   = 0x%016llX\n",
		       (uint64_t)vma->vm_prev);
		printk("ndckpt:   vm_flags   = 0x%016llX\n",
		       (uint64_t)vma->vm_flags);
		vma = vma->vm_next;
	}
}
EXPORT_SYMBOL(ndckpt_handle_execve);

static int add_sysfs_kobj(const char *name, struct kobj_attribute *attr)
{
	int error = 0;
	error = sysfs_create_file(kobj_ndckpt, &attr->attr);
	if (error) {
		printk("ndckpt: failed to create /sys/kernel/ndckpt/%s\n",
		       name);
		return -1;
	}
	return 0;
}

static int __init ndckpt_module_init(void)
{
	int error = 0;
	printk("ndckpt: module init\n");
	kobj_ndckpt = kobject_create_and_add("ndckpt", kernel_kobj);
	if (!kobj_ndckpt) {
		printk("ndckpt: kobject_create_and_add failed.\n");
		return -ENOMEM;
	}
	if ((error = add_sysfs_kobj("cmd", &cmd_attribute)))
		return error;
	if ((error = add_sysfs_kobj("objs", &objs_attribute)))
		return error;
	if ((error = add_sysfs_kobj("init", &init_attribute)))
		return error;
	if ((error = add_sysfs_kobj("alloc", &alloc_attribute)))
		return error;
	if ((error = add_sysfs_kobj("pid", &pid_attribute)))
		return error;

	return 0;
}
static void __exit ndckpt_module_cleanup(void)
{
	printk("ndckpt: module cleanup\n");
	kobject_put(kobj_ndckpt);
	return;
}

module_init(ndckpt_module_init);
module_exit(ndckpt_module_cleanup);
MODULE_LICENSE("GPL");
