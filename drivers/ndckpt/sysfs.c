#include "ndckpt_internal.h"

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

static void TestMem(int *array)
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

static ssize_t info_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	struct PersistentMemoryManager *pman = first_pmem_device->virt_addr;
	pman_print_last_proc_info(pman);
	return 0;
}
static ssize_t info_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	return count;
}
static struct kobj_attribute info_attribute =
	__ATTR(info, 0660, info_show, info_store);

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

int sysfs_interface_init(void)
{
	int error;
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
	if ((error = add_sysfs_kobj("info", &info_attribute)))
		return error;
	return 0;
}
