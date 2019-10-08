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

static struct pmem_device *first_pmem_device;
static struct kobject *example_kobject;

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
	for (stride = 1; stride <= kRangeMax / 2; stride = stride * 2) {
		result_array[0][x] = stride;
		x++;
	}

	//ClearIntFlag();
	set_cache_disable_bit();
	y = 0;
	for (csize = kRangeMin; csize <= kRangeMax; csize = csize * 2) {
		y++;
		x = 0;
		result_array[y][x++] = csize * sizeof(int);
		for (stride = 1; stride <= csize / 2; stride = stride * 2) {
      printk("ndckpt: csize = %lld, stride = %lld\n", csize, stride);
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

static ssize_t foo_show(struct kobject *kobj, struct kobj_attribute *attr,
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

static ssize_t foo_store(struct kobject *kobj, struct kobj_attribute *attr,
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
	return count;
}

static struct kobj_attribute foo_attribute =
	__ATTR(cmd, 0660, foo_show, foo_store);

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

static int __init ndckpt_module_init(void)
{
	int error = 0;
	printk("ndckpt: module init\n");
	example_kobject = kobject_create_and_add("ndckpt", kernel_kobj);
	if (!example_kobject) {
		printk("ndckpt: kobject_create_and_add failed.\n");
		return -ENOMEM;
	}
	error = sysfs_create_file(example_kobject, &foo_attribute.attr);
	if (error) {
		pr_debug("failed to create the ndckpt node\n");
	}
	return 0;
}
static void __exit ndckpt_module_cleanup(void)
{
	printk("ndckpt: module cleanup\n");
	kobject_put(example_kobject);
	return;
}

module_init(ndckpt_module_init);
module_exit(ndckpt_module_cleanup);
MODULE_LICENSE("GPL");
