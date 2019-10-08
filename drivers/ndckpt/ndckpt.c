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
static int foo;

static ssize_t foo_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
  pr_debug("ndckpt: read\n");
	return sprintf(buf, "%llu\n", ktime_get_ns());
}

static ssize_t foo_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
  pr_debug("ndckpt: write\n");
	sscanf(buf, "%du", &foo);
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
