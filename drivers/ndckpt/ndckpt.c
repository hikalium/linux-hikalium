#include <linux/kernel.h>
#include <linux/module.h>

#include "../nvdimm/pmem.h"
#include "ndckpt.h"
static struct pmem_device *first_pmem_device;

void ndckpt_notify_pmem(struct pmem_device *pmem) {
  if(!first_pmem_device) {
    printk("ndckpt: first pmem notified\n");
    first_pmem_device = pmem;
    printk("ndckpt: phys_addr: 0x%016llx\n", pmem->phys_addr);
    printk("ndckpt: size     : 0x%08lx\n", pmem->size);
    printk("ndckpt: virt_addr: 0x%016llx\n", (unsigned long long)pmem->virt_addr);
  }
}
EXPORT_SYMBOL(ndckpt_notify_pmem);

static int __init ndckpt_module_init(void)
{
  printk ("ndckpt: module init\n");
  return 0;
}
static void __exit ndckpt_module_cleanup(void)
{
  printk("ndckpt: module cleanup\n");
  return;
}

module_init(ndckpt_module_init);
module_exit(ndckpt_module_cleanup);
MODULE_LICENSE("GPL");
