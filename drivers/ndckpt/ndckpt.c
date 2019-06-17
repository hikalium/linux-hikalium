#include <linux/kernel.h>
#include <linux/module.h>

static int __init ndckpt_module_init(void)
{
  printk ("ndckpt module init\n");
  return 0;
}
static void __exit ndckpt_module_cleanup(void)
{

  printk("!!hello ndckpt module cleanup\n");
  return;
}

module_init(ndckpt_module_init);
module_exit(ndckpt_module_cleanup);
MODULE_LICENSE("GPL");
