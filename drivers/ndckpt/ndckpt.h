#ifndef __NDCKPT_H__
#define __NDCKPT_H__

struct pmem_device;

void ndckpt_notify_pmem(struct pmem_device *pmem);
int ndckpt_enable_checkpointing(struct task_struct *task, int restore_obj_id);
uint64_t ndckpt_alloc_phys_page(void);
uint64_t ndckpt_virt_to_phys(void *vaddr);
void *ndckpt_phys_to_virt(uint64_t paddr);

#endif /* __NDCKPT_H__ */
