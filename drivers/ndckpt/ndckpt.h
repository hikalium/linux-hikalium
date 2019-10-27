#ifndef __NDCKPT_H__
#define __NDCKPT_H__

void ndckpt_notify_pmem(struct pmem_device *pmem);
int ndckpt_enable_checkpointing(struct task_struct *task, int restore_obj_id);

#endif /* __NDCKPT_H__ */
