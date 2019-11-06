#ifndef __NDCKPT_H__
#define __NDCKPT_H__

// struct vm_area_struct -> vm_ckpt_flags
#define VM_CKPT_TARGET  0x0001

struct pmem_device;

void ndckpt_notify_pmem(struct pmem_device *pmem);
int ndckpt_enable_checkpointing(struct task_struct *task, int restore_obj_id);
uint64_t ndckpt_alloc_phys_page(void);
uint64_t ndckpt_virt_to_phys(void *vaddr);
void *ndckpt_phys_to_virt(uint64_t paddr);
int ndckpt_handle_checkpoint(void);
void ndckpt_handle_execve(struct task_struct *task);

#endif /* __NDCKPT_H__ */
