#ifndef __NDCKPT_H__
#define __NDCKPT_H__

#include <asm/pgalloc.h>

// struct vm_area_struct -> vm_ckpt_flags
#define VM_CKPT_TARGET 0x0001

struct pmem_device;

void ndckpt_notify_pmem(struct pmem_device *pmem);
int ndckpt_enable_checkpointing(struct task_struct *task, int restore_obj_id);
uint64_t ndckpt_alloc_phys_page(void);
void *ndckpt_alloc_zeroed_page(void);
uint64_t ndckpt_virt_to_phys(void *vaddr);
void *ndckpt_phys_to_virt(uint64_t paddr);
int ndckpt_is_phys_addr_in_nvdimm(uint64_t paddr);
int ndckpt_is_virt_addr_in_nvdimm(void *vaddr);
int ndckpt_handle_checkpoint(void);
void ndckpt_handle_execve(struct task_struct *task);

static inline int ndckpt_is_enabled_on_current(void)
{
	return current->flags & PF_NDCKPT_ENABLED &&
	       (current->flags & PF_FORKNOEXEC) == 0;
}

static inline pud_t *ndckpt_pud_offset(p4d_t *p4d, unsigned long address)
{
	uint64_t paddr = p4d_val(*p4d) & p4d_pfn_mask(*p4d);
	if (!ndckpt_is_phys_addr_in_nvdimm(paddr))
		return (pud_t *)p4d_page_vaddr(*p4d) + pud_index(address);
	return (pud_t *)ndckpt_phys_to_virt(paddr) + pud_index(address);
}

static inline pmd_t *ndckpt_pmd_offset(pud_t *e, unsigned long address)
{
	uint64_t paddr = pud_val(*e) & PTE_PFN_MASK;
	if (!ndckpt_is_phys_addr_in_nvdimm(paddr))
		return (pmd_t *)pud_page_vaddr(*e) + pmd_index(address);
	return (pmd_t *)ndckpt_phys_to_virt(paddr) + pmd_index(address);
}

static inline unsigned long ndckpt_pgd_page_vaddr(pgd_t pgd)
{
	// https://elixir.bootlin.com/linux/v5.1.3/source/arch/x86/include/asm/pgtable.h#L934
	uint64_t paddr = pgd_val(pgd) & PTE_PFN_MASK;
	if (!ndckpt_is_phys_addr_in_nvdimm(paddr))
		return (unsigned long)__va(paddr);
	return (unsigned long long)ndckpt_phys_to_virt(paddr);
}
static inline unsigned long ndckpt_pud_page_vaddr(pud_t pud)
{
	// https://elixir.bootlin.com/linux/v5.1.3/source/arch/x86/include/asm/pgtable.h#L934
	uint64_t paddr = pud_val(pud) & PTE_PFN_MASK;
	if (!ndckpt_is_phys_addr_in_nvdimm(paddr))
		return (unsigned long)__va(paddr);
	return (unsigned long long)ndckpt_phys_to_virt(paddr);
}
static inline unsigned long ndckpt_pmd_page_vaddr(pmd_t pmd)
{
	// https://elixir.bootlin.com/linux/v5.1.3/source/arch/x86/include/asm/pgtable.h#L934
	uint64_t paddr = pmd_val(pmd) & PTE_PFN_MASK;
	if (!ndckpt_is_phys_addr_in_nvdimm(paddr))
		return (unsigned long)__va(paddr);
	return (unsigned long long)ndckpt_phys_to_virt(paddr);
}

static inline unsigned long ndckpt_p4d_to_pdpt_paddr(p4d_t e)
{
	return p4d_val(e) & PTE_PFN_MASK;
}

static inline int ndckpt_is_p4d_points_nvdimm_page(p4d_t e)
{
	return ndckpt_is_phys_addr_in_nvdimm(ndckpt_p4d_to_pdpt_paddr(e));
}

static inline unsigned long ndckpt_pud_to_pdpt_paddr(pud_t e)
{
	return pud_val(e) & PTE_PFN_MASK;
}

static inline int ndckpt_is_pud_points_nvdimm_page(pud_t e)
{
	return ndckpt_is_phys_addr_in_nvdimm(ndckpt_pud_to_pdpt_paddr(e));
}

static inline unsigned long ndckpt_pmd_to_pdpt_paddr(pmd_t e)
{
	return pmd_val(e) & PTE_PFN_MASK;
}

static inline int ndckpt_is_pmd_points_nvdimm_page(pmd_t e)
{
	return ndckpt_is_phys_addr_in_nvdimm(ndckpt_pmd_to_pdpt_paddr(e));
}

int ndckpt___pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address);

static inline pud_t *ndckpt_pud_alloc(struct mm_struct *mm, p4d_t *p4d,
				      unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) &&
		ndckpt___pud_alloc(mm, p4d, address)) ?
		       NULL :
		       ndckpt_pud_offset(p4d, address);
}

int ndckpt___pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address);

static inline pmd_t *ndckpt_pmd_alloc(struct mm_struct *mm, pud_t *pud,
				      unsigned long address)
{
	// Alloc page for pud if not existed, and return addr to entry for the address
	return (unlikely(pud_none(*pud)) &&
		ndckpt___pmd_alloc(mm, pud, address)) ?
		       NULL :
		       ndckpt_pmd_offset(pud, address);
}

static inline void ndckpt_pmd_populate(struct mm_struct *mm, pmd_t *pmd,
				       pte_t *pte)
{
	unsigned long pfn =
		(ndckpt_is_virt_addr_in_nvdimm(pte) ? ndckpt_virt_to_phys(pte) :
						      __pa(pte)) >>
		PAGE_SHIFT;

	paravirt_alloc_pte(mm, pfn);
	set_pmd(pmd, __pmd(((pteval_t)pfn << PAGE_SHIFT) | _PAGE_TABLE));
}

static inline pte_t *ndckpt_pte_offset_kernel(pmd_t *pmd, unsigned long address)
{
	return (pte_t *)ndckpt_pmd_page_vaddr(*pmd) + pte_index(address);
}

void ndckpt__pte_alloc(struct vm_fault *vmf);

#endif /* __NDCKPT_H__ */
