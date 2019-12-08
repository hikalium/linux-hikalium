#include "ndckpt_internal.h"
/*
  Intel / Linux
  PML4: pgd_t[512];
        p4d_t <- Only used when 5level paging is used.
  PDPT: pud_t[512];
  PD  : pmd_t[512];
  PT  : pte_t[512];
*/

static void ndckpt_print_pt(pte_t *pte)
{
	int i;
	uint64_t e;
	printk("ndckpt:       PT   @ 0x%016llX on %s\n", (uint64_t)pte,
	       get_str_dram_or_nvdimm(pte));
	if (!ndckpt_is_virt_addr_in_nvdimm(pte))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pte_t); i++) {
		e = pte[i].pte;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt:       PAGE[0x%03X] = 0x%016llX on %s %s\n", i,
		       e, get_str_dram_or_nvdimm_phys(e & PTE_PFN_MASK),
		       (e & _PAGE_DIRTY) ? "DIRTY" : "clean");
	}
}

static void ndckpt_print_pd(pmd_t *pmd)
{
	int i;
	uint64_t e;
	printk("ndckpt:     PD   @ 0x%016llX on %s\n", (uint64_t)pmd,
	       get_str_dram_or_nvdimm(pmd));
	if (!ndckpt_is_virt_addr_in_nvdimm(pmd))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pmd_t); i++) {
		e = pmd[i].pmd;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt:     PD  [0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pt((pte_t *)ndckpt_pmd_page_vaddr(pmd[i]));
	}
}

static void ndckpt_print_pdpt(pud_t *pud)
{
	int i;
	uint64_t e;
	printk("ndckpt:   PDPT @ 0x%016llX on %s\n", (uint64_t)pud,
	       get_str_dram_or_nvdimm(pud));
	if (!ndckpt_is_virt_addr_in_nvdimm(pud))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pud_t); i++) {
		e = pud[i].pud;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt:   PDPT[0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pd((pmd_t *)ndckpt_pud_page_vaddr(pud[i]));
	}
}

void ndckpt_print_pml4(pgd_t *pgd)
{
	int i;
	uint64_t e;
	printk("ndckpt: PML4 @ 0x%016llX on %s\n", (uint64_t)pgd,
	       get_str_dram_or_nvdimm(pgd));
	if (!ndckpt_is_virt_addr_in_nvdimm(pgd))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pgd_t); i++) {
		e = (uint64_t)pgd[i].pgd;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		printk("ndckpt: PML4[0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pdpt((pud_t *)ndckpt_pgd_page_vaddr(pgd[i]));
	}
}
