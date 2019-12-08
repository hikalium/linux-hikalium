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
	pr_ndckpt("      PT   @ 0x%016llX on %s\n", (uint64_t)pte,
		  get_str_dram_or_nvdimm(pte));
	if (!ndckpt_is_virt_addr_in_nvdimm(pte))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pte_t); i++) {
		e = pte[i].pte;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		pr_ndckpt("      PAGE[0x%03X] = 0x%016llX on %s %s\n", i, e,
			  get_str_dram_or_nvdimm_phys(e & PTE_PFN_MASK),
			  (e & _PAGE_DIRTY) ? "DIRTY" : "clean");
	}
}

static void ndckpt_print_pd(pmd_t *pmd)
{
	int i;
	uint64_t e;
	pr_ndckpt("    PD   @ 0x%016llX on %s\n", (uint64_t)pmd,
		  get_str_dram_or_nvdimm(pmd));
	if (!ndckpt_is_virt_addr_in_nvdimm(pmd))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pmd_t); i++) {
		e = pmd[i].pmd;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		pr_ndckpt("    PD  [0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pt((pte_t *)ndckpt_pmd_page_vaddr(pmd[i]));
	}
}

static void ndckpt_print_pdpt(pud_t *pud)
{
	int i;
	uint64_t e;
	pr_ndckpt("  PDPT @ 0x%016llX on %s\n", (uint64_t)pud,
		  get_str_dram_or_nvdimm(pud));
	if (!ndckpt_is_virt_addr_in_nvdimm(pud))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pud_t); i++) {
		e = pud[i].pud;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		pr_ndckpt("  PDPT[0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pd((pmd_t *)ndckpt_pud_page_vaddr(pud[i]));
	}
}

void ndckpt_print_pml4(pgd_t *pgd)
{
	int i;
	uint64_t e;
	pr_ndckpt("PML4 @ 0x%016llX on %s\n", (uint64_t)pgd,
		  get_str_dram_or_nvdimm(pgd));
	if (!ndckpt_is_virt_addr_in_nvdimm(pgd))
		return;
	for (i = 0; i < PAGE_SIZE / sizeof(pgd_t); i++) {
		e = (uint64_t)pgd[i].pgd;
		if ((e & _PAGE_PRESENT) == 0)
			continue;
		pr_ndckpt("PML4[0x%03X] = 0x%016llX\n", i, e);
		ndckpt_print_pdpt((pud_t *)ndckpt_pgd_page_vaddr(pgd[i]));
	}
}

void erase_mappings_to_dram(pgd_t *t4, uint64_t start, uint64_t end)
{
	uint64_t addr;
	pgd_t *e4;
	pud_t *t3 = NULL;
	pud_t *e3;
	pmd_t *t2 = NULL;
	pmd_t *e2;
	pte_t *t1 = NULL;
	pte_t *e1;
	uint64_t page_paddr;
	int i1 = -1, i2 = -1, i3 = -1, i4 = -1;
	pr_ndckpt("erase_mappings_to_dram: [0x%016llX, 0x%016llX)\n", start,
		  end);
	for (addr = start; addr < end;) {
		if (i4 != PADDR_TO_IDX_IN_PML4(addr)) {
			i4 = PADDR_TO_IDX_IN_PML4(addr);
			e4 = &t4[i4];
			if ((e4->pgd & _PAGE_PRESENT) == 0) {
				addr += PGDIR_SIZE;
				continue;
			}
			t3 = (void *)ndckpt_pgd_page_vaddr(*e4);
		}
		if (i3 != PADDR_TO_IDX_IN_PDPT(addr)) {
			i3 = PADDR_TO_IDX_IN_PDPT(addr);
			e3 = &t3[i3];
			if ((e3->pud & _PAGE_PRESENT) == 0) {
				addr += PUD_SIZE;
				continue;
			}
			t2 = (void *)ndckpt_pud_page_vaddr(*e3);
		}
		if (i2 != PADDR_TO_IDX_IN_PD(addr)) {
			i2 = PADDR_TO_IDX_IN_PD(addr);
			e2 = &t2[i2];
			if ((e2->pmd & _PAGE_PRESENT) == 0) {
				addr += PMD_SIZE;
				continue;
			}
			t1 = (void *)ndckpt_pmd_page_vaddr(*e2);
			if (!ndckpt_is_virt_addr_in_nvdimm(t1)) {
				e2->pmd = 0;
				ndckpt_invlpg((void *)addr);
				addr += PMD_SIZE;
				continue;
			}
		}
		i1 = PADDR_TO_IDX_IN_PT(addr);
		e1 = &t1[i1];
		if ((e1->pte & _PAGE_PRESENT) == 0) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = e1->pte & PTE_PFN_MASK;
		if (!ndckpt_is_phys_addr_in_nvdimm(page_paddr)) {
			pr_ndckpt(
				"clear mapping to DRAM page @ 0x%016llX v->p 0x%016llX\n",
				addr, page_paddr);
			e1->pte = 0;
			ndckpt_invlpg((void *)addr);
		}
		addr += PAGE_SIZE;
	}
	ndckpt_sfence();
	pr_ndckpt("SFENCE() done\n");
}

void pr_ndckpt_pgtable_range(pgd_t *t4, uint64_t start, uint64_t end)
{
	uint64_t addr;
	pgd_t *e4;
	pud_t *t3 = NULL;
	pud_t *e3;
	pmd_t *t2 = NULL;
	pmd_t *e2;
	pte_t *t1 = NULL;
	pte_t *e1;
	uint64_t page_paddr;
	int i1 = -1, i2 = -1, i3 = -1, i4 = -1;
	for (addr = start; addr < end;) {
		if (i4 != PADDR_TO_IDX_IN_PML4(addr)) {
			i4 = PADDR_TO_IDX_IN_PML4(addr);
			pr_ndckpt("PML4[0x%03X]\n", i4);
			e4 = &t4[i4];
			if ((e4->pgd & _PAGE_PRESENT) == 0) {
				addr += PGDIR_SIZE;
				continue;
			}
			t3 = (void *)ndckpt_pgd_page_vaddr(*e4);
		}
		if (i3 != PADDR_TO_IDX_IN_PDPT(addr)) {
			i3 = PADDR_TO_IDX_IN_PDPT(addr);
			pr_ndckpt(" PDPT[0x%03X]\n", i3);
			e3 = &t3[i3];
			if ((e3->pud & _PAGE_PRESENT) == 0) {
				addr += PUD_SIZE;
				continue;
			}
			t2 = (void *)ndckpt_pud_page_vaddr(*e3);
		}
		if (i2 != PADDR_TO_IDX_IN_PD(addr)) {
			i2 = PADDR_TO_IDX_IN_PD(addr);
			pr_ndckpt("  PD  [0x%03X]\n", i2);
			e2 = &t2[i2];
			if ((e2->pmd & _PAGE_PRESENT) == 0) {
				addr += PMD_SIZE;
				continue;
			}
			t1 = (void *)ndckpt_pmd_page_vaddr(*e2);
		}
		i1 = PADDR_TO_IDX_IN_PT(addr);
		pr_ndckpt("   PT  [0x%03X]\n", i1);
		e1 = &t1[i1];
		if ((e1->pte & _PAGE_PRESENT) == 0) {
			addr += PAGE_SIZE;
			continue;
		}
		page_paddr = e1->pte & PTE_PFN_MASK;
		pr_ndckpt("    PAGE @ 0x%016llX v->p 0x%016llX on %s\n", addr,
			  page_paddr, get_str_dram_or_nvdimm_phys(page_paddr));
		addr += PAGE_SIZE;
	}
}
