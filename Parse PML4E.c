// https://github.com/ommadawn46/HEVD-Exploit-Win10-22H2-KVAS/blob/main/util/parse_pml4e.py

#include <windows.h>
#include <stdint.h>
#include <stdio.h>



#define BIT_DESC_COUNT 7

typedef struct {
    int bit;
    const char *description;
} BitDescription;

const BitDescription bit_descriptions[BIT_DESC_COUNT] = {
    {0, "Present"},
    {1, "Read/Write"},
    {2, "User/Supervisor"},
    {3, "Page-Level Write-Through"},
    {4, "Page-Level Cache Disable"},
    {5, "Accessed"},
    {63, "Execute Disable"}
};

VOID parse_pml4e(unsigned long long pml4e) {
    // Print PML4E in binary
    printf("\n\t* PML4E: ");
    for (int i = 63; i >= 0; i--) {
        printf("%llu", (pml4e >> i) & 1);
        if (i % 8 == 0) printf(" "); // Optional: add space for readability
    }
    printf("\n");

    // Print bit descriptions
    for (int i = 0; i < BIT_DESC_COUNT; i++) {
        int bit = bit_descriptions[i].bit;
        const char *desc = bit_descriptions[i].description;
        const char *status = (pml4e >> bit) & 1 ? "Set" : "Not Set";
        printf("\t* Bit %2d: %-30s - %s\n", bit, desc, status);
    }

    // Print Physical Frame Number (PFN)
    unsigned long long pfn = (pml4e >> 12) & 0xFFFFFFFFFF;
    printf("\t* Physical Frame Number (PFN): %#llx\n", pfn);
}

int main(){
    uintptr_t value;

    parse_pml4e(value);
}