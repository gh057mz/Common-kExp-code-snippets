#include <windows.h>


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


int main(){

    HINSTANCE hNtDLL = LoadLibraryA("ntdll.dll");

    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)(GetProcAddress(hNtDLL, "NtQuerySystemInformation"));


}