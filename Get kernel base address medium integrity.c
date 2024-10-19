#include <windows.h>
#include <stdint.h>
#include <Psapi.h>



// Method 1
PVOID get_kernel_base_1()
{
	LPVOID drivers[1024];
	DWORD cbNeeded;
	EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
	return drivers[0];
}


// Method 2
uint64_t get_kernel_base_2(){

    #define MAX_DRIVERS 1024
    #define BUFFER_SIZE 1024

	HMODULE base[MAX_DRIVERS];
    DWORD cbNeeded;
    BOOL success;
    char driverName[BUFFER_SIZE];
    int i;

    success = EnumDeviceDrivers((LPVOID *)base, sizeof(base), &cbNeeded);

    if (!success) {
        printf("- EnumDeviceDrivers() function call failed!\n");
        exit(-1);
    }

    for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        if (base[i] == NULL) {
            continue;
        }

        memset(driverName, 0, sizeof(driverName));

        DWORD result = GetDeviceDriverBaseNameA(
            base[i],             
            driverName,           
            sizeof(driverName)   
        );

        if (result == 0) {

            printf("- GetDeviceDriverBaseNameA() function call failed!\n");
            exit(-1);
        }

        if (strstr(strlwr(driverName), "ntoskrnl") != NULL) {
            
            return (uint64_t)base[i];
            break;
        }
    }
}


