// https://github.com/processhacker/phnt
#define PHNT_VERSION PHNT_THRESHOLD // Windows 10

#include <phnt_windows.h>
#include <phnt.h>
/*
* pdbexe is another neat util to get undoc structure
* pdbex _PEB ntdll.pdb -m -j
* pdbex _RTL_USER_PROCESS_PARAMETERS ntdll.pdb -m -j
* https://github.com/wbenny/pdbex
*/

#include <stdio.h>
#include <intrin.h>

// https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
// pointer	FS:[0x18]	GS:[0x30] Linear address of TEB
// pointer	FS:[0x30]   GS:[0x60] Process Environment Block(PEB)

int main(void) {

    // Allows access to undoc fields of PEB unlike the ones mentioned in the link
    // https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
    PEB _peb = {0};

#if _M_IX86
    DWORD peb_x86;
    DWORD teb_x86;

    _asm {
        //int 3
        mov eax, fs:[0x30] // PEB
        mov peb_x86, eax
        mov eax, fs:[0x18] // TEB
        mov teb_x86, eax
    }
    printf("[+]peb_x86 : 0x%x\n", peb_x86);
    printf("[+]teb_x86 : 0x%x\n", teb_x86);

    // using compiler intrinsic
    DWORD dwPeb = __readfsdword(0x30);
    printf("[+]peb_x86 : 0x%x\n", dwPeb);

    DWORD dwTeb = __readfsdword(0x18);
    printf("[+]teb_x86 : 0x%x\n", dwTeb);

    _peb = *(PEB*)dwPeb;
    printf("[*]Image base address: %p\n", _peb.ImageBaseAddress);
    printf("[+]Image name: %ls\n", _peb.ProcessParameters->ImagePathName.Buffer);

#elif _M_AMD64
    // using compiler intrinsic
    DWORD64 dwPeb = __readgsqword(0x60);
    printf("[+]peb_x64 : 0x%llx\n", dwPeb);

    DWORD64 dwTeb = __readgsqword(0x30);
    printf("[+]teb_x64: 0x%llx\n", dwTeb);

    _peb = *(PEB*)dwPeb;
    printf("[*]Image base address: %p\n", _peb.ImageBaseAddress);
    printf("[+]Image name: %ls\n", _peb.ProcessParameters->ImagePathName.Buffer);
#endif

    return 0;
}

