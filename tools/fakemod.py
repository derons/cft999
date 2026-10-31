import struct
from unicorn import UcError
MODBASE=0x20000000
MODSIZE=0x10000
STUBBASE=0x70000000
NAMES = sorted(set("""
LdrGetProcedureAddress LdrLoadDll LdrUnloadDll LdrGetDllHandle LdrFindEntryForAddress
NtAllocateVirtualMemory NtClose NtCreateFile NtCreateSection NtCreateThreadEx NtDeviceIoControlFile
NtDuplicateObject NtFreeVirtualMemory NtFsControlFile NtMapViewOfSection NtOpenFile NtOpenProcess
NtOpenThread NtProtectVirtualMemory NtQueryInformationProcess NtQueryInformationThread NtQueryObject
NtQuerySystemInformation NtQueryVirtualMemory NtReadFile NtReadVirtualMemory NtResumeThread
NtSetContextThread NtSetInformationProcess NtSetInformationThread NtSuspendThread NtTerminateProcess
NtTerminateThread NtUnmapViewOfSection NtWaitForSingleObject NtWriteFile NtWriteVirtualMemory
RtlAddFunctionTable RtlAddVectoredExceptionHandler RtlCaptureContext RtlDeleteFunctionTable
RtlExitUserProcess RtlImageNtHeader RtlInitializeCriticalSection RtlLookupFunctionEntry
RtlRemoveVectoredExceptionHandler RtlVirtualUnwind RtlUnwindEx RtlEnterCriticalSection
RtlLeaveCriticalSection RtlDeleteCriticalSection RtlAllocateHeap RtlFreeHeap RtlNtStatusToDosError
ZwClose ZwQueryInformationProcess ZwQuerySystemInformation ZwProtectVirtualMemory
VirtualAlloc VirtualFree VirtualProtect VirtualQuery VirtualAllocEx VirtualProtectEx
LoadLibraryA LoadLibraryW LoadLibraryExA LoadLibraryExW GetProcAddress GetModuleHandleA
GetModuleHandleW GetModuleHandleExA GetModuleFileNameA GetModuleFileNameW GetCurrentProcess
GetCurrentThread GetCurrentProcessId GetCurrentThreadId FlushInstructionCache Sleep SleepEx
ExitProcess ExitThread TerminateProcess TerminateThread CreateThread CreateRemoteThread
ResumeThread SuspendThread SetThreadContext GetThreadContext GetSystemInfo GetNativeSystemInfo
IsDebuggerPresent CheckRemoteDebuggerPresent OutputDebugStringA OutputDebugStringW GetTickCount
GetTickCount64 QueryPerformanceCounter QueryPerformanceFrequency CloseHandle CreateFileA
CreateFileW ReadFile WriteFile GetLastError SetLastError LocalAlloc LocalFree HeapAlloc HeapFree
GetProcessHeap SetUnhandledExceptionFilter UnhandledExceptionFilter RaiseException
AddVectoredExceptionHandler RemoveVectoredExceptionHandler SetConsoleCtrlHandler
GetStartupInfoA GetStartupInfoW GetCommandLineA GetCommandLineW GetEnvironmentStringsW
FreeEnvironmentStringsW GetStdHandle WriteConsoleW WideCharToMultiByte MultiByteToWideChar
GetVersionExW GetVersion RtlGetVersion ProcessPrng BCryptGenRandom SystemFunction036
""".split()))
def build(uc):
    img=bytearray(MODSIZE)
    img[0:2]=b'MZ'
    struct.pack_into('<I', img, 0x3c, 0x40)
    img[0x40:0x44]=b'PE\x00\x00'
    struct.pack_into('<HHIIIHH', img, 0x44, 0x8664,1,0,0,0,0xF0,0x22)
    opt=0x58
    struct.pack_into('<H', img, opt, 0x20b)
    struct.pack_into('<Q', img, opt+24, MODBASE)
    struct.pack_into('<I', img, opt+32, 0x1000)
    struct.pack_into('<I', img, opt+36, 0x200)
    struct.pack_into('<I', img, opt+56, MODSIZE)
    struct.pack_into('<I', img, opt+60, 0x200)
    struct.pack_into('<I', img, opt+108, 16)
    EXP=0x600; F_A=0x800; N_A=0x1000; O_A=0x2000; S_A=0x3000; NAME_RVA=0x3020
    N=len(NAMES)
    struct.pack_into('<II', img, opt+112, EXP, 40+12*N)
    sh=0x58+0xF0
    img[sh:sh+8]=b'.text\x00\x00\x00'
    struct.pack_into('<IIIIIIHHI', img, sh+8, 0x8000,0x1000,0x8000,0x200,0,0,0,0,0x60000020)
    img[S_A:S_A+9]=b'ntdll.dll'
    struct.pack_into('<IIHHIIIIIII', img, EXP, 0,S_A,1,N,N,F_A,N_A,O_A,0,0,0)
    offs=[]; cur=NAME_RVA
    for n in NAMES:
        b=n.encode()+b'\x00'; img[cur:cur+len(b)]=b; offs.append(cur); cur+=len(b)
    for i in range(N):
        struct.pack_into('<I', img, F_A+4*i, 0x4000+i*0x10)
        struct.pack_into('<I', img, N_A+4*i, offs[i])
        struct.pack_into('<H', img, O_A+2*i, i)
    uc.mem_map(MODBASE, MODSIZE); uc.mem_write(MODBASE, bytes(img))
    try: uc.mem_map(STUBBASE, 0x100000)
    except UcError: pass
    for i in range(N): uc.mem_write(STUBBASE+i*0x10, b'\xc3')
    return {MODBASE+0x4000+i*0x10:n for i,n in enumerate(NAMES)}, {MODBASE+o:n for n,o in zip(NAMES,offs)}, NAMES
