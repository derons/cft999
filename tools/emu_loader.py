import os
import sys, struct, collections, pefile
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from unicorn import *
from unicorn.x86_const import *
import fakemod
IMGBASE=0x140000000
pe=pefile.PE('cybercup.exe'); d=open('cybercup.exe','rb').read()
blob=d[0xb3c00:0xb3c00+0xed5a00]
SIZE=0x2700000
uc=Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(IMGBASE,SIZE); uc.mem_map(0,SIZE)
uc.mem_map(0x60000000,0x400000)   # stack
uc.mem_map(0x85000000,0x4000000)  # heap
uc.reg_write(UC_X86_REG_RSP,0x60300000)
uc.mem_write(IMGBASE,d[:0x400]); uc.mem_write(0,d[:0x400])
for s in pe.sections:
    if s.SizeOfRawData:
        data=d[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        uc.mem_write(IMGBASE+s.VirtualAddress,data); uc.mem_write(s.VirtualAddress,data)
STUBBASE=0x70000000
uc.mem_map(STUBBASE,0x100000)
fns, name_by_addr, NAMES = fakemod.build(uc)
print('fake module names',len(NAMES))
imports=[]
for i in range(461):
    o=732160+i*8
    v=struct.unpack('<Q',d[o:o+8])[0]
    if v==0: continue
    nm='?'
    if 0x1725000<=v<0x25fa93c:
        bo=v-0x1725000; nm=blob[bo+2:bo+2+64].split(b'\x00')[0].decode('latin1')
    imports.append((0x1724000+i*8,nm))
iat_stub={}
for k,(rva,nm) in enumerate(imports):
    addr=STUBBASE+0x80000+k*0x10
    uc.mem_write(addr,b'\xc3'); iat_stub[addr]=nm
    uc.mem_write(IMGBASE+rva,struct.pack('<Q',addr)); uc.mem_write(rva,struct.pack('<Q',addr))
heap=[0x85010000]
def alloc(n):
    n=max(n,0x40); p=heap[0]; heap[0]=(p+n+0x1f)&~0xf; return p
calls=collections.Counter(); calllog=[]; insn=[0]; ring=collections.deque(maxlen=60)
imgwr=collections.Counter(); cpuidlog=[]
CAP=int(sys.argv[1]) if len(sys.argv)>1 else 20000000
START=int(sys.argv[2],16) if len(sys.argv)>2 else 0x2419ae5
def do(name):
    rc=uc.reg_read(UC_X86_REG_RCX); rd=uc.reg_read(UC_X86_REG_RDX); r8=uc.reg_read(UC_X86_REG_R8); r9=uc.reg_read(UC_X86_REG_R9)
    rax=0
    if name in ('NtQueryInformationProcess','NtQueryInformationThread','NtQuerySystemInformation','NtQueryObject','NtQueryVirtualMemory','NtQueryInformationProcess'):
        if rd: uc.mem_write(rd, b'\x00'*0x80)
        if r8: uc.mem_write(r8, b'\x20\x00\x00\x00' if 'Process' in name else b'\x00'*8)
        rax=0
    elif name in ('NtSetInformationThread','NtSetInformationProcess','NtProtectVirtualMemory','NtAllocateVirtualMemory','NtFreeVirtualMemory','VirtualProtect','VirtualProtectEx','FlushInstructionCache','NtClose','NtMapViewOfSection','NtUnmapViewOfSection','NtCreateThreadEx','NtResumeThread','NtSuspendThread','NtWaitForSingleObject','NtOpenProcess','NtOpenThread','NtDuplicateObject','RtlAddVectoredExceptionHandler','RtlRemoveVectoredExceptionHandler','RtlAddFunctionTable','RtlInitializeCriticalSection','RtlEnterCriticalSection','RtlLeaveCriticalSection','RtlDeleteCriticalSection','LdrLoadDll','LdrGetProcedureAddress','NtWriteVirtualMemory','NtReadVirtualMemory','NtWriteFile','NtReadFile','NtCreateFile','NtOpenFile'):
        if name=='NtAllocateVirtualMemory' or name=='VirtualAlloc':
            p=alloc(0x10000)
            uc.mem_write(rc, struct.pack('<Q',p)); uc.mem_write((rc+8) if False else rd, struct.pack('<Q',0x10000))
            rax=p if name=='VirtualAlloc' else 0
        elif name=='LdrGetProcedureAddress':
            rax=0
        else:
            rax=1 if name.startswith(('Virtual','Flush')) else 0
    elif name in ('LocalAlloc','HeapAlloc','RtlAllocateHeap'): rax=alloc(rd or 0x100)
    elif name in ('GetProcessHeap',): rax=0x85010000
    elif name in ('GetModuleHandleA','GetModuleHandleW','GetModuleHandleExA','LoadLibraryA','LoadLibraryW','LdrLoadDll'):
        rax=fakemod.MODBASE
    elif name in ('GetProcAddress','LdrGetProcedureAddress'):
        rax=fakemod.MODBASE+0x4000
    elif name in ('GetModuleFileNameW','GetModuleFileNameA'):
        s='C:\\cybercup2077.exe'
        if 'W' in name: uc.mem_write(rc, s.encode('utf-16-le')+b'\x00\x00')
        else: uc.mem_write(rc, s.encode()+b'\x00')
        rax=len(s)
    elif name in ('Sleep','SleepEx','LocalFree','HeapFree','RtlFreeHeap','RtlExitUserProcess'): rax=0
    elif name in ('GetCurrentProcess',): rax=0xffffffffffffffff
    elif name in ('GetCurrentProcessId','GetCurrentThreadId','GetTickCount'): rax=0x1234
    elif name in ('GetSystemInfo','GetNativeSystemInfo','GetStartupInfoA','GetStartupInfoW','GetVersion','RtlGetVersion','QueryPerformanceCounter','ProcessPrng','BCryptGenRandom','SystemFunction036'):
        if name in ('ProcessPrng','BCryptGenRandom','SystemFunction036') and rc: uc.mem_write(rc, b'\x11'*32)
        if name=='QueryPerformanceCounter' and rc: uc.mem_write(rc, struct.pack('<Q',1234))
        rax=1
    elif name in ('ExitProcess','ExitThread','NtTerminateProcess','RtlExitUserProcess'):
        print('!!! Exit called with', hex(rc), 'from rva', hex(log_ret())) ; uc.emu_stop()
    return rax
def log_ret():
    try: return struct.unpack('<Q', uc.mem_read(uc.reg_read(UC_X86_REG_RSP),8))[0]
    except UcError: return 0
def hook(uc, addr, size, ud):
    insn[0]+=1
    if insn[0]>CAP: uc.emu_stop(); return
    if addr in fns:
        nm=fns[addr]; calls[nm]+=1
        if len(calllog)<200: calllog.append((hex(addr-fakemod.MODBASE),nm,hex(uc.reg_read(UC_X86_REG_RCX)),hex(uc.reg_read(UC_X86_REG_RDX)),hex(uc.reg_read(UC_X86_REG_R8))))
        uc.reg_write(UC_X86_REG_RAX, do(nm)&0xffffffffffffffff); return
    if addr in iat_stub:
        nm=iat_stub[addr]; calls['IAT:'+nm]+=1
        if len(calllog)<200: calllog.append(('IAT',nm,hex(uc.reg_read(UC_X86_REG_RCX)),hex(uc.reg_read(UC_X86_REG_RDX)),hex(uc.reg_read(UC_X86_REG_R8))))
        uc.reg_write(UC_X86_REG_RAX, do(nm)&0xffffffffffffffff); return
    try: b=uc.mem_read(addr,size)
    except UcError: return
    ring.append((addr if addr<SIZE else addr-IMGBASE, b.hex()))
    if b[:2]==b'\x0f\xa2' and len(cpuidlog)<200:
        cpuidlog.append((hex(addr-IMGBASE),hex(uc.reg_read(UC_X86_REG_EAX)),hex(uc.reg_read(UC_X86_REG_ECX)),hex(uc.reg_read(UC_X86_REG_RDX))))
uc.hook_add(UC_HOOK_CODE, hook)
def wr(uc,access,address,size,value,ud):
    if IMGBASE<=address<IMGBASE+SIZE: imgwr[address-IMGBASE]+=1
uc.hook_add(UC_HOOK_MEM_WRITE, wr)
mapped=set(); memlog=[]
def mf(uc,access,address,size,value,ud):
    if len(memlog)<30: memlog.append((access,hex(address),size,hex(uc.reg_read(UC_X86_REG_RIP))))
    page=address & ~0xfff
    try: uc.mem_map(page,0x1000); mapped.add(page)
    except UcError: pass
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED, mf)
rip=IMGBASE+START; faults=0
while insn[0]<=CAP:
    try:
        uc.emu_start(rip,0,count=CAP)
        print('END normal rip',hex(uc.reg_read(UC_X86_REG_RIP)-IMGBASE),'insn',insn[0]); break
    except UcError as e:
        rip=uc.reg_read(UC_X86_REG_RIP); faults+=1
        if faults<=10: print('FAULT',e,'rip',hex(rip),'insn',insn[0])
        if faults>20: break
print('insns',insn[0],'faults',faults)
print('calls',dict(calls))
print('calllog',calllog[:60])
print('cpuid',cpuidlog[:20])
print('image writes',[(hex(k),v) for k,v in list(imgwr.items())[:20]], 'pages',len(imgwr))
print('memfaults',memlog[:10])
print('--- tail ---')
for a,b in list(ring)[-25:]: print(hex(a),b)
