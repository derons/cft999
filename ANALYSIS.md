# CyberCup 2077 — reverse-engineering write-up

**Result: flag not recovered.** The driver is fully understood; the game binary is a self-checking,
junk-obfuscated build whose protection gate could not be passed offline. Everything below is verified
by direct byte/instruction analysis and by emulation, not by guessing.

Artifacts: `cybercup.exe` (16,291,840 B), `cybercup.sys` (27,024 B) from `cybercup.zip`.
Both are byte-intact (zip CRC32s match: `0x337d4d59` / `0x5156cc83`), no overlay, no hidden members
in the archive.

---

## 1. The driver `cybercup.sys` — completely mapped

PE32+ KMDF driver, `SimpleSvm` / `CyberCupLabDriverTest`, ImageBase `0x140000000`.
It is a mock AMD-SVM hypervisor that exposes a fake-CPUID + VMMCALL "anti-cheat" API.
It contains **no flag and no flag comparison** — all of its checks are keyed hashes.

| item | value |
|---|---|
| DriverEntry | `0x1400061000` |
| VM context builder | `0x1400041c0` |
| VMEXIT dispatcher | `0x1400046e0` |
| CPUID handler | `0x140001db4` |
| VMMCALL(`0xCCBHVLAB`) sub-handlers | `0x315c`, `0x24c8`, `0x1260`, `0x29c0`, `0x20d4`, `0x36c4` |
| ARM64 executor (guest-supplied program) | `0x140001260` |
| SipHash-2-4 | `0x1400015e8` |

* Exit codes handled: `0x43 0x46 0x4e 0x72 0x7c 0x80 0x81 0x400 0xf0000000`, unknown → `KeBugCheck(0xe2)`.
* CPUID fakes vendor `"SimpleSvm   "`; `1FCA`, `20EC`, `SILA`, `TUMH`, `TGDA` are fake CPUID payloads.
* Leaf `0x4fffffff` → status/magic; leaf `0x4ffffffd` → command channel (`0x0acf2077 + n`).
* `CYCU` leaf `0x43594355` (`0x140001fc8`): requires `state == 3` and a global `== 0x43453032`,
  then answers `fmix32(guest ^ 0x9c3017a5) ^ global ^ 0x73d45bc1` plus the tag `"1FCA"`.
* VMMCALL tag `CCBHVLAB` (in guest memory at `+0x70`), sub-command in `+0x78`:
  * `0x3000–0x30ff` → `0x315c`: 8 claim slots (`data+0x10d0`, stride `0x48`), SipHash with
    `"HFVLOPEN"`, 4 chained rounds for `0x3001`;
  * `0x3100–0x31ff` → `0x24c8`: 8 "hook window" slots (`data+0x34f0`, stride `0x230`) —
    `0x3100` claim (SipHash `"ARMVM001"`, 300 ms timeout), `0x3101` append ≤0x40 dwords of program,
    `0x3102` write a qword of the 0x108-byte register block, `0x3103` execute via `0x1260`,
    `0x3104` read, `0x3105` execute with a caller-patched register, `0x3106` (`SOLVSTPF`);
  * `0x3200` → `0x1260` directly; `0x3201–0x32ff` → `0x29c0` (ARM64 `movz/movn` builders);
  * `0x3301/0x3302` → `0x20d4`; anything else → `0x36c4` (8-entry table, `data+0xc0`, mix
    `r11d*0x45d9f3b ^ ror(0xa3c59ac3, 0x17)`).
* Other machinery: `ExCreateCallback`/`ExRegisterCallback` on `\Callbacks \PowerState`,
  `PsSetCreateProcessNotifyRoutine` (`0x3c90`, only clears slots), `MmMapIoSpaceEx`,
  splitmix64/xxHash constant `0x9e3779b97f4a7c15` at `0x2118`, self-verification of `SOURCE01/02`.
* Strings are decoys/tags only: `HVCPID11 ARMVM001 CHECKOPN CHECKSTE HFVLOPEN HVPRED01 HFVLSTEP
  ALISBACK SOURCE01 SOURCE02 CYCUPNPT CCBHVLAB HVTRAP11 HVBREAK1`; magic `0x2077abcd51474e50`.
* Authenticode certificate: `CN=CyberCupLabDriverTest`, self-signed, 2026‑10‑20 → 2027‑10‑20.

So the driver is a *mock of a real anti-cheat*: real protocol, real hashing, fake payloads.
The flag therefore has to live (or be checked) in the game.

## 2. The game `cybercup.exe` — packed, junk-obfuscated, self-checking

### 2.1 Section table

Every code section has `SizeOfRawData = 0` (`.text`, `.rdata`, `.data`, `.pdata`, `.ygzqwaa`) — i.e. the
file ships *no* code for them; the only file-backed payload is:

| section | RVA | raw offset | raw size |
|---|---|---|---|
| `.acfx` | `0x1671000` | `0x400` | `0xb2800` (730 KB table) |
| `.ahrjtab` (IAT) | `0x1724000` | `0xb2c00` | `0x1000` |
| `.nkjlbac` (RWX) | `0x1725000` | `0xb3c00` | `0xed5a00` (15.5 MB) |
| `.reloc` | `0x25fb000` | `0xf89600` | `0x200` |

### 2.2 Entry point and TLS

* Entry `0x25fa93c` (last bytes of `.nkjlbac`): `48 8d 05 f2 fe e0 ff; ff e0; c3` =
  `lea rax,[rip-0x1f010e]; jmp rax` → **`0x2409835`**, inside `.nkjlbac`.
  That target is in the high-entropy blob and does not decode to a valid instruction stream.
* TLS directory `0x2093d88`, callbacks `0x142419ae5` (blob) and `0x140396380` (zeroed `.rdata`).

### 2.3 What `.nkjlbac` actually contains

| range (blob offset) | content |
|---|---|
| `0x0 – 0xd41300` | high-entropy blob, 7.996–7.999 bit/byte (encrypted/compressed payload) |
| `0xc40000 – 0xc80000` | structured table: sorted u16 stream of `(tag, id)` pairs (`tag ∈ {0x0a,0x8a}`, ids ascending) |
| `0xd41300 – 0xed593c` | **real x86-64 code** — entropy 6.9, 492 k instructions, 14 k skipped data bytes, `jmp rel32` targets land on instruction starts 241/241 |
| `0xea3b90 – 0xed593c` | tail: 12-byte `(a,b,rva)` records, in-image qwords, then the entry trampoline |

The code region is **junk-obfuscated**: harmless junk (`clc/stc/cmc/nop`, `bt/bts/btr`, `xadd`,
dead-register ops) interleaved with the real stream, `jmp +0` everywhere, computed immediates
(`push r; xor [rsp], r; pop r`), control-flow flattening and per-string decryption loops.

Confirmed real-code anchors inside it:

* `0x2467ddd` — string decryptor (key `0x17a206fd`, `rol` by counter, length `0x104`);
* `0x24c47f9` — `call rax` with an RVA-valued table entry (protector import trampoline);
* `0xd432db…0xd43402` — driver handshake: `mov eax,0x4ffffffd; mov ecx,0xacf2077; cpuid`, then
  `cmp ecx,"1FCA"`, `cmp ebx,"20EC"`, `cmp ecx,"BACK"`, `cmp edx,"ALIS"`;
* `0xd0b34e` — murmur3 `fmix32` (`0x9e3779b9`, `0x85ebca6b`, `0xc2b2ae35`).

### 2.4 Imports (rebuilt by the protector)

The IAT at `0x1724000` (8-byte stride, names stored inside `.nkjlbac`) resolves to 43 real imports:
`GetProcessHeap, NtWriteFile, ImpersonateAnonymousToken, OleInitialize, WaitOnAddress, SysFreeString,
ActivateAudioInterfaceAsync, CoCreateFreeThreadedMarshaler, AssocQueryStringW, DragQueryFileW,
RoOriginateErrorW, MonitorFromPoint, DeleteObject, ProcessPrng, AdjustWindowRectEx,
ImmGetCompositionStringW, D3DCompile, SetWindowTheme, DwmEnableBlurBehindWindow, memcpy, _hypotf,
_configure_narrow_argv, strlen, _set_fmode, _configthreadlocale, free, LocalAlloc, LocalFree,
GetModuleFileNameW, GetProcessAffinityMask, SetProcessAffinityMask, SetThreadAffinityMask, Sleep,
ExitProcess, LoadLibraryA, GetModuleHandleA, GetProcAddress, GetModuleHandleW, GetCurrentProcessId,
VirtualProtect, GetCurrentProcess, FlushInstructionCache`.

### 2.5 `.acfx`

Header `{0x2db95856, 0xc000edfa, 0x160e780}` followed by 60,921 12-byte records `(u32, u32, u32)`.
The third field is a strictly ascending RVA into `.ygzqwaa` (`0x160e780 … 0x1670187`); only 36 records
have a non-zero middle field (`{1,2,3,13…23,31,33,45…48,50,51,56}`). Behaviour matches a
fixup/patch table (value, kind, address), not a payload. No standard hash (SipHash-2-4,
crc32, fnv1/1a ×4 variants) reproduces field 1 from field 3.

## 3. Dynamic analysis (unicorn harness, kept in `tools/`)

Harness: image mapped at `0x140000000` **and** an RVA alias at `0`, stack, heap, a fabricated
`ntdll`/`kernel32` PE with a valid DOS/PE header, one `.text` section and a real export directory
(135 names) whose function pointers point to instrumented stubs, plus stubs for every real IAT entry
(`LocalAlloc`, `GetModuleHandleA`, `GetModuleFileNameW`, `VirtualProtect`, …) and lazy page mapping
on faults. Run with `tools/emu_loader.py` (needs `pefile` + `unicorn`).

Result of starting at the TLS callback `0x2419ae5`:

* executes **1,712,281 instructions** deterministically, then calls `ExitProcess(0xdeadc0de)`;
* immediately before that it decrypts the UTF-16 string **`"Initialization error "`** into its stack buffer;
* imports actually used: `LocalAlloc(0,0x160)`, `GetModuleHandleA("kernel32.dll")`,
  `GetModuleHandleA("ntdll.dll")`, `GetModuleFileNameW`, `ExitProcess(0xdeadc0de)`;
* **no `cpuid`, no `vmmcall`, and zero writes into the image** — nothing is unpacked or patched;
* exactly one bogus read (`0x5722065622194`, ASCII `"…!be run"`): the protector dereferenced a pointer
  into its own DOS-stub header, i.e. an internal table it walked was not what it expected;
* the exit is invariant to the `GetModuleFileNameW` result (four path/name variants tested).

Interpretation: the protector resolves `ntdll` exports itself and aborts with
**"Initialization error 3"** when the environment is not a real Windows loader. The game therefore
never reaches the point where it talks to the driver, and the flag path never runs. The blob at
`0x0 – 0xd41300` is never written to, so it is either encrypted payload that this gate protects, or
padding.

## 4. Negative results (do not repeat)

* No `ctfcup` / `puctfc` / reversed token / UTF-16 flag / braced token anywhere in either file.
* No printable run ≥14 chars in the exe beyond imports and six 14–15-char high-entropy blobs.
* No archive container at any tested offset: zlib, raw deflate, gzip, lzma, bz2, at `0`,
  `0xc30000`, `0xc48000`, `0xc80000`, `0xd40000`, `0xea3bc0`.
* No `MZ/PE/PK/7z/xz/zstd/ELF/RIFF/OggS/PNG` payload beyond the real PE and unvalidated decoys.
* No overlay: EOF is right after the `.reloc` block; CRC32 matches the advertised values.
* Not XOR/Caesar/single-byte keyed; not repeating-key XOR (periods 2–8 and 8…65536 probed by
  residue entropy — all 0.0042, i.e. flat).
* Bit-plane/LSB/stride extraction (`stride 2…256`, all phases) and `ctf`-in-subsequence scans: only
  statistical noise.
* Linear capstone sweeps in `.nkjlbac` are only meaningful from `0xd41300` upward; the entry target
  `0x2409835` is not code.
* The `.acfx` third field is not a file offset and not a code address; field 1 is not a standard hash.
* The `.pdata`-listed driver functions (`0x1af0`, `0x3920`, `0x41c0`, `0x4fb8`, `0x5150`, `0x5170`,
  `0x5580`) contain no string comparison and no hard-coded constants that could be a flag.
* Certificate, version resources, Rich header, PDB path: nothing to harvest (no `.rsrc`, no debug dir).

## 5. How to finish this challenge

1. **Fastest:** run the pair on a real Windows + AMD-V host with `cybercup.sys` installed
   (`sc create`; the driver gates on `"CYCUPNPT"` and the magic `0x2077abcd51474e50`).
   The game will then pass its `cpuid 0x4ffffffd` handshake; break on
   `cpuid`/`vmmcall` (`0F A2` / `0F 01 D9`) and on the `.nkjlbac` writes to find the unpacked
   flag check, or dump decrypted strings produced by the routine at `0x2467ddd`.
2. **Offline:** raise the fidelity of `tools/emu_loader.py` until `"Initialization error 3"`
   disappears — specifically (a) a real `ntdll`/`kernel32` image with sorted export names so the
   protector's manual export walk matches, (b) a plausible PEB/TEB and Ldr lists at `gs:[0x60]`,
   (c) `NtQueryInformationProcess`/`NtSetInformationThread` answers that read as "not debugged".
   Watch for the first write into the image (`0x140001000…`) — that is the unpacking step, and the
   `.acfx` fixup table then tells you where patches are applied.
3. **Static alternative:** deobfuscate `0xd41300 – 0xed593c` by removing the junk stream
   (`clc/stc/cmc/nop`, `jmp +0`, dead-register ops, `push/xor [rsp]/pop` idioms) and look for the
   comparison that consumes a user-entered string before it is handed to the ARM64 slot API
   (`0x3100…0x3105`) — the flag is almost certainly the expected input of that comparison.
