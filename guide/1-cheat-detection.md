# EAC EOS — Cheat Detection

27.10.2026

What EAC detects, how, and via what kernel calls.

**Legend:** **YES** — reliably detected ·
**PARTIAL** — detected under some conditions ·
**NO** — not detected

---

## Detected Injection Types

| Injection Method                   | Detected?   | How                                                                               |
| ---------------------------------- | ----------- | --------------------------------------------------------------------------------- |
| `LoadLibrary`                      | **YES**     | `PsSetLoadImageNotifyRoutine`, module blacklist                                   |
| Manual map (MDL/physical)          | **PARTIAL** | Stack walking catches callbacks from unmapped memory                              |
| Reflective DLL                     | **YES**     | Memory content scan, no module entry in `PsLoadedModuleList`                      |
| APC injection                      | **YES**     | Thread notify callback, stack walk on APC delivery                                |
| Thread hijack / `SetThreadContext` | **YES**     | Handle stripping blocks `SetThreadContext`, thread start addr validation          |
| Process hollowing                  | **YES**     | Process creation notify, parent relationship check                                |
| Module stomping                    | **PARTIAL** | PE hash mismatch (disk vs memory fingerprint §239-240), section heuristics (§241) |
| DLL sideloading                    | **YES**     | Image load notify hashes every loaded image                                       |
| Shellcode in allocated memory      | **YES**     | Stack walking — return address outside any module                                 |
| `NtCreateSection`-based            | **YES**     | Image load notify fires                                                           |
| Atom bombing                       | **PARTIAL** | Memory content scan may catch payload                                             |
| ThreadlessInject / PoolParty       | **PARTIAL** | Memory scan if payload touches monitored regions                                  |

---

## Detected Driver Types

| Driver Type                                                     | Detected?   | How                                                                          |
| --------------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------- |
| Unsigned driver (`NtLoadDriver`)                                | **YES**     | `SeRegisterImageVerificationCallback` rejects before execution               |
| Test-signed driver                                              | **YES**     | BCD testsigning check + cert chain validation                                |
| Known BYOVD (RTCore64, dbk64, Dell DBUtil, Intel NAL, GIGABYTE) | **YES**     | Encrypted SHA-1 blacklist (42 entries), name blacklist (4,674 comparisons)   |
| Unknown BYOVD with valid WHQL                                   | **NO**      | Passes cert chain check, not on blacklist                                    |
| Cheat Engine kernel (`dbk64.sys`)                               | **YES**     | Hardcoded in module blacklist                                                |
| Manual-mapped driver                                            | **PARTIAL** | Stack walk catches calls from unmapped memory, no `PsLoadedModuleList` entry |
| Driver with dev build path PDB                                  | **YES**     | ~30 encrypted path patterns checked (§34)                                    |
| Revoked-cert driver                                             | **YES**     | Certificate chain validation, CRL check                                      |

---

## Detected Hypervisor Techniques

| Technique                                   | Detected?   | How                                                                      |
| ------------------------------------------- | ----------- | ------------------------------------------------------------------------ |
| CPUID leaf `0x1` bit 31 (HV present)        | **YES**     | Direct check — bit set = hypervisor active                               |
| Custom HV vendor string                     | **YES**     | CPUID `0x40000000` read — unknown vendor flagged                         |
| CPUID feature filtering                     | **YES**     | Cross-leaf consistency check — missing features = HV filtering           |
| MSR hooking (`LSTAR`, `SYSENTER_EIP`)       | **YES**     | Read-modify-write cycle under CLI/STI — readback mismatch = interception |
| EPT page splitting (execute vs read)        | **PARTIAL** | INVLPG forces TLB miss → fresh page walk reveals split                   |
| TSC manipulation                            | **YES**     | RDTSC quad-check with CPUID calibration, WRMSR+RDPMC timing              |
| Hyper-V binary patching (`hvix64`/`hvax64`) | **YES**     | Disk vs memory hash comparison                                           |
| Type-1 HV below Windows                     | **PARTIAL** | MSR probe, RDTSC timing, but no binary to hash                           |
| VBS/HVCI state change                       | **YES**     | `VslGetSecurePciEnabled` check                                           |
| HV shared page anomaly                      | **YES**     | `NtQuerySystemInformation(0xC5)` — non-standard address pattern          |
| ACPI table manipulation                     | **YES**     | `HalAcpiGetTableEx` from 4 sites — checks SLIC, MADT, FADT               |

---

## Detected DMA / Firmware Techniques

| Technique                                  | Detected?   | How                                                                            |
| ------------------------------------------ | ----------- | ------------------------------------------------------------------------------ |
| PCILeech default FPGA (Xilinx ID)          | **YES**     | PCI config space scan — 512 `HalGetBusDataByOffset` + port `0xCF8`/`0xCFC` I/O |
| Custom FPGA with spoofed vendor/device ID  | **NO**      | Looks like legitimate PCI device                                               |
| Thunderbolt DMA adapter                    | **PARTIAL** | PCI device logged, presence noted                                              |
| IOMMU bypass                               | **PARTIAL** | VBS state check detects if IOMMU active                                        |
| DMA device with unusual BAR config         | **YES**     | PCI bus/device/function topology walk (§215)                                   |
| Modified UEFI firmware                     | **YES**     | SMBIOS cross-validation with CPUID, ACPI table probes                          |
| Bootkit (MBR/VBR modification)             | **YES**     | TPM PCR mismatch, Secure Boot chain validation                                 |
| UEFI bootkit (firmware DXE)                | **YES**     | TPM PCR[0-7] mismatch, firmware table parsing                                  |
| Early-launch driver injection              | **YES**     | TPM PCR[11] mismatch                                                           |
| BCD test-signing enabled                   | **YES**     | Registry BCD element check                                                     |
| Modified `ntoskrnl`/`securekernel` on disk | **YES**     | Disk vs memory image hash                                                      |

---

## Kernel Calls EAC Monitors

Calls EAC watches for unauthorized use (by cheats calling them):

| Call                            | Monitoring Method                                                    |
| ------------------------------- | -------------------------------------------------------------------- |
| `NtOpenProcess`                 | `ObRegisterCallbacks` — strips `VM_READ`/`WRITE`/`OPERATION`         |
| `NtOpenThread`                  | `ObRegisterCallbacks` — strips `SET`/`GET_CONTEXT`, `SUSPEND_RESUME` |
| `NtDuplicateObject`             | `ObRegisterCallbacks` — same stripping on duped handles              |
| `NtWriteVirtualMemory`          | Handle stripping blocks; stack walking catches kernel calls          |
| `NtAllocateVirtualMemory`       | Handle stripping; kernel allocs visible in VAD                       |
| `NtProtectVirtualMemory`        | Handle stripping; RWX regions flagged by scan                        |
| `PsCreateSystemThread`          | Thread start address must be in known module                         |
| `NtCreateThreadEx`              | Process notify catches new threads in game process                   |
| `NtSetContextThread`            | Handle stripping blocks                                              |
| `NtLoadDriver` / `ZwLoadDriver` | `SeRegisterImageVerificationCallback` fires pre-execution            |
| `MmLoadSystemImage`             | Same callback chain                                                  |

---

## Kernel Calls EAC Makes (Detection Tools)

| Call                                          | Usage                                          |
| --------------------------------------------- | ---------------------------------------------- |
| `RtlWalkFrameChain`                           | Stack frame capture (1% sampling in callbacks) |
| `RtlVirtualUnwind` + `RtlLookupFunctionEntry` | Return address validation per frame            |
| `MmCopyVirtualMemory`                         | Read game process memory pages                 |
| `MmCopyMemory`                                | Safe kernel memory reads                       |
| `PsLookupProcessByProcessId`                  | PID resolution (512/scan pass)                 |
| `PsLookupThreadByThreadId`                    | TID resolution (1000+/scan cycle)              |
| `PsGetProcessImageFileName`                   | Process name for blacklist                     |
| `SeQueryInformationToken`                     | Token privileges, user SID, AppContainer SID   |
| `ObReferenceObjectByName`                     | Named object lookup (`\Driver\disk`, etc.)     |
| `CiValidateFileObject`                        | Signed file on disk vs process image           |
| `HalGetBusDataByOffset`                       | PCI config reads (512)                         |
| `HalAcpiGetTableEx`                           | ACPI table reads (4 sites)                     |
| `IoWMIOpenBlock` + `IoWMIQueryAllData`        | WMI/SMBIOS data                                |
| `FltReadFile`                                 | File contents via minifilter                   |
| `RtlCompareString`                            | Module name blacklist (4,674 calls)            |
| `NtQuerySystemInformation(0x05)`              | Full process list                              |
| `NtQuerySystemInformation(0x0B)`              | All loaded modules (64 calls)                  |
| `NtQuerySystemInformation(0x10)`              | All open handles system-wide                   |
| `NtQuerySystemInformation(0x67)`              | SMBIOS/ACPI firmware tables                    |
| `NtQuerySystemInformation(0xC5)`              | Hypervisor shared page                         |

---

## Kernel Callbacks Registered

| Callback              | API                                   | Scope                                |
| --------------------- | ------------------------------------- | ------------------------------------ |
| Handle filter         | `ObRegisterCallbacks`                 | Every `NtOpenProcess`/`NtOpenThread` |
| Process notify        | `PsSetCreateProcessNotifyRoutine(Ex)` | Every process create/exit            |
| Thread notify         | `PsSetCreateThreadNotifyRoutine`      | Every thread creation                |
| Image load            | `PsSetLoadImageNotifyRoutine`         | Every DLL/driver load                |
| Image verification    | `SeRegisterImageVerificationCallback` | Every driver CI check                |
| Filesystem minifilter | `FltRegisterFilter`                   | All file I/O system-wide             |
| NMI callback          | `KeRegisterNmiCallback`               | NMI on all cores                     |
| Debug print           | `DbgSetDebugPrintCallback`            | All debug output                     |
| WinTrust provider     | Custom registration                   | Signature verification               |

---

## Memory Scanning Methods

| Method                                       | What It Does                                              |
| -------------------------------------------- | --------------------------------------------------------- |
| `MmCopyVirtualMemory` page scan              | SHA-256 of 4096-byte pages vs expected hashes             |
| SIMD content scanner (SSE2/AVX/AVX2/AVX-512) | 16-64 bytes/cycle, ASCII pattern detection in memory      |
| AOB signature scanner (IDA/CE format)        | Byte pattern + mask matching against `ntoskrnl` prologues |
| PE on-disk vs in-memory comparison           | Field-by-field PE header fingerprint diff                 |
| PE section integrity hash                    | Per-section hash with `.rsrc`/`.reloc` exclusion          |
| PE section characteristics check             | W+X flagging, unusual protection attributes               |
| Marker-bounded integrity hash                | XOR-decode bounded region → hash → compare expected       |
| Import/export table validation               | Resolved addresses must be within owning module           |
| CRC32 hardware integrity check               | CRC32C instruction-based fast integrity                   |
| Spinlock memory watchpoint                   | Detects concurrent access to monitored regions            |
| CR3 page table walk                          | Physical memory read bypassing all API monitoring         |

---

## Cheat Tool Detection

| Tool                                 | Detection Method                               |
| ------------------------------------ | ---------------------------------------------- |
| Cheat Engine (`dbk64.sys` + process) | Module blacklist + process name scan           |
| x64dbg                               | Process name scan                              |
| ReClass.NET                          | Process name scan                              |
| Process Hacker / System Informer     | Process name scan                              |
| IDA Pro                              | Process name scan                              |
| Kernel debugger (WinDbg)             | `KdDebuggerEnabled` check, INT 1/3 SEH traps   |
| Frida / DBI                          | RDTSC timing detection                         |
| Custom debug tools                   | Build path PDB detection, module name matching |

---

## Anti-Debug

| Check                          | Method                                                               |
| ------------------------------ | -------------------------------------------------------------------- |
| INT 1 SEH trap                 | Driver init gate — debugger consuming = driver fails to load         |
| INT 3 SEH trap                 | Same + periodic re-check                                             |
| RDTSC timing                   | Back-to-back with randomized loop — single-step/VM overhead detected |
| `KdDebuggerEnabled`            | Direct kernel variable read — ever-set = flagged                     |
| RDTSC+CPUID quad check         | Ratio comparison — HV exit cost detected                             |
| WRMSR+RDPMC                    | Performance counter timing channel                                   |
| `KUSER_SHARED_DATA` timestamps | Unhookable timing source                                             |

---

## Communication Channel Detection

| Channel                              | Detected?   | How                               |
| ------------------------------------ | ----------- | --------------------------------- |
| Named device object                  | **YES**     | `\Device\` directory enumeration  |
| Named section (shared memory)        | **YES**     | Handle table scan                 |
| Named pipe                           | **YES**     | `\Device\NamedPipe\` enumeration  |
| Unnamed device                       | **PARTIAL** | `IoEnumerateDeviceObjectList`     |
| Unnamed section (kernel handle)      | **PARTIAL** | Handle visible if not kernel-only |
| MDL-based shared page                | **NO**      | No handle, no section object      |
| Physical memory mapping              | **NO**      | No handle, no section, no object  |
| WNF state data                       | **NO**      | EAC doesn't scan WNF              |
| PCI BAR register signaling           | **NO**      | Outside OS object model           |
| Direct function call between drivers | **YES**     | Stack walking                     |

---

## Detection Timing

| Detection             | Frequency                                   |
| --------------------- | ------------------------------------------- |
| Stack walking         | 1% per kernel callback                      |
| `ObRegisterCallbacks` | Every handle operation system-wide          |
| Process scanning      | Continuous (512 PIDs/pass)                  |
| Thread enumeration    | Continuous (1000+ TIDs/cycle)               |
| Memory integrity      | Periodic (dozens of regions/cycle)          |
| Module blacklist      | 10+ full passes over `PsLoadedModuleList`   |
| PCI config scan       | Init + periodic (512 reads)                 |
| Export table walking  | FLTMGR: 10K+, hal: 4.4K, cng: 2.9K, CI: 571 |
| Filesystem minifilter | Every file I/O                              |
| RDTSC timing          | Init only                                   |
| Code self-check       | Periodic                                    |
| Cert store scan       | ~1000 `NtQueryValueKey`, ~550 `NtOpenKey`   |
