# Custom Driver Mapper & BYOVD Research Notes

## Overview

This document summarizes the research on creating a custom kernel driver mapper, comparing it to existing tools (kdmapper, KDU), and selecting vulnerable signed drivers (BYOVD) for arbitrary kernel read/write — specifically for reading process or physical memory without using the heavily blocked `iqvw64e.sys`.

---

## 1. Custom Driver Mapper Skeleton

A modular C++ skeleton was created that follows the classic **BYOVD + manual map** pattern:

1. Load a vulnerable signed driver to obtain kernel arbitrary read/write (or allocation).
2. Allocate kernel memory.
3. Copy PE headers and sections of the custom driver.
4. Apply base relocations (`IMAGE_REL_BASED_DIR64`).
5. Resolve imports (primarily from `ntoskrnl`).
6. Call `DriverEntry`.

### Files in the skeleton
- `mapper.h` — interfaces and structures
- `mapper.cpp` — PE mapping logic (relocations, import walk, entry call)
- `main.cpp` — simple CLI entry point
- `README.md` — build instructions

### Build
```bat
cl.exe /EHsc /std:c++17 main.cpp mapper.cpp /link /SUBSYSTEM:CONSOLE
```

The kernel primitives (`KernelRead`, `KernelWrite`, `KernelAlloc`) are intentionally left as stubs so any vulnerable driver can be plugged in.

---

## 2. Comparison: Custom Skeleton vs kdmapper

| Aspect                  | Custom Skeleton                     | kdmapper (TheCruZ)                          |
|-------------------------|-------------------------------------|---------------------------------------------|
| Status                  | Educational / incomplete           | Fully functional                            |
| Vulnerable driver       | Any (you implement)                | Hardcoded to `iqvw64e.sys` (Intel Nal)     |
| Kernel R/W              | Stubs                              | Real IOCTL implementation                   |
| Import resolution       | Simplified stub                    | Full ntoskrnl export walk                   |
| Entry point call        | Stub                               | Real (shellcode / system thread)            |
| Stealth features        | None                               | PiDDBCacheTable clearing, independent pages |
| Purpose                 | Modular template                   | Ready-to-use research tool                  |

**Summary**: kdmapper is a complete, production-grade mapper locked to one vulnerable driver. The skeleton is a clean base if you want to support multiple drivers or integrate the logic into your own tool.

---

## 3. Alternatives to iqvw64e.sys for Memory Access

If the goal is to read process memory or physical memory without the heavily blocklisted Intel driver, these are the strongest options:

| Driver              | Source                  | Primitive                          | Best For                          | Notes |
|---------------------|-------------------------|------------------------------------|-----------------------------------|-------|
| **RTCore64.sys**    | MSI Afterburner         | Virtual R/W + MSR                  | Process virtual memory            | Easiest replacement. IOCTLs `0x80002048` (read) / `0x8000204C` (write). Direct virtual access. |
| **gdrv.sys**        | Gigabyte APP Center     | Physical R/W + MSR                 | True physical memory              | CVE-2018-19320. Excellent for physical address reads. |
| **dbutil_2_3.sys**  | Dell firmware tools     | Arbitrary R/W                      | General kernel R/W                | CVE-2021-21551. Historically widely deployed. |
| Hardware monitors   | Various OEM tools       | Physical R/W + MSR / port I/O      | Physical memory                   | Examples: WinRing0, AsrDrv, SIVX64, ArgusMonitor, etc. Often less aggressively blocked. |

### Recommended starting point
**RTCore64.sys** is the closest practical drop-in replacement for most process-memory use cases because it provides direct virtual address read/write without requiring page-table walking.

**Device**: `\\.\RTCore64`

Once you have the primitive you can:
- Walk `EPROCESS` lists
- Read process virtual memory directly
- Translate virtual → physical via page tables if pure physical access is required

**Note**: All BYOVD approaches require administrator privileges to load the driver. Modern Windows with HVCI / Vulnerable Driver Blocklist enabled will block the well-known ones.

---

## 4. KDU (Kernel Driver Utility) — Strongly Recommended

**Repository**: https://github.com/hfiref0x/KDU

KDU is a mature, actively maintained framework (latest v1.5.0 as of Sep 2026) that abstracts **60+ vulnerable drivers** (“providers”) into a unified interface.

### Key Features
- Protected Process Light (PPL) hijacking
- Driver Signature Enforcement (DSE) override
- Driver mapping (`-map`)
- Process memory dumping (`-dmp`)
- Process/thread handle opening with full access
- Support for many providers including RTCore64, Gdrv, dbutil, Intel Nal, and numerous WinIo / PhyMem-style drivers

### Comparison

| Aspect                    | Custom Skeleton     | kdmapper     | **KDU**                          |
|---------------------------|---------------------|--------------|----------------------------------|
| Completeness              | Stubs               | Full (1 driver) | Full multi-provider framework |
| Number of drivers         | You implement       | 1            | 60+                              |
| Memory primitives         | Stubs               | Real         | Real, unified API                |
| Extra capabilities        | None                | Mapping only | PPL, DSE, dump, handles, etc.    |
| Provider switching        | Manual              | Hardcoded    | `-prv ID`                        |
| Maintenance               | None                | Occasional   | Very active                      |

### Example Commands
```bat
kdu -list
kdu -prv 1 -dmp 1234          # Dump process memory via RTCore64
kdu -prv 2 -map custom.sys    # Map driver via Gigabyte Gdrv
kdu -prv 1 -ps 1234           # Modify process protection
```

### Limitations
- `-map` has classic manual-map restrictions (limited imports, no SEH, PatchGuard risk).
- Does not clear `PiDDBCacheTable` / `MmUnloadedDrivers` (by design).
- Some providers are blocklisted under HVCI.
- Not designed for stealth against modern anti-cheats.

**Verdict**: For research, memory reading, and quick testing, **KDU is clearly superior** to both the skeleton and kdmapper. Use it first.

---

## 5. Recommendations

1. **Start with KDU** — it already supports RTCore64 (provider 1), Gdrv (provider 2), and many physical-memory drivers.
2. Prefer **RTCore64** if you mainly need process virtual memory reads.
3. Prefer **Gdrv** or a PhyMem/WinIo-style provider if you specifically need physical addresses.
4. Use the custom skeleton only if you need a minimal, embeddable, or heavily customized mapper.
5. Always test on systems where the Vulnerable Driver Blocklist is disabled or not enforced.

---

## References
- KDU: https://github.com/hfiref0x/KDU
- kdmapper: https://github.com/TheCruZ/kdmapper
- LOLDrivers catalog: https://www.loldrivers.io

---
