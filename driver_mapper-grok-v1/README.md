# Custom Driver Mapper (BYOVD + Manual Map)

## Build
```
cl.exe /EHsc /std:c++17 main.cpp mapper.cpp /link /SUBSYSTEM:CONSOLE
```
Or use Visual Studio (x64 Release).

## Usage
```
mapper.exe C:\path\to\your\custom.sys
```

## What you must implement
1. **Kernel primitives** in `mapper.cpp`:
   - `KernelRead` / `KernelWrite` / `KernelAlloc` / `KernelFree`
   - These come from your chosen vulnerable signed driver (iqvw64e.sys, dbutil_2_3.sys, RTCore64.sys, etc.)

2. **Import resolution**:
   - Walk ntoskrnl export table to resolve real function addresses

3. **Entry point invocation**:
   - Most mappers allocate a small shellcode or use a system thread / APC to call `DriverEntry`

## Common BYOVD targets
- Intel `iqvw64e.sys` (Nal device) — classic kdmapper
- Capcom.sys
- MSI `RTCore64.sys`
- Dell `dbutil_2_3.sys`

## Notes
- This is a research / educational skeleton for kernel mapping research.
- Replace the stubs with real IOCTL implementations for a working mapper.
- Handle SEH, pool tagging, and cleanup properly in production research code.
