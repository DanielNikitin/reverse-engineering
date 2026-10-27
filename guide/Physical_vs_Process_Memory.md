# Physical Memory vs Process (Virtual) Memory in Game Cheats

## Overview

Understanding the difference between process/virtual memory and physical memory is important when dealing with modern anti-cheats such as Easy Anti-Cheat (EAC).

---

## Virtual (Process) Memory vs Physical Memory

| Aspect                  | Process / Virtual Memory                          | Physical Memory                              |
|-------------------------|---------------------------------------------------|----------------------------------------------|
| What it is              | The address space the process sees (0x0000… to 0xFFFF…) | Actual RAM addresses on the hardware        |
| How you normally access | `ReadProcessMemory`, pointers inside the process  | Via page tables, `MmMapIoSpace`, DMA, or kernel primitives |
| Translation             | Virtual → Physical via the process CR3 + page tables | Direct                                       |
| Anti-cheat visibility   | Easy to hook/monitor in user-mode                 | Harder to fully hide; requires kernel or hardware access |
| Typical use in cheats   | Normal ESP, entity lists, etc.                    | Bypassing certain protections, reading hidden/encrypted data, DMA cheats |

---

## How This Relates to EAC (and Similar Anti-Cheats)

EAC does **not** literally store the game’s offsets only in physical memory and nowhere in the process. The game still runs in its own virtual address space.

What people usually mean by “EAC hides things in physical memory” is one or more of these techniques:

1. **Protected / encrypted structures in virtual memory**  
   Critical data (entity list, local player, view matrix, etc.) is encrypted, scrambled, or stored behind guard pages / integrity checks inside the process. A normal virtual read gives garbage or triggers detection.

2. **Page table / physical-level tricks**  
   - Some pages are marked in a way that external virtual reads fail or are monitored.  
   - Data can be temporarily unmapped from the process virtual space and only exist as physical pages.  
   - Anti-cheat can use kernel callbacks or its own driver to control which pages are visible.

3. **Kernel-side data**  
   EAC keeps some state (or copies of game data) in kernel memory that is never mapped into the game process’s user-mode address space. To read that you need kernel R/W or physical access.

4. **Detection of virtual reads**  
   User-mode or even some kernel virtual reads can be detected. Reading via physical addresses (after translating with the process CR3) or via DMA can bypass certain monitoring.

---

## Practical Implication for Cheats

- **Normal process memory read** (RPM or simple kernel virtual R/W)  
  → Works for many games, but often insufficient or detectable against EAC/BattlEye.

- **Physical memory read** (translate virtual → physical via CR3 + page tables, then read physical)  
  → More reliable against some protections. This is why DMA cards and certain BYOVD physical primitives are popular — they operate below the level where many anti-cheat checks live.

- **Write** follows the same logic: writing physical pages can sometimes be stealthier than writing through the process’s virtual address space.

---

## Summary

- **Process memory** = virtual addresses the game uses.  
- **Physical memory** = the real RAM those virtual addresses map to.  
- EAC makes pure virtual reads unreliable or detectable by encrypting data, controlling page mappings, and monitoring access. That’s why many advanced cheats move to physical-level reads (via page-table walking + physical R/W or DMA).
