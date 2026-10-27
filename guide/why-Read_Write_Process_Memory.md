# Read vs Write of Physical / Process Memory in Game Cheats

## Overview

Reading physical or process memory is sufficient for **read-only features** such as ESP. Writing is required for any feature that **modifies game state**.

---

## What You Can Do With Read Only

- **ESP / Wallhack / Radar** — read entity list, positions, health, names, bones, view matrix.
- **External Aimbot** — read positions + view angles, calculate angles, then move the mouse (no memory write needed).
- **Information overlays** — distance, weapons, cooldowns, etc.

For a pure ESP you only need a reliable **read** primitive:
- User-mode `ReadProcessMemory` (if the game is unprotected)
- Kernel R/W via BYOVD or DMA (if anti-cheat blocks user-mode reads)

---

## Why Write Is Needed

Writing is required whenever you want to change values or behavior inside the game process:

| Feature                      | Why write is required                              | Example                              |
|------------------------------|----------------------------------------------------|--------------------------------------|
| Internal aimbot / silent aim | Change view angles or bullet direction in memory   | Write `pitch`/`yaw` or bullet velocity |
| No-recoil / no-spread        | Overwrite recoil/spread values every frame         | Zero out recoil vectors              |
| Speed hack / fly             | Modify movement speed or gravity flags             | Write to velocity or movement flags  |
| God mode / infinite ammo     | Patch health, armor, or ammo counters              | Write large values or freeze them    |
| Triggerbot (memory-based)    | Force fire button or shoot flag                    | Write `is_shooting = true`           |
| Skin changers / unlocks      | Overwrite item IDs or inventory data               | Write skin/weapon IDs                |
| Anti-aim / desync            | Manipulate network-related angles or packet data   | Write fake angles                    |
| Bypassing checks             | Patch integrity checks or anti-cheat flags         | Write to validation variables        |

---

## External vs Internal Context

### External Cheat (separate process)
- **Read** = enough for ESP and external aimbot (mouse movement).
- **Write** = required for the features listed above.  
  Kernel-level write (BYOVD, manual-mapped driver, or DMA) is often necessary because user-mode `WriteProcessMemory` is blocked or heavily monitored.

### Internal Cheat (injected)
- Direct memory access is usually available, but modern anti-cheats still monitor writes.
- Kernel-level write can still be used to stay under the radar or to patch protected memory regions.

---

## Practical Summary

- **ESP only** → read is sufficient.
- **Anything that changes the game** (aim, movement, stats, gameplay-affecting visuals, etc.) → write is required.
- In protected games the write primitive almost always has to come from kernel space (BYOVD, manual-mapped driver, or DMA) because user-mode writes are heavily monitored.

This is why kernel mappers and R/W tools remain relevant even when the first feature people implement is a simple ESP.
