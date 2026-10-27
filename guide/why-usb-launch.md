# Why Some Rust (EAC) Cheats Require Launching from a USB Flash Drive

Some Rust cheats that target EAC require (or strongly recommend) launching from a USB flash drive. This is not a universal requirement, but it appears in certain loaders and bypasses for practical detection-avoidance and operational security reasons.

---

## Main Reasons

| Reason | Explanation | Relevance to EAC |
|--------|-------------|------------------|
| **Minimize disk traces** | The cheat/loader never touches the system drive. No files written to `C:\`, so fewer entries in Prefetch, Amcache, USN Journal, BAM/DAM, and filesystem scans. | High — EAC and post-ban cleaners look for these artifacts. |
| **Avoid known-path / file scans** | Some detections look for specific filenames, hashes, or paths on fixed drives. A USB path is temporary and can be ejected. | Medium |
| **Cleaner launch environment** | The loader reads the payload directly into memory from the USB and never drops it to disk (or drops it only to the USB). | Medium |
| **Easier evidence removal** | Unplug the USB and most local evidence disappears. Harder to do if everything is on the system SSD. | High for manual opsec |
| **Volume / path quirks** | A few older or specific bypasses behave differently (or were only tested) when the working directory is a removable volume. | Low–Medium |
| **Avoid main disk serial linkage** | Some crude HWID or volume checks can be influenced by where the process is launched from. Not the strongest reason, but it appears in some setups. | Low |

---

## What USB Launch Does *Not* Reliably Bypass

- Kernel-level EAC checks (stack walking, module list, BYOVD blacklist, memory scans).
- Server-side HWID bans.
- Most modern behavioral or integrity detections.

---

## Bottom Line

Launching from USB is primarily an **opsec and artifact-reduction** technique, not a core anti-cheat bypass. It reduces the amount of forensic evidence left on the main system drive after a ban or detection. Modern EAC still catches the actual cheat behavior in memory or via kernel callbacks regardless of where the executable was started from.

If the loader specifically *requires* USB, it is usually because the author built the dropper/mapper to only function that way (or to force users into better cleanup habits).
