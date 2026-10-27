# Will the Orion Temp Spoofer Work on My System?

**Short answer:** It *might* work, but it is not guaranteed, and it carries real risk of BSOD, instability, or leaving your system in a bad state.

---

## Requirements for Orion (the Temp Spoofer) to Run

From the UnknownCheats thread:
- Windows 10/11 x64
- Administrator privileges
- Ability to load the vulnerable driver it uses (BYOVD)
- Visual Studio build environment if you compile it yourself (or use the released binary)
- Secure Boot / HVCI / Vulnerable Driver Blocklist **disabled** or not blocking the specific driver it relies on

If any of those are active on your system, it will fail to load or crash.

---

## Practical Problems

| Issue                        | Likelihood   | Notes from the thread / typical behavior          |
|-----------------------------|--------------|---------------------------------------------------|
| BSOD on load or shutdown    | Medium–High  | NDIS/MAC part was already reported to cause BSODs |
| Network drop / instability  | Medium       | Split-brain MAC issue was discussed               |
| Does nothing / partial spoof| Medium       | Depends on Windows build and whether offsets match|
| Blocked by HVCI or driver blocklist | High on modern Win11 | Most BYOVD drivers used by these tools are blocked |
| Leaves traces               | High         | Kernel driver load, event logs, etc.              |

---

## Will It Change Your Hardware Numbers?

- **Yes, temporarily** — if it successfully loads and the offsets match your Windows version, it will alter SMBIOS, disk serials, MAC, etc. in memory/kernel structures for the current boot.
- **No, permanently** — changes are lost on reboot (that’s why it’s called a “temp” spoofer).
- It does **not** change the actual firmware/BIOS values.

---

## Recommendation

If you truly just want to change hardware identifiers “for no particular reason,” this is a high-risk way to do it. Safer and more reliable options for casual use are:
- Registry-level MAC change + adapter restart
- Third-party user-mode tools that only touch non-critical IDs
- Or simply not doing it

Orion is written for anti-cheat bypass research contexts and assumes you accept kernel instability and potential detection.

**If you still want to try it**, test it in a VM first, with HVCI off, and be prepared to recover from a BSOD.

---

**Source thread**: https://www.unknowncheats.me/forum/anti-cheat-research/759853-temp-spoofer.html
