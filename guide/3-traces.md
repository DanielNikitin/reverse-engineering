# EAC EOS — Ban Traces & Cleaner Reference

Everything EAC leaves on the system that needs cleaning after a ban.

---

## Registry Traces

| Path | What | Clean Method |
|------|------|-------------|
| `HKLM\SYSTEM\CCS\Services\EasyAntiCheat_EOS` | Driver service key + detection records | Delete entire key tree |
| `HKLM\SYSTEM\CCS\Services\EasyAntiCheat_EOS\*` | Per-process detection result values | Delete values |
| `HKLM\SYSTEM\CCS\Services\EasyAntiCheat` (non-EOS) | Legacy EAC service key | Delete if present |
| `HKLM\SYSTEM\CCS\Enum\*` (driver entries) | PnP driver enumeration history | Delete EAC-related entries |
| `HKLM\SOFTWARE\WOW6432Node\EasyAntiCheat` | EAC config/install data | Delete entire key |
| `HKLM\SYSTEM\CCS\Control\WMI\Security` | WMI access audit trail | Check for EAC GUIDs |
| `HKCU\SOFTWARE\EpicGames\*` | Game launcher state, ban state cached | Delete or reset |

---

## Filesystem Traces

| Path | What | Clean Method |
|------|------|-------------|
| `C:\Program Files (x86)\EasyAntiCheat\` | EAC install dir, certs, configs | Delete folder |
| `C:\Program Files (x86)\EasyAntiCheat_EOS\` | EOS variant install | Delete folder |
| `%APPDATA%\EasyAntiCheat\` | User-level EAC data | Delete folder |
| `%LOCALAPPDATA%\EasyAntiCheat\` | Cached detection data, logs | Delete folder |
| `%SystemRoot%\System32\drivers\EasyAntiCheat*.sys` | Kernel driver on disk | Delete |
| `%SystemRoot%\Prefetch\EASYANTICHEAT*.pf` | Prefetch trace (records load history) | Delete matching .pf files |
| `%SystemRoot%\MEMORY.DMP` | Crash dump — contains 0xEAC bugcheck if triggered | Delete if contains EAC bugcheck |
| `%SystemRoot%\Minidump\*.dmp` | Mini crash dumps | Delete EAC-dated dumps |
| `%SystemRoot%\System32\winevt\Logs\System.evtx` | Event log — driver load/unload/crash events | Clear or selectively delete |
| Game install dir | Per-game EAC folder (e.g. `FortniteGame\Binaries\Win64\EasyAntiCheat\`) | Delete EAC subfolder |
| `%ProgramData%\EasyAntiCheat\` | Shared EAC data | Delete folder |

---

## Certificate Store Traces

EAC reads 4 cert stores and leaves access timestamps:

| Store | Registry Path |
|-------|-------------|
| ROOT | `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\` |
| AuthRoot | `HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\` |
| TrustedAppRoot | `HKLM\SOFTWARE\Microsoft\SystemCertificates\TrustedAppRoot\Certificates\` |
| FlightRoot | `HKLM\SOFTWARE\Microsoft\SystemCertificates\FlightRoot\Certificates\` |

~1000 NtQueryValueKey + ~550 NtOpenKey calls per scan. Last-access timestamps on these keys can show EAC was reading them. Not critical for ban evasion but forensic indicator.

---

## Kernel Object Traces

| Object | Path | Lifetime |
|--------|------|----------|
| Device object | `\Device\EasyAntiCheat_EOS` | Deleted on driver unload |
| Symbolic link | `\DosDevices\EasyAntiCheat_EOS` | Deleted on driver unload |
| Shared sections | `\EasyAntiCheat_EOS\*` | Closed on teardown |
| MiniFilter instance | FltMgr altitude registration | Unregistered on teardown |

These are transient — exist only while driver is loaded. No cleanup needed.

---

## Kernel Callback Residue

| Callback | Registration |
|----------|-------------|
| ObRegisterCallbacks | Unregistered on teardown (§32) |
| PsSetCreateProcessNotifyRoutine(Ex) | Unregistered on teardown |
| PsSetCreateThreadNotifyRoutine | Unregistered on teardown |
| PsSetLoadImageNotifyRoutine | Unregistered on teardown |
| SeRegisterImageVerificationCallback | Unregistered on teardown |
| FltRegisterFilter | Unregistered on teardown |
| KeRegisterNmiCallback | Unregistered on teardown |
| DbgSetDebugPrintCallback | Unregistered on teardown |
| WinTrust provider | Custom deregistration |

All unregistered on clean driver unload. If driver crashes (0xEAC bugcheck), callbacks may not deregister cleanly — reboot clears them.

---

## TEB Detection Flags

| Trace | Location | Clean |
|-------|----------|-------|
| Per-thread detection flags | `TEB.SystemReserved1[0xf]` | Cleared per-thread on teardown |
| Detection flag accumulator | Kernel state mirror | Cleared on teardown |

If EAC crashes, TEB flags may persist until thread exit. Not a ban trace — per-session only.

---

## Server-Side Traces (Can't Clean)

| What | Notes |
|------|-------|
| HWID fingerprint | SMBIOS UUID + board serial + disk serial + MAC — stored server-side |
| Detection telemetry | All detection results sent via TLV protocol to *.easy.ac |
| Ban database entry | Encrypted per-entry, case-insensitive compare (& 0xDF) |
| EOS account linkage | Epic account → HWID mapping |
| Game ID + detection profile | Per-game detection history |
| TPM attestation data | PCR values, boot chain measurement — sent and stored |
| IP address history | Logged per-session |

You can't clean server-side data. This is why HWID spoofing is required — you need to present as "new hardware."

---

## Windows Artifacts (OS-Level)

| Artifact | Location | Clean Method |
|----------|----------|-------------|
| Prefetch/Superfetch DB | `%SystemRoot%\Prefetch\` | Delete all EAC .pf files |
| Amcache.hve | `%SystemRoot%\AppCompat\Programs\Amcache.hve` | Delete EAC driver entries (requires offline edit) |
| ShimCache | `HKLM\SYSTEM\CCS\Control\Session Manager\AppCompatCache` | Flush cache (reboot clears volatile entries) |
| SRUM (System Resource Usage Monitor) | `%SystemRoot%\System32\sru\SRUDB.dat` | Delete or clear EAC entries |
| BAM/DAM (Background Activity Monitor) | `HKLM\SYSTEM\CCS\Services\bam\State\UserSettings\*` | Delete EAC execution entries |
| UserAssist | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*` | ROT13-encoded, delete matching GUIDs |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Delete game/EAC launcher entries |
| USN Journal | NTFS volume journal | Can't selectively clean — full format or journal reset |
| Event Logs (all) | `%SystemRoot%\System32\winevt\Logs\` | Clear System + Application + Security logs (or selective) |

---

## Network Traces

| Trace | Location |
|-------|----------|
| DNS cache | `ipconfig /flushdns` clears |
| ARP cache | `arp -d *` clears |
| TCP/IP persistent connections | Reboot clears |
| Firewall log | `%SystemRoot%\System32\LogFiles\Firewall\` — delete if logging enabled |
| Router/gateway logs | Can't clean — ISP/router level |

---

## Cleaner Execution Order

1. **Uninstall game + EAC** (removes service, driver, game files)
2. **Delete EAC folders** (Program Files, AppData, ProgramData)
3. **Clean registry** (service keys, cert store timestamps, BAM/DAM, ShimCache, UserAssist)
4. **Clean OS artifacts** (Prefetch, Amcache, SRUM, Event Logs, Jump Lists)
5. **Flush network** (DNS, ARP)
6. **Spoof HWIDs** (all identifiers from `2-hwid-identifiers.md` — must be done before reinstall)
7. **New account** (fresh Epic/Steam account — old account is flagged server-side)
8. **Reinstall** (fresh game + EAC install on "new" hardware)

---

## What EAC Reports to Server on Detection

| Data | Protocol |
|------|----------|
| Detection type code | TLV field |
| Evidence virtual address | TLV field |
| Process name + PID | TLV field |
| Module hashes (SHA-256) | TLV field |
| Stack trace (return addresses) | TLV field |
| HWID composite fingerprint | TLV field |
| Timestamp (KUSER_SHARED_DATA) | TLV field |
| Game ID | TLV field |
| Boot environment info | TLV field |

All encrypted with PRNG stream cipher, compressed with Oodle, sent over TLS to EAC backend. Threshold-based — not every detection fires immediately; accumulates to significance threshold (§189).

---

## BSOD Artifacts (If __fastfail Triggered)

174 INT 0x29 sites with bugcheck 0xEAC. If triggered:

| Artifact | Location | Clean |
|----------|----------|-------|
| Full crash dump | `%SystemRoot%\MEMORY.DMP` | Delete |
| Mini dump | `%SystemRoot%\Minidump\*.dmp` | Delete timestamped dump |
| WER report | `%ProgramData%\Microsoft\Windows\WER\` | Delete report folders |
| Event log entry | System.evtx — BugCheck event | Clear event log |
| Registry crash count | Various crash reporting keys | Reset values |

Crash dump contains bugcheck code 0xEAC — forensic proof EAC detected something. Always delete crash artifacts.
