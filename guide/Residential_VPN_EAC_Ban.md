# Why a Residential VPN Is Needed After an EAC HWID + IP Ban

EAC (and most modern anti-cheats) stores both hardware identifiers and IP address history server-side. After a ban, simply spoofing HWID is often not enough if you reconnect from the same or a similar IP.

---

## What EAC Actually Records

- HWID composite fingerprint (SMBIOS, disk serial, MAC, etc.) — **primary ban key**
- IP address history (logged per session)
- Account linkage
- Detection telemetry

IP is listed as lower priority than HWID because it can change with DHCP, but it is still collected and used.

---

## Why a Normal VPN or Datacenter IP Fails

| IP Type                      | How EAC / Game Servers Treat It          | Result After Ban          |
|------------------------------|------------------------------------------|---------------------------|
| Same home IP                 | Exact match to banned IP                 | Instant re-ban            |
| Datacenter VPN (most cheap VPNs) | Known hosting ranges, high abuse score | Flagged or blocked        |
| Shared proxy / VPN           | Many bans from same ranges               | High risk of re-ban       |
| **Residential IP**           | Looks like a normal home connection      | Much harder to auto-flag  |

Residential IPs come from real ISPs (home broadband). They are not in the big datacenter ranges that anti-cheats and fraud systems heavily monitor.

---

## Practical Bypass Flow After HWID + IP Ban

1. Spoof all critical HWIDs (SMBIOS UUID, board serial, disk serial, MAC, etc.) so the machine looks like new hardware.
2. Use a **residential** VPN/proxy so the connection IP is also new and looks legitimate.
3. Create a fresh account.
4. Clean local traces.

Without the residential IP step, the server can still correlate the new HWID with the old banned IP (or with a suspicious datacenter range) and re-apply the ban.

---

## Bottom Line

- **HWID spoof** → makes the PC look like different hardware.  
- **Residential IP** → makes the network connection look like a different, legitimate home user.  

Both are required because EAC bans on the combination of hardware fingerprint **and** IP history, not HWID alone.
