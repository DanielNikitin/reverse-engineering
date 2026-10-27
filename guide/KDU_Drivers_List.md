# KDU Providers List (Vulnerable Drivers)

**Source**: Official KDU `Help/providers.md`  
**Default provider**: ID **0** (Intel Nal / `iqvw64e.sys`) if `-prv` is not specified.

---

## Main Providers (Most Relevant for Memory R/W & Mapping)

| ID | Vendor       | Driver          | Software Package                  | Version                     | MSFT Blacklist     | Notes                              |
|----|--------------|-----------------|-----------------------------------|-----------------------------|--------------------|------------------------------------|
| 0  | Intel        | IQVM64/Nal      | Network Adapter Diagnostic        | 1.03.0.7                    | Cert               | Default. Classic, heavily blocked  |
| 1  | MSI          | **RTCore64**    | MSI Afterburner                   | ≤ 4.6.2 build 15658         | Page hash          | Very popular. Virtual R/W          |
| 2  | Gigabyte     | **Gdrv**        | Gigabyte TOOLS                    | -                           | Name               | Physical R/W. Common alternative   |
| 3  | ASUSTeK      | ATSZIO64        | ASUSTeK WinFlash utility          | -                           | Name               |                                    |
| 4  | Patriot      | MsIo64          | Patriot Viper RGB                 | 1.0                         | Page hash          | WinIo-style physical               |
| 5  | ASRock       | GLCKIO2         | ASRock Polychrome RGB             | 1.0.4                       | Page hash          | WinIo-style                        |
| 6  | G.SKILL      | EneIo64         | G.SKILL Trident Z Lighting        | 1.00.08                     | Cert               |                                    |
| 7  | EVGA         | WinRing0x64     | EVGA Precision X1                 | 1.0.2.0                     | Name               | WinRing0 physical/MSR              |
| 13 | ASUS         | AsIO2           | ASUS GPU Tweak                    | ≤ 2.1.7.1                   | -                  | Common                             |
| 14 | PassMark     | DirectIo64      | PassMark Performance Test         | ≤ 10.1                      | Page hash          | Physical access                    |
| 16 | Dell         | **DBUtil_2_3**  | Dell BIOS Utility                 | ≤ 2.3                       | Page hash          | Arbitrary R/W                      |
| 20 | Dell         | DBUtilDrv2      | Dell BIOS Utility                 | ≤ 2.7                       | -                  | Newer Dell variant                 |
| 22 | ASUS         | AsIO3           | ASUS GPU Tweak II/III             | 2.3.0.3                     | -                  | Newer ASUS                         |
| 30 | AMD          | AMDRyzenMasterDriver | Ryzen Master etc.            | ≤ 2.0.0.0                   | -                  |                                    |
| 44 | AMD          | PdFwKrnl        | AMD Radeon Software               | ≤ 23.9.1                    | -                  |                                    |

---

## Newer Providers (IDs 50–67)

These are more recent additions and often less heavily blocked:

| ID | Vendor              | Driver         | Software Package               | Version              |
|----|---------------------|----------------|--------------------------------|----------------------|
| 50 | ASRock              | AsrDrv107n     | ASRock Motherboard Utility     | ≤ 3.0.498            |
| 51 | ASRock              | AsrDrv107      | ASRock Motherboard Utility     | ≤ 3.0.498            |
| 55 | TechPowerUp         | ThrottleStop   | ThrottleStop                   | ≤ 3.0.0.0            |
| 57 | Lenovo              | LnvMSRIO       | Lenovo filter driver           | ≤ 3.1.0.35           |
| 65 | Adlice              | RootLaser      | Adlice Protect                 | ≤ 3.4.1.0            |
| 66 | Kontron AG          | KtAPI          | -                              | - (MAPMEM)           |
| 67 | HP                  | hpwks          | HP Workstation Tools Driver    | ≤ 1.5.0.0            |

*(Full list contains 68 providers total. Use `kdu.exe -list` for the complete up-to-date catalog.)*

---

## Practical Recommendations

- **Avoid** ID 0 (Intel Nal) if you want to stay away from the most blocked driver.
- **Best starting points**:
  - **ID 1 – RTCore64** → best for virtual process memory reads/writes.
  - **ID 2 – Gdrv** → best for physical memory access.
  - **ID 16 – dbutil_2_3** → solid general R/W.
- Always verify current blocklist status on your target system (HVCI / Microsoft Vulnerable Driver Blocklist). Newer providers (50+) are sometimes less restricted.

---

## Usage Examples

```bat
kdu.exe -list
kdu.exe -prv 1 -dmp 1234       # Process memory dump via RTCore64
kdu.exe -prv 2 -map driver.sys # Map driver via Gigabyte Gdrv
```

**Repository**: https://github.com/hfiref0x/KDU
