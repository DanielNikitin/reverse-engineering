# EAC EOS — HWID Identifiers & Spoofing

Every hardware identifier EAC collects and how to spoof it.

---

## Collected Identifiers

| Identifier                  | Source                                         | Format String                   | Address         | Spoof Method                                                 |
| --------------------------- | ---------------------------------------------- | ------------------------------- | --------------- | ------------------------------------------------------------ |
| **SMBIOS UUID**             | Type 1 System Info                             | `%016llx-%016llx`               | `0x140300AEA`   | Firmware table hook (`IoWMIOpenBlock` intercept) or BIOS mod |
| **SMBIOS System Serial**    | Type 1 System Info                             | part of 128-bit ID              | `0x140300B30`   | Same as UUID — must match manufacturer                       |
| **SMBIOS Board Serial**     | Type 2 Baseboard                               | part of 128-bit ID              | —               | Firmware table hook                                          |
| **SMBIOS Enclosure Serial** | Type 3 Enclosure                               | part of fingerprint             | —               | Firmware table hook                                          |
| **Memory Serial**           | Type 17 Memory Device                          | part of fingerprint             | —               | Firmware table hook — change per-DIMM                        |
| **Processor ID**            | Type 4 / CPUID Leaf 1 EAX                      | part of fingerprint             | —               | HV CPUID intercept — must match SMBIOS Type 4                |
| **Processor Brand String**  | CPUID `0x80000002-4`                           | 48-char string                  | —               | HV CPUID intercept                                           |
| **MBR Disk Signature**      | MBR sector 0 offset `0x1B8`                    | `MBR:%08x`                      | `0x140300B1E`   | Hook `IOCTL_DISK_GET_DRIVE_GEOMETRY` or write MBR directly   |
| **SCSI LUN**                | SCSI inquiry                                   | `:lun=%llx`                     | `0x140300B0A`   | Storage miniport filter — intercept inquiry response         |
| **Disk Serial**             | SCSI inquiry / SMART                           | part of fingerprint             | —               | Storage miniport filter                                      |
| **Partition Index**         | Partition table                                | `Part:%u`                       | `0x140300BFC`   | Partition table metadata mod                                 |
| **MAC Address**             | NDIS permanent                                 | `%02x:%02x:%02x:%02x:%02x:%02x` | `0x140300BC0`   | NDIS LWF driver intercepting `OID_802_3_PERMANENT_ADDRESS`   |
| **IPv4 Address**            | Adapter config                                 | `%u.%u.%u.%u`                   | `0x140300C18`   | Adapter reconfig — unreliable ban ID (DHCP changes)          |
| **Optical Drive**           | Device enum                                    | `CD:%u`                         | `0x140300C0C`   | Not critical                                                 |
| **TPM Endorsement Key**     | `Tbsi_Context_Create` → `Tbsip_Submit_Command` | hash                            | —               | No viable software spoof — skip TPM or no TPM                |
| **TPM PCR Values**          | TCG 2.0 event log                              | PCR[0-14]                       | —               | Hardware-sealed — can't modify without re-seal               |
| **PCI Device IDs**          | `HalGetBusDataByOffset` + port `0xCF8`/`0xCFC` | vendor:device pairs             | —               | DMA device firmware config space spoof                       |
| **CPUID Feature Flags**     | Leaves `0x1`, `0x7`                            | bitmask                         | `DAT_14030a240` | HV CPUID passthrough — don't filter                          |
| **CPUID Vendor String**     | Leaf `0x0`                                     | 12-char                         | —               | HV CPUID passthrough                                         |

---

## SMBIOS Types Parsed

| Type | Name               | Key Fields                                                  |
| ---- | ------------------ | ----------------------------------------------------------- |
| 0    | BIOS Information   | Vendor, version, release date, ROM size                     |
| 1    | System Information | Manufacturer, product, version, **serial**, **UUID**        |
| 2    | Baseboard          | Manufacturer, product, version, **serial**, asset tag       |
| 3    | System Enclosure   | Manufacturer, type, version, **serial**, asset tag          |
| 4    | Processor          | Manufacturer, version, **processor ID**, voltage, speed     |
| 11   | OEM Strings        | All OEM entries                                             |
| 17   | Memory Device      | Manufacturer, **serial**, part number, size, speed, locator |
| 127  | End-of-Table       | Sentinel                                                    |

Collected via `IoWMIOpenBlock(MSSmBios_RawSMBiosTables)` + `IoWMIQueryAllData` + `NtQuerySystemInformation(0x67)`.

EAC validates `CsIc`/`CrIc` tag markers in firmware tables (§186) — invalid/missing tags = spoof detected.

---

## CPUID Leaves Collected

| Leaf           | Data                                     | Ban Relevance          |
| -------------- | ---------------------------------------- | ---------------------- |
| `0x00`         | Vendor (`GenuineIntel` / `AuthenticAMD`) | CPU vendor fingerprint |
| `0x01`         | Family/Model/Stepping + features         | CPU identity           |
| `0x02-0x0F`    | Cache, TLB, topology                     | Hardware topology      |
| `0x17+`        | Extended HW fingerprinting (SOC vendor)  | Deep fingerprint       |
| `0x40000000`   | Hypervisor vendor                        | HV detection           |
| `0x80000002-4` | Brand string (`"Intel Core i9-..."`)     | CPU name               |

---

## PCI Devices Fingerprinted

512 reads across all bus/device/function combos. Per device: vendor ID, device ID, subsystem vendor, subsystem ID, class code, revision.

**Known flagged devices:**

| Vendor         | Device          | What                   |
| -------------- | --------------- | ---------------------- |
| `0x15AD`       | `0x0405`        | VMware SVGA            |
| `0x15AD`       | `0x0740`        | VMware vmxnet3         |
| `0x15AD`       | `0x07B0`        | VMware PVSCSI          |
| `0x1AF4`       | `0x1000-0x107F` | VirtIO (KVM/QEMU)      |
| `0x1414`       | `0x5353`        | Hyper-V video          |
| `0x1B36`       | `*`             | QEMU                   |
| Xilinx default | —               | PCILeech/Screamer FPGA |

---

## Ban Enforcement Function

**`FUN_140149b2d`** (§38):

```text
1. Read live hardware value
2. Server sends check_bitmask — controls which IDs to check
3. Decrypt expected banned value (per-entry PRNG XOR key schedule)
4. Case-insensitive compare (& 0xDF mask) — changing case won't evade
5. Match → BAN_FLAG set
6. Two-stage verification (primary match → secondary lookup → confirm)
7. Zero decrypted buffers after compare (anti-forensics)
```

- Server controls which checks run per scan wave
- Ban database encrypted — can't dump statically
- Two-stage reduces false positives

---

## Spoof Priority Checklist

| Priority     | Identifier                     | Why                                                      |
| ------------ | ------------------------------ | -------------------------------------------------------- |
| **CRITICAL** | SMBIOS UUID (Type 1)           | Primary hardware fingerprint component                   |
| **CRITICAL** | SMBIOS System Serial (Type 1)  | Primary hardware fingerprint component                   |
| **CRITICAL** | SMBIOS Board Serial (Type 2)   | Primary hardware fingerprint component                   |
| **HIGH**     | MBR Disk Signature             | Explicitly collected with format string                  |
| **HIGH**     | MAC Address (permanent)        | Explicitly collected — must spoof BEFORE EAC reads       |
| **HIGH**     | Disk Serial (SCSI)             | Part of composite fingerprint                            |
| **MEDIUM**   | SMBIOS Memory Serial (Type 17) | Per-DIMM serial in fingerprint                           |
| **MEDIUM**   | CPUID Processor ID             | Must match SMBIOS Type 4                                 |
| **MEDIUM**   | CPUID Brand String             | Cross-validated with SMBIOS                              |
| **MEDIUM**   | PCI Device IDs                 | DMA setups only                                          |
| **LOW**      | IPv4 Address                   | Changes with DHCP — weak identifier                      |
| **LOW**      | Partition Index                | Minor component                                          |
| **SKIP**     | TPM Endorsement Key            | No viable software spoof — disable TPM or don't have one |

---

## Cross-Validation Requirements

EAC cross-checks identifiers. Changing one without others = inconsistency flag:

- SMBIOS Type 4 Processor **must match** CPUID data
- SMBIOS Manufacturer **must be consistent** with ACPI OEM tables
- MAC OUI prefix **must match** a real vendor
- Disk serial **must be consistent** with controller type
- All identifiers **must change together** to look like "new hardware"
- SMBIOS firmware tables **must pass** `CsIc`/`CrIc` tag validation

---

## Spoof Implementation Notes

**Firmware table hook:** Intercept `IoWMIOpenBlock` / `IoWMIQueryAllData` / `NtQuerySystemInformation(0x67)` at kernel level. Return modified SMBIOS tables with new serials/UUIDs. Must maintain valid SMBIOS structure (correct lengths, checksums, type ordering).

**NDIS MAC spoof:** NDIS lightweight filter driver. Must intercept `OID_802_3_PERMANENT_ADDRESS` — not just current address. Install before EAC loads or the original MAC is already collected.

**Disk serial spoof:** Storage miniport filter intercepting SCSI inquiry responses. Must return consistent serial across multiple query paths (`IOCTL_STORAGE_QUERY_PROPERTY`, SMART, SCSI inquiry).

**CPUID spoof:** Requires hypervisor. Intercept CPUID exits, return modified leaf data. Ensure all related leaves are consistent (leaf 1 family/model must match leaf `0x80000002-4` brand string).
