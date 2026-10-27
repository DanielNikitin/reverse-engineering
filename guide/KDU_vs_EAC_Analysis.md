# KDU Applicability Against EAC EOS

Reviewed analysis of how well the KDU (Kernel Driver Utility) method applies against the EAC EOS detection surface, ban traces, and HWID collection documented in the research notes.

---

## Summary Judgment

**KDU is useful as a research primitive for kernel R/W and quick testing, but it is a poor fit as a production solution against current EAC EOS.**  
Most of the detection methods documented will catch classic KDU-style usage.

---

## Where KDU Helps

| Capability                  | Relevance | Comment                                              |
|-----------------------------|-----------|------------------------------------------------------|
| Kernel R/W primitive        | High      | Needed to read/write game process memory when user-mode is stripped |
| Multiple providers          | Medium    | Lets you test different BYOVDs quickly               |
| `-dmp` / process memory access | Medium | Useful for initial offset research                   |
| DSE override / mapping      | Low–Medium| Can load a custom driver for testing                 |
| PPL / handle manipulation   | Low       | EAC already strips handles via `ObRegisterCallbacks` |

---

## Where KDU Fails Against EAC

| EAC Detection                                      | Impact on KDU                                      | Severity   |
|----------------------------------------------------|----------------------------------------------------|------------|
| Known BYOVD blacklist (RTCore64, dbk64, Dell DBUtil, Intel NAL, GIGABYTE, etc.) | Direct hit. Most of KDU’s popular providers are on the encrypted SHA-1 + name blacklist | **Critical** |
| `SeRegisterImageVerificationCallback`              | Catches unsigned / test-signed drivers             | High       |
| Stack walking (`RtlWalkFrameChain` + `RtlVirtualUnwind`) | Catches calls originating from manually mapped or unmapped memory | High       |
| Module blacklist + `PsLoadedModuleList` checks     | Manual-mapped drivers have no entry → flagged      | High       |
| `ObRegisterCallbacks` handle stripping             | Blocks normal `NtOpenProcess` / `NtWriteVirtualMemory` | High       |
| PCI config space scan                              | Detects many DMA devices; less relevant for pure BYOVD | Medium     |
| Hypervisor / CPUID / MSR / TSC checks              | KDU itself doesn’t use HV, but any HV-based spoof added later will be scrutinized | Medium     |
| Memory integrity / PE hash / content scanners      | Detects modified or injected code                  | Medium–High|

**Bottom line:**  
Unknown BYOVD with valid WHQL can pass the initial cert check, but almost everything else (stack walks, missing module list entry, known hashes, etc.) still catches the typical KDU workflow.

---

## Relation to Ban Traces & HWID

### Ban Traces
KDU does nothing to help with cleanup. All the registry keys, prefetch, Amcache, BAM/DAM, event logs, crash dumps (especially 0xEAC bugcheck), and filesystem traces still need the cleaner flow. KDU usage itself adds more traces (driver load events, service keys, etc.).

### HWID Identifiers
KDU gives you the kernel access needed to implement some of the spoofs (firmware table hooks, NDIS LWF, storage miniport filter, etc.), but it does not implement any of them. You still have to write the actual spoofing logic. TPM remains effectively unspoofable in software.

---

## Practical Applicability

| Use Case                          | KDU Suitability | Recommendation                              |
|-----------------------------------|-----------------|---------------------------------------------|
| Initial research / offset finding | Good            | Use on a clean VM or with blocklist disabled |
| Testing different BYOVD primitives| Good            | Switch providers with `-prv`                |
| Production external cheat vs EAC  | Poor            | Blacklisted providers + stack/module detection |
| Loading a custom stealth driver   | Poor–Medium     | Mapping leaves detectable artifacts         |
| HWID spoof development            | Medium          | Useful as the R/W primitive while building real spoof drivers |
| Long-term bypass                  | Poor            | Needs unknown/less-known drivers + better mapping + physical-level techniques + full cleaner + HWID spoof |

---

## Conclusion

KDU is an excellent **research tool** and provider database, but against the documented EAC surface it is mostly a starting point, not a solution. The detections (especially known BYOVD hashes, stack walking, and missing `PsLoadedModuleList` entries) directly target the way KDU and classic mappers operate.

### Realistic Next Steps
1. Identify currently unblocked or lesser-known providers (newer KDU IDs or drivers not yet in the 42-entry SHA-1 list).
2. Move toward physical memory access + page-table walking instead of pure virtual R/W.
3. Combine with a proper cleaner + full HWID spoof chain.
4. Consider whether a custom minimal mapper or a heavily modified KDU fork is worth it versus other approaches (DMA with spoofed config space, etc.).

---

*Analysis based on the provided EAC EOS research notes (cheat detection, HWID identifiers, and ban traces).*
