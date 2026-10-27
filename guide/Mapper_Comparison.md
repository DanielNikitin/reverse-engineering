# Direct Comparison: Custom Mapper Skeleton vs kdmapper vs KDU

| Aspect                  | My mapper skeleton          | kdmapper                    | **KDU**                              |
|-------------------------|-----------------------------|-----------------------------|--------------------------------------|
| Completeness            | Educational stubs           | Full for one driver         | Full multi-provider framework        |
| Vulnerable drivers      | You implement them          | Only iqvw64e                | **60+ providers** (RTCore64, Gdrv, dbutil, many WinIo/PhyMem, newer ones) |
| Memory primitives       | Stubs                       | Real                        | Real, unified API                    |
| Driver mapping (`-map`) | No                          | Yes                         | Yes (with shellcode variants)        |
| Extra capabilities      | None                        | Mapping only                | PPL hijack, DSE override, process memory dump, handle opening, etc. |
| Maintenance             | None                        | Occasional                  | Very active (v1.5.0 in Sep 2026)     |
| Provider switching      | Manual rewrite              | Hardcoded                   | `-prv ID` switch                     |
| Physical memory focus   | Possible if you code it     | Limited                     | Strong (many MAPMEM/WinIo providers) |

## Summary

- **Custom mapper skeleton**: Clean educational base. Useful only if you want to build or heavily customize your own mapper and implement the kernel primitives yourself.
- **kdmapper**: Complete, ready-to-use mapper locked to the Intel `iqvw64e.sys` driver. Good for single-purpose mapping research but limited in flexibility.
- **KDU**: Clearly the strongest option for research. Multi-provider support, unified memory primitives, extra features (PPL, DSE, memory dump, etc.), and active maintenance.

**Recommendation**: Prefer KDU for practical work. Use the custom skeleton only when you need a minimal or fully custom implementation.
