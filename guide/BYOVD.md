BYOVD (Bring Your Own Vulnerable Driver) — техника, при которой злоумышленник или исследователь загружает в систему легитимно подписанный, но уязвимый драйвер (с известными дырами в виде произвольного чтения/записи памяти ядра, IOCTL без проверок и т.п.).
Через него получают примитивы для работы в kernel-режиме и дальше мапят или исполняют свой неподписанный код.

Конкретные драйверы, эксплойты:

Driver,Source,Primitive,Best For,Notes
RTCore64.sys,MSI Afterburner,Virtual R/W + MSR,Process virtual memory,Easiest alternative. Direct virtual R/W (IOCTL 0x80002048 read / 0x8000204C write). No page-table math needed for most process reads.
gdrv.sys,Gigabyte APP Center,Physical R/W + MSR,True physical memory,Excellent if you specifically want physical addresses. CVE-2018-19320.
dbutil_2_3.sys,Dell firmware tools,Arbitrary R/W,General kernel R/W,Widely deployed historically. CVE-2021-21551.
WinRing0 / AsrDrv / hardware monitors,OEM monitoring tools,Physical R/W + MSR / port I/O,Physical memory + hardware access,"Many variants (SIVX64, ArgusMonitor, etc.). Often less aggressively blocked than the big three."


==========

BYOVD ≠ Mapper.
They are related but different.
What it is: The technique of loading a legitimate, signed, but vulnerable driver (e.g. RTCore64.sys, Gdrv.sys, iqvw64e.sys) to obtain a kernel read/write (or other) primitive.
Goal: Get arbitrary kernel memory access from user mode.
Examples: Loading RTCore64 and using its IOCTLs to read/write kernel memory.

Mapper
What it is: A tool or technique that uses a kernel primitive (usually obtained via BYOVD) to manually map an unsigned/custom driver into kernel memory.
Goal: Load and execute your own driver without going through the normal Windows driver loader (and without a valid signature).
Examples: kdmapper, KDU’s -map command, custom mappers.

BYOVD  →  gives you kernel R/W primitive
              ↓
Mapper →  uses that primitive to map your custom driver

Every classic mapper (kdmapper, KDU, etc.) uses BYOVD.
BYOVD alone does not map a driver — it only gives you the access needed to do so (or to read/write memory directly).

BYOVD = how you get kernel access.
Mapper = what you do with that access to load your own driver.