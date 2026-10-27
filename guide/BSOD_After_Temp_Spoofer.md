# What to Do If BSOD Happens After Temp Spoofing

If you get a BSOD after running a temp spoofer (like Orion or similar BYOVD-based tools), follow these steps in order.

---

## 1. Immediate Recovery

- **Boot into Safe Mode**
  - Restart and interrupt boot 2–3 times, or hold Shift while clicking Restart → Troubleshoot → Advanced options → Startup Settings → Safe Mode.
- In Safe Mode the spoofer driver usually won’t load.

---

## 2. Remove the Spoofer / Vulnerable Driver

Most temp spoofers either load via a mapper (no permanent service) or create a temporary service.

Do the following in Safe Mode (as Administrator):

```cmd
:: Stop and delete any related services
sc stop Orion
sc delete Orion
sc stop temp
sc delete temp

:: Common vulnerable driver names used by these tools
sc stop RTCore64
sc delete RTCore64
sc stop gdrv
sc delete gdrv
sc stop iqvw64e
sc delete iqvw64e
```

Also delete the driver files if present:
- `C:\Windows\System32\drivers\*.sys` (look for recently added ones)
- Any files the tool dropped in its folder or `%TEMP%`

---

## 3. Clean Registry Traces

```cmd
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Orion" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\temp" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\RTCore64" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\gdrv" /f
```

---

## 4. Check Crash Dump (Optional but Useful)

- Look in `C:\Windows\Minidump\` or `C:\Windows\MEMORY.DMP`
- The bugcheck code will tell you what failed (often related to NDIS, memory corruption, or the vulnerable driver).

---

## 5. If It Still Crashes on Normal Boot

- Boot from Windows installation media → Repair → Command Prompt and repeat the `sc delete` + file deletion steps.
- Or use System Restore to a point before you ran the spoofer.
- Last resort: Reset this PC / clean reinstall.

---

## 6. Prevention for Next Time

- Always test these tools in a **VM** first.
- Disable HVCI / Memory Integrity only when needed, then re-enable.
- Have a backup or restore point before running any kernel spoofer.
- Prefer tools that clean up after themselves, or run them from a USB and eject immediately.

---

**Note:** Most BSODs from temp spoofers are caused by the vulnerable driver or bad NDIS/MAC patches. Removing the driver and rebooting into Safe Mode resolves the majority of cases.
