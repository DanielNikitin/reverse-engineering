@echo off
setlocal enabledelayedexpansion

echo ================================================================
echo Building dxk_sync_host.sys (MSVC x64 Kernel Driver)
echo ================================================================

call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"

if not exist "ntoskrnl.lib" (
    echo [*] Generating ntoskrnl.lib from ntoskrnl.def...
    lib.exe /NOLOGO /DEF:ntoskrnl.def /MACHINE:X64 /OUT:ntoskrnl.lib
)

cl.exe /c /O2 /Oi /Ot /std:c++20 /kernel /GR- /GS- /EHs-c- /GF /Gy /W3 /nologo ^
       /D_AMD64_ /D_KERNEL_MODE /I. /I"%VCToolsInstallDir%include" ^
       driver_main.cpp

if %ERRORLEVEL% neq 0 (
    echo [-] Compilation failed!
    exit /b %ERRORLEVEL%
)

link.exe /NOLOGO /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry ^
         /NODEFAULTLIB /OPT:REF /OPT:ICF ^
         /DEBUG:NONE ^
         /DYNAMICBASE /FIXED:NO ^
         /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text ^
         ntoskrnl.lib ^
         driver_main.obj /OUT:..\Build\dxk_sync_host.sys

if %ERRORLEVEL% equ 0 (
    echo [+] Successfully built dxk_sync_host.sys
    copy /Y ..\Build\dxk_sync_host.sys ..\mapper\dxk_sync_host.sys >nul
    copy /Y ..\Build\dxk_sync_host.sys "C:\Users\Dwin6_0\Desktop\NewBy\Build\dxk_sync_host.sys" >nul
    del *.obj 2>nul
) else (
    echo [-] Link failed!
    exit /b %ERRORLEVEL%
)
