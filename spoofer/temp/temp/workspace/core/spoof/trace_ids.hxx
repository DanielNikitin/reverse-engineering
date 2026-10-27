#pragma once
#include "helpers.hxx"

namespace spoof::trace_ids {

    static DWORD rand_dword() {
        return ( helpers::rand_next() << 17u ) ^
               ( helpers::rand_next() << 2u ) ^
                 helpers::rand_next();
    }

    static GUID make_guid() {
        GUID g{};
        g.Data1 = rand_dword();
        g.Data2 = static_cast<WORD>( helpers::rand_next() );
        g.Data3 = static_cast<WORD>( ( helpers::rand_next() & 0x0FFFu ) | 0x4000u );
        const DWORD a = rand_dword();
        const DWORD b = rand_dword();
        memcpy( g.Data4, &a, 4 );
        memcpy( g.Data4 + 4, &b, 4 );
        g.Data4[0] = static_cast<BYTE>( ( g.Data4[0] & 0x3Fu ) | 0x80u );
        return g;
    }

    static void format_guid( wchar_t* out, std::size_t cch, bool braces ) {
        const GUID g = make_guid();
        swprintf_s( out, cch,
            braces
                ? L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
                : L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1],
            g.Data4[2], g.Data4[3], g.Data4[4],
            g.Data4[5], g.Data4[6], g.Data4[7] );
    }

    static bool contains_i( const wchar_t* haystack, const wchar_t* needle ) {
        if ( !haystack || !needle || !*needle ) return false;
        const std::size_t nlen = wcslen( needle );
        for ( const wchar_t* p = haystack; *p; ++p )
            if ( _wcsnicmp( p, needle, nlen ) == 0 )
                return true;
        return false;
    }

    static bool set_sz( HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value ) {
        HKEY hk = nullptr;
        if ( RegCreateKeyExW( root, path, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hk, nullptr ) != ERROR_SUCCESS )
            return false;

        const DWORD bytes = static_cast<DWORD>( ( wcslen( value ) + 1 ) * sizeof( wchar_t ) );
        const bool ok = RegSetValueExW( hk, name, 0, REG_SZ,
            reinterpret_cast<const BYTE*>( value ), bytes ) == ERROR_SUCCESS;
        RegCloseKey( hk );
        return ok;
    }

    static void delete_value( HKEY root, const wchar_t* path, const wchar_t* name ) {
        HKEY hk = nullptr;
        if ( RegOpenKeyExW( root, path, 0, KEY_SET_VALUE, &hk ) != ERROR_SUCCESS )
            return;
        RegDeleteValueW( hk, name );
        RegCloseKey( hk );
    }

    static bool set_dword( HKEY root, const wchar_t* path, const wchar_t* name, DWORD value ) {
        HKEY hk = nullptr;
        if ( RegCreateKeyExW( root, path, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hk, nullptr ) != ERROR_SUCCESS )
            return false;

        const bool ok = RegSetValueExW( hk, name, 0, REG_DWORD,
            reinterpret_cast<const BYTE*>( &value ), sizeof( value ) ) == ERROR_SUCCESS;
        RegCloseKey( hk );
        return ok;
    }

    static void patch_guid_value( HKEY root, const wchar_t* path, const wchar_t* name, bool braces, std::uint32_t& count ) {
        wchar_t guid[64] = {};
        format_guid( guid, 64, braces );
        if ( set_sz( root, path, name, guid ) )
            ++count;
    }

    static void patch_hardware_profiles( std::uint32_t& count ) {
        HKEY profiles = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles",
                0, KEY_READ, &profiles ) != ERROR_SUCCESS )
            return;

        for ( DWORD i = 0; ; ++i ) {
            wchar_t sub[128] = {};
            DWORD sub_len = 128;
            if ( RegEnumKeyExW( profiles, i, sub, &sub_len, nullptr, nullptr, nullptr, nullptr ) != ERROR_SUCCESS )
                break;

            wchar_t path[256] = {};
            swprintf_s( path, L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\%s", sub );
            patch_guid_value( HKEY_LOCAL_MACHINE, path, L"HwProfileGuid", true, count );
        }
        RegCloseKey( profiles );
    }

    static void patch_matching_values_recursive( HKEY root, const wchar_t* path,
                                                 const wchar_t* const* needles,
                                                 std::size_t needle_count,
                                                 std::uint32_t& count,
                                                 std::uint32_t depth = 0 ) {
        if ( depth > 12 ) return;

        HKEY hk = nullptr;
        if ( RegOpenKeyExW( root, path, 0, KEY_READ | KEY_WRITE, &hk ) != ERROR_SUCCESS )
            return;

        for ( DWORD i = 0; ; ++i ) {
            wchar_t name[256] = {};
            DWORD name_len = 256;
            DWORD type = 0;
            LSTATUS s = RegEnumValueW( hk, i, name, &name_len, nullptr, &type, nullptr, nullptr );
            if ( s == ERROR_NO_MORE_ITEMS ) break;
            if ( s != ERROR_SUCCESS ) continue;

            bool match = false;
            for ( std::size_t n = 0; n < needle_count && !match; ++n )
                match = contains_i( name, needles[n] );

            if ( match && ( type == REG_SZ || type == REG_EXPAND_SZ || type == REG_BINARY || type == REG_DWORD || type == REG_QWORD ) ) {
                wchar_t guid[64] = {};
                format_guid( guid, 64, contains_i( name, L"guid" ) || contains_i( name, L"uuid" ) );
                RegSetValueExW( hk, name, 0, REG_SZ,
                    reinterpret_cast<const BYTE*>( guid ),
                    static_cast<DWORD>( ( wcslen( guid ) + 1 ) * sizeof( wchar_t ) ) );
                ++count;
            }
        }

        for ( DWORD i = 0; ; ++i ) {
            wchar_t sub[256] = {};
            DWORD sub_len = 256;
            if ( RegEnumKeyExW( hk, i, sub, &sub_len, nullptr, nullptr, nullptr, nullptr ) != ERROR_SUCCESS )
                break;

            wchar_t child[512] = {};
            swprintf_s( child, L"%s\\%s", path, sub );
            patch_matching_values_recursive( root, child, needles, needle_count, count, depth + 1 );
        }

        RegCloseKey( hk );
    }

    static bool run_hidden( const wchar_t* cmd ) {
        wchar_t command_line[1024] = {};
        swprintf_s( command_line, L"cmd.exe /c %s", cmd );

        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof( si );
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if ( !CreateProcessW( nullptr, command_line, nullptr, nullptr, FALSE,
                CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi ) )
            return false;

        WaitForSingleObject( pi.hProcess, 30000 );
        DWORD exit_code = 1;
        GetExitCodeProcess( pi.hProcess, &exit_code );
        CloseHandle( pi.hThread );
        CloseHandle( pi.hProcess );
        return exit_code == 0;
    }

    static void delete_file_if_exists( const wchar_t* path, std::uint32_t& count ) {
        if ( DeleteFileW( path ) )
            ++count;
    }

    static void cleanup_known_files() {
        std::uint32_t deleted = 0;
        wchar_t win[MAX_PATH] = {};
        GetWindowsDirectoryW( win, MAX_PATH );

        wchar_t path[MAX_PATH] = {};
        swprintf_s( path, L"%s\\INF\\setupapi.dev.log", win );
        delete_file_if_exists( path, deleted );
        swprintf_s( path, L"%s\\INF\\setupapi.setup.log", win );
        delete_file_if_exists( path, deleted );
        swprintf_s( path, L"%s\\Temp\\MachineGuid.txt", win );
        delete_file_if_exists( path, deleted );

        wchar_t temp[MAX_PATH] = {};
        if ( GetTempPathW( MAX_PATH, temp ) ) {
            swprintf_s( path, L"%sMachineGuid.txt", temp );
            delete_file_if_exists( path, deleted );
        }

        logging::print( "trace_ids: deleted %u known serial/log file(s)", deleted );
    }

    static void cleanup_recycle_bins() {
        DWORD mask = GetLogicalDrives();
        std::uint32_t cleaned = 0;
        for ( wchar_t drive = L'A'; drive <= L'Z'; ++drive ) {
            if ( !( mask & ( 1u << ( drive - L'A' ) ) ) ) continue;

            wchar_t root[4] = { drive, L':', L'\\', 0 };
            if ( GetDriveTypeW( root ) != DRIVE_FIXED ) continue;

            wchar_t cmd[128] = {};
            swprintf_s( cmd, L"rd /s /q %c:\\$Recycle.Bin", drive );
            if ( run_hidden( cmd ) )
                ++cleaned;
        }
        logging::print( "trace_ids: recycle bin cleanup touched %u drive(s)", cleaned );
    }

    static void cleanup_ida_files() {
        std::uint32_t cleaned = 0;
        wchar_t base[MAX_PATH] = {};
        wchar_t cmd[1024] = {};

        if ( GetEnvironmentVariableW( L"APPDATA", base, MAX_PATH ) ) {
            swprintf_s( cmd, L"del /f /q \"%s\\Hex-Rays\\IDA\\history*\" 2>nul", base );
            if ( run_hidden( cmd ) ) ++cleaned;
            swprintf_s( cmd, L"del /f /q \"%s\\Hex-Rays\\IDA\\*.lst\" 2>nul", base );
            if ( run_hidden( cmd ) ) ++cleaned;
        }

        if ( GetEnvironmentVariableW( L"USERPROFILE", base, MAX_PATH ) ) {
            swprintf_s( cmd, L"del /f /q \"%s\\.idapro\\*history*\" 2>nul", base );
            if ( run_hidden( cmd ) ) ++cleaned;
        }

        logging::print( "trace_ids: IDA file history cleanup %u command(s)", cleaned );
    }

    static void cleanup_shadow_copies() {


        wchar_t sysdir[MAX_PATH] = {};
        GetSystemDirectoryW( sysdir, MAX_PATH );
        wchar_t cmd[MAX_PATH + 64] = {};
        swprintf_s( cmd, L"\"%s\\vssadmin.exe\" delete shadows /all /quiet", sysdir );

        wchar_t full_cmd[MAX_PATH + 128] = {};
        swprintf_s( full_cmd, L"cmd.exe /c %s", cmd );

        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof( si );
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if ( !CreateProcessW( nullptr, full_cmd, nullptr, nullptr, FALSE,
                CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi ) ) {
            logging::print( "trace_ids: shadow copies cleanup failed (CreateProcess)" );
            return;
        }
        WaitForSingleObject( pi.hProcess, 30000 );
        DWORD exit_code = 0xFF;
        GetExitCodeProcess( pi.hProcess, &exit_code );
        CloseHandle( pi.hThread );
        CloseHandle( pi.hProcess );


        const bool ok = exit_code == 0 || exit_code == 1;
        logging::print( "trace_ids: shadow copies cleanup %s (exit=%u)",
            ok ? "ok" : "failed", static_cast<unsigned>( exit_code ) );
    }

    static void cleanup_usn_journals() {
        DWORD mask = GetLogicalDrives();
        std::uint32_t cleaned = 0;
        for ( wchar_t drive = L'A'; drive <= L'Z'; ++drive ) {
            if ( !( mask & ( 1u << ( drive - L'A' ) ) ) ) continue;

            wchar_t root[4] = { drive, L':', L'\\', 0 };
            if ( GetDriveTypeW( root ) != DRIVE_FIXED ) continue;

            wchar_t cmd[128] = {};
            swprintf_s( cmd, L"fsutil usn deletejournal /d /n %c:", drive );
            if ( run_hidden( cmd ) )
                ++cleaned;
        }
        logging::print( "trace_ids: USN journal cleanup touched %u drive(s)", cleaned );
    }

    static void cleanup_bcd() {
        std::uint32_t ok = 0;
        ok += run_hidden( L"bcdedit /deletevalue {current} resumeobject" ) ? 1u : 0u;
        ok += run_hidden( L"bcdedit /deletevalue {default} resumeobject" ) ? 1u : 0u;
        ok += run_hidden( L"bcdedit /deletevalue {bootmgr} displayorder" ) ? 1u : 0u;
        logging::print( "trace_ids: BCD resume/displayorder cleanup %u/3", ok );
    }

    static void patch_registry_ids() {
        std::uint32_t count = 0;

        patch_guid_value( HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography",
            L"MachineGuid", false, count );

        patch_hardware_profiles( count );

        patch_guid_value( HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            L"SusClientId", false, count );
        delete_value( HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            L"SusClientIdValidation" );

        patch_guid_value( HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\SQMClient",
            L"MachineId", true, count );
        patch_guid_value( HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\SQMClient\\Windows",
            L"MachineId", true, count );

        const DWORD install_stamp = 1262304000u + ( rand_dword() % 4102444800u );
        if ( set_dword( HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Internet Explorer",
                L"InstallDate", install_stamp ) )
            ++count;
        if ( set_dword( HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Internet Explorer",
                L"InstallTime", rand_dword() ) )
            ++count;

        const wchar_t* diag_needles[] = {
            L"DiagTrack", L"DeviceId", L"MachineId", L"SusClientId", L"SQM", L"Wat", L"Activation"
        };
        patch_matching_values_recursive( HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics",
            diag_needles, sizeof( diag_needles ) / sizeof( diag_needles[0] ), count );
        patch_matching_values_recursive( HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
            diag_needles, sizeof( diag_needles ) / sizeof( diag_needles[0] ), count );

        const wchar_t* office_needles[] = {
            L"MotherboardUUID", L"MachineGuid", L"MachineId", L"DeviceId", L"Telemetry"
        };
        patch_matching_values_recursive( HKEY_CURRENT_USER,
            L"SOFTWARE\\Microsoft\\Office",
            office_needles, sizeof( office_needles ) / sizeof( office_needles[0] ), count );
        patch_matching_values_recursive( HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Office",
            office_needles, sizeof( office_needles ) / sizeof( office_needles[0] ), count );

        const wchar_t* video_needles[] = {
            L"DeviceId", L"HardwareInformation", L"MatchingDeviceId", L"ProviderName"
        };
        patch_matching_values_recursive( HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DEVICEMAP\\VIDEO",
            video_needles, sizeof( video_needles ) / sizeof( video_needles[0] ), count );
        patch_matching_values_recursive( HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Video",
            video_needles, sizeof( video_needles ) / sizeof( video_needles[0] ), count );

        const wchar_t* ida_needles[] = {
            L"History", L"Recent", L"Input", L"Last"
        };
        patch_matching_values_recursive( HKEY_CURRENT_USER,
            L"SOFTWARE\\Hex-Rays",
            ida_needles, sizeof( ida_needles ) / sizeof( ida_needles[0] ), count );
        patch_matching_values_recursive( HKEY_CURRENT_USER,
            L"SOFTWARE\\IDA",
            ida_needles, sizeof( ida_needles ) / sizeof( ida_needles[0] ), count );

        logging::print( "trace_ids: patched %u registry trace value(s)", count );
    }

    inline void install() {
        patch_registry_ids();
        cleanup_bcd();
        cleanup_usn_journals();
        cleanup_known_files();
        cleanup_recycle_bins();
        cleanup_ida_files();
        cleanup_shadow_copies();
    }

}
