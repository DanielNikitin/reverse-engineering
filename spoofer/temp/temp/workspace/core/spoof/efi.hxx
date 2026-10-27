#pragma once
#include "helpers.hxx"

namespace spoof::efi {

    using namespace helpers;



    static const GUID k_vendor_guid = {
        0xeaec226fu, 0xc9a3u, 0x477au,
        { 0xa8u, 0x26u, 0xddu, 0xc7u, 0x16u, 0xcdu, 0xc0u, 0xe3u }
    };



    static void enable_env_privilege() {
        HANDLE token = nullptr;
        if ( !OpenProcessToken( GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token ) )
            return;
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValueA( nullptr, "SeSystemEnvironmentPrivilege",
                               &tp.Privileges[0].Luid );
        AdjustTokenPrivileges( token, FALSE, &tp, sizeof( tp ), nullptr, nullptr );
        CloseHandle( token );
    }



    using NtSetSysEnvEx_t = NTSTATUS( __stdcall* )(
        PUNICODE_STRING, LPGUID, PVOID, ULONG, ULONG );

    static void write_efi_var( NtSetSysEnvEx_t fn,
                               const wchar_t* name, std::uint32_t size ) {

        UNICODE_STRING uname{};
        uname.Buffer        = const_cast<wchar_t*>( name );
        uname.Length        = static_cast<USHORT>( wcslen( name ) * sizeof( wchar_t ) );
        uname.MaximumLength = static_cast<USHORT>( uname.Length + 2 );


        if ( size > 256 ) size = 256;
        std::uint8_t buf[256]{};
        for ( std::uint32_t i = 0; i < size; ++i )
            buf[i] = static_cast<std::uint8_t>( rand_next() & 0xFF );


        const NTSTATUS st = fn( &uname,
                                const_cast<LPGUID>( &k_vendor_guid ),
                                buf, size, 0x00000007u );
        if ( st == 0 )
            logging::print( "efi: var '%ls' (%u bytes) -> ok", name, size );
        else
            logging::print( "efi: var '%ls' status=0x%08X", name,
                            static_cast<std::uint32_t>( st ) );
    }



    inline void install() {

        const std::uint64_t boot_env_va =
            pdb::get_symbol_address( "ExpBootEnvironmentInformation" );
        if ( boot_env_va ) {
            std::uint8_t old_guid[16]{};
            kread( boot_env_va, old_guid, 16 );
            logging::print( "efi: boot GUID before: "
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                old_guid[3],old_guid[2],old_guid[1],old_guid[0],
                old_guid[5],old_guid[4], old_guid[7],old_guid[6],
                old_guid[8],old_guid[9], old_guid[10],old_guid[11],
                old_guid[12],old_guid[13],old_guid[14],old_guid[15] );

            std::uint8_t new_guid[16]{};
            for ( int i = 0; i < 16; ++i )
                new_guid[i] = static_cast<std::uint8_t>( rand_next() & 0xFF );

            new_guid[6] = static_cast<std::uint8_t>( ( new_guid[6] & 0x0Fu ) | 0x40u );
            new_guid[8] = static_cast<std::uint8_t>( ( new_guid[8] & 0x3Fu ) | 0x80u );

            if ( kwrite( boot_env_va, new_guid, 16 ) )
                logging::print( "efi: boot GUID patched: "
                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    new_guid[3],new_guid[2],new_guid[1],new_guid[0],
                    new_guid[5],new_guid[4], new_guid[7],new_guid[6],
                    new_guid[8],new_guid[9], new_guid[10],new_guid[11],
                    new_guid[12],new_guid[13],new_guid[14],new_guid[15] );
            else
                logging::print( "efi: boot GUID kwrite failed" );
        } else {
            logging::print( "efi: ExpBootEnvironmentInformation not found, skipping boot GUID" );
        }



        enable_env_privilege();

        auto* fn = reinterpret_cast<NtSetSysEnvEx_t>(
            GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                            "NtSetSystemEnvironmentValueEx" ) );
        if ( !fn ) {
            logging::print( "efi: NtSetSystemEnvironmentValueEx not found, skipping EFI vars" );
            return;
        }

        write_efi_var( fn, L"OfflineUniqueIDRandomSeed",  32 );
        write_efi_var( fn, L"UnlockIDCopy",               32 );
        write_efi_var( fn, L"OfflineUniqueIDEKPub",      256 );
        write_efi_var( fn, L"PlatformModuleData",         128 );
    }

}
