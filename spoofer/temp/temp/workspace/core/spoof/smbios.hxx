#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>

namespace spoof::smbios {

    using namespace helpers;

#pragma pack(push,1)
    struct SMBIOS_HEADER { std::uint8_t Type, Length; std::uint16_t Handle; };
    struct SMBIOS_TYPE1  { SMBIOS_HEADER H; std::uint8_t Manufacturer,ProductName,Version,SerialNumber; std::uint8_t UUID[16]; };
    struct SMBIOS_TYPE2  { SMBIOS_HEADER H; std::uint8_t Manufacturer,Product,Version,SerialNumber; };
    struct SMBIOS_TYPE3  { SMBIOS_HEADER H; std::uint8_t Manufacturer,Type,Version,SerialNumber,AssetTag; };
    struct SMBIOS_TYPE17 {
        SMBIOS_HEADER H;
        std::uint16_t PhysArrayHandle, MemErrHandle, TotalWidth, DataWidth, Size;
        std::uint8_t  FormFactor, DeviceSet, DeviceLocator, BankLocator, MemType;
        std::uint16_t TypeDetail, Speed;
        std::uint8_t  Manufacturer, SerialNumber, AssetTag, PartNumber;
    };
#pragma pack(pop)



    static char* get_string_at( SMBIOS_HEADER* hdr, std::uint8_t* table_end, int idx, std::uint32_t* out_len ) {
        if ( out_len ) *out_len = 0;
        if ( idx == 0 || !hdr || !table_end ) return nullptr;
        char* cur = reinterpret_cast<char*>( hdr ) + hdr->Length;
        char* lim = reinterpret_cast<char*>( table_end );
        if ( cur >= lim ) return nullptr;
        for ( int i = 0; i < idx - 1; ++i ) {
            while ( cur < lim && *cur ) ++cur;
            if ( ++cur >= lim ) return nullptr;
        }
        char* end = cur;
        while ( end < lim && *end ) ++end;
        if ( end >= lim || end == cur ) return nullptr;
        if ( out_len ) *out_len = static_cast<std::uint32_t>( end - cur );
        return cur;
    }

    static bool is_default_string( const char* s, std::uint32_t len ) {
        if ( !s || !len ) return true;
        static const char* bad[] = { "to be", "def", "oem", "syst", "applic", "none", "0000", "1234" };
        for ( auto* pat : bad ) {
            for ( std::uint32_t p = 0; p < len; ++p ) {
                const char* c = s + p;
                int j = 0;
                while ( pat[j] && p + j < len && ( (unsigned char)c[j] | 32 ) == (unsigned char)( pat[j] | 32 ) ) ++j;
                if ( !pat[j] ) return true;
            }
        }
        return false;
    }

    static bool is_mutable( const char* s, std::uint32_t len ) {
        if ( !s || len < 4 || is_default_string( s, len ) ) return false;
        for ( std::uint32_t i = 0; i < len; ++i )
            if ( s[i] != ' ' && s[i] != '\t' && s[i] != '-' && s[i] != '_' ) return true;
        return false;
    }

    static std::uint32_t hash_bytes( const std::uint8_t* buf, std::uint32_t len, std::uint32_t salt ) {
        std::uint32_t h = 2166136261u ^ salt;
        if ( buf && len ) for ( std::uint32_t i = 0; i < len; ++i ) { h ^= buf[i]; h *= 16777619u; }
        return h ? h : ( 0x9E3779B9u ^ salt );
    }


    static bool randomize_serial( char* s, std::uint32_t len, std::uint32_t salt ) {
        if ( !is_mutable( s, len ) ) return false;
        std::uint32_t seed = hash_bytes( reinterpret_cast<std::uint8_t*>( s ), len, salt ) ^ s_rng_seed;
        bool changed = false;
        for ( std::uint32_t i = 0; i < len; ++i ) {
            char c = s[i];
            seed = seed * 0x343fdu + 0x269ec3u;
            const std::uint8_t r = static_cast<std::uint8_t>( seed >> 16 );
            if      ( c >= '0' && c <= '9' ) { s[i] = static_cast<char>( '0' + r % 10 );  changed = true; }
            else if ( c >= 'A' && c <= 'Z' ) { s[i] = static_cast<char>( 'A' + r % 26 );  changed = true; }
            else if ( c >= 'a' && c <= 'z' ) { s[i] = static_cast<char>( 'a' + r % 26 );  changed = true; }

        }
        return changed;
    }


    static bool randomize_uuid( std::uint8_t* uuid, std::uint32_t salt ) {
        bool all_zero = true, all_ff = true;
        for ( int i = 0; i < 16; ++i ) { all_zero = all_zero && !uuid[i]; all_ff = all_ff && uuid[i] == 0xffu; }
        if ( all_zero || all_ff ) return false;
        std::uint32_t seed = hash_bytes( uuid, 16, salt ) ^ s_rng_seed;
        for ( int i = 0; i < 16; ++i ) {
            seed = seed * 0x343fdu + 0x269ec3u;
            uuid[i] = static_cast<std::uint8_t>( seed >> 16 );
        }
        uuid[6] = static_cast<std::uint8_t>( ( uuid[6] & 0x0Fu ) | 0x40u );
        uuid[8] = static_cast<std::uint8_t>( ( uuid[8] & 0x3Fu ) | 0x80u );
        return true;
    }

    static std::uint32_t modify_table( std::uint8_t* table, std::uint32_t length ) {
        std::uint32_t patched = 0;
        for ( auto* cur = table; cur < table + length; ) {
            auto* hdr = reinterpret_cast<SMBIOS_HEADER*>( cur );
            if ( hdr->Length < sizeof( SMBIOS_HEADER ) || cur + hdr->Length > table + length ) break;
            if ( hdr->Type == 127 ) break;

            if ( hdr->Type == 1 && hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE1, SerialNumber ) + 1 ) ) {
                auto* t1 = reinterpret_cast<SMBIOS_TYPE1*>( hdr );
                std::uint32_t slen = 0;
                char* sv = get_string_at( hdr, table + length, t1->SerialNumber, &slen );
                if ( sv ) patched += randomize_serial( sv, slen, 0x1103u + hdr->Handle ) ? 1u : 0u;
                if ( hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE1, UUID ) + 16 ) )
                    patched += randomize_uuid( t1->UUID, 0x1104u + hdr->Handle ) ? 1u : 0u;
            } else if ( hdr->Type == 2 && hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE2, SerialNumber ) + 1 ) ) {
                auto* t2 = reinterpret_cast<SMBIOS_TYPE2*>( hdr );
                std::uint32_t slen = 0;
                char* sv = get_string_at( hdr, table + length, t2->SerialNumber, &slen );
                if ( sv ) patched += randomize_serial( sv, slen, 0x1203u + hdr->Handle ) ? 1u : 0u;
            } else if ( hdr->Type == 3 && hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE3, SerialNumber ) + 1 ) ) {
                auto* t3 = reinterpret_cast<SMBIOS_TYPE3*>( hdr );
                std::uint32_t slen = 0;
                char* sv = get_string_at( hdr, table + length, t3->SerialNumber, &slen );
                if ( sv ) patched += randomize_serial( sv, slen, 0x1302u + hdr->Handle ) ? 1u : 0u;
                if ( hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE3, AssetTag ) + 1 ) ) {
                    std::uint32_t alen = 0;
                    char* av = get_string_at( hdr, table + length, t3->AssetTag, &alen );
                    if ( av ) patched += randomize_serial( av, alen, 0x1304u + hdr->Handle ) ? 1u : 0u;
                }
            } else if ( hdr->Type == 17 && hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE17, SerialNumber ) + 1 ) ) {
                auto* t17 = reinterpret_cast<SMBIOS_TYPE17*>( hdr );
                std::uint32_t slen = 0;
                char* sv = get_string_at( hdr, table + length, t17->SerialNumber, &slen );
                if ( sv ) patched += randomize_serial( sv, slen, 0x1118u + hdr->Handle ) ? 1u : 0u;
            }

            auto* eos = cur + hdr->Length;
            while ( eos < table + length - 1 && ( *eos || *( eos + 1 ) ) ) ++eos;
            if ( eos >= table + length - 1 ) break;
            cur = eos + 2;
        }
        return patched;
    }



    static void patch_physical() {
        const auto phys_addr_va = pdb::get_symbol_address( "WmipSMBiosTablePhysicalAddress" );
        const auto length_va    = pdb::get_symbol_address( "WmipSMBiosTableLength" );
        if ( !phys_addr_va || !length_va ) {
            logging::print( "smbios: WmipSMBiosTablePhysicalAddress/Length not found in PDB" );
            return;
        }

        const std::uint64_t phys_addr = kread_val<std::uint64_t>( phys_addr_va );
        const std::uint32_t table_len = kread_val<std::uint32_t>( length_va );
        if ( !phys_addr || !table_len || table_len > 0x100000 ) {
            logging::print( "smbios: invalid SMBIOS physical addr=0x%llx len=%u", phys_addr, table_len );
            return;
        }

        logging::print( "smbios: table pa=0x%llx len=%u", phys_addr, table_len );

        std::vector<std::uint8_t> buf( table_len );
        if ( !driver::read_physical_memory( phys_addr, buf.data(), table_len ) ) {
            logging::print( "smbios: failed to read physical table" );
            return;
        }

        const std::uint32_t patched = modify_table( buf.data(), table_len );
        if ( patched ) {
            driver::write_physical_memory( phys_addr, buf.data(), table_len );
            logging::print( "smbios: physical table patched (%u fields)", patched );
        }
    }



    static void patch_registry() {
        HKEY hk = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE,
             L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
             0, KEY_READ | KEY_WRITE, &hk ) != ERROR_SUCCESS ) {
            logging::print( "smbios: mssmbios registry key not accessible" );
            return;
        }

        DWORD sz = 0, type = 0;
        RegQueryValueExW( hk, L"SMBiosData", nullptr, nullptr, nullptr, &sz );
        if ( !sz ) { RegCloseKey( hk ); return; }

        std::vector<std::uint8_t> buf( sz );
        if ( RegQueryValueExW( hk, L"SMBiosData", nullptr, &type, buf.data(), &sz ) != ERROR_SUCCESS
             || type != REG_BINARY || sz < 8 ) {
            RegCloseKey( hk ); return;
        }

        const std::uint32_t table_len = *reinterpret_cast<std::uint32_t*>( &buf[4] );
        if ( table_len + 8 <= sz ) {
            const std::uint32_t patched = modify_table( &buf[8], table_len );
            if ( patched ) {
                RegSetValueExW( hk, L"SMBiosData", 0, REG_BINARY, buf.data(), sz );
                logging::print( "smbios: registry SMBiosData patched (%u fields)", patched );
            }
        }
        RegCloseKey( hk );
    }



    inline void install() {
        patch_physical();
        patch_registry();
    }

}
