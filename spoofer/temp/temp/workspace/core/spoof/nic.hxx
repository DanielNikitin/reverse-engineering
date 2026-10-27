#pragma once
#include "helpers.hxx"
#include "../../../impl/pdb_offsets.hxx"

namespace spoof::nic {

    using namespace helpers;

    struct ndis_off_t {
        std::uint64_t miniport_list_rva  = 0;
        std::uint64_t wpp_cb_rva         = 0;
        std::uint32_t mp_next_global     = 0;
        std::uint32_t mp_physical_medium = 0;
        std::uint32_t mp_eth_db          = 0;
        std::uint32_t mp_adapter_ctx     = 0;
        std::uint32_t mp_if_avail        = 0;
        std::uint32_t mp_if_block        = 0;
        std::uint32_t ifb_cur            = 0;
        std::uint32_t ifb_perm           = 0;
        std::uint32_t ifb_family         = 0;
        std::uint32_t pa_length          = 0;
        std::uint32_t pa_address         = 0;
        std::uint32_t ethdb_addr         = 0;
        bool     valid              = false;
    };

    static ndis_off_t s_off;
    static std::uint8_t s_first_mac[6];

    static bool mac_is_set( const std::uint8_t mac[6] ) {
        return mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5];
    }

    static bool same_oui( const std::uint8_t a[6], const std::uint8_t b[6] ) {
        return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
    }

    static void resolve_offsets() {
        loader_offsets::ndis_offsets ndis{};
        if ( !pdb_offsets::resolve_ndis( &ndis ) ) {
            logging::print( "nic: NDIS offset resolution failed" );
            return;
        }
        const std::uint64_t ndis_base = helpers::get_kernel_module_base( L"ndis.sys" );
        if ( !ndis_base ) {
            logging::print( "nic: could not find ndis.sys kernel base" );
            return;
        }
        s_off.miniport_list_rva  = ndis_base + ndis.miniport_list_rva;
        s_off.wpp_cb_rva         = ndis_base + ndis.wpp_main_cb_rva;
        s_off.mp_next_global     = ndis.mp_next_global;
        s_off.mp_physical_medium = ndis.mp_physical_medium;
        s_off.mp_eth_db          = ndis.mp_eth_db;
        s_off.mp_adapter_ctx     = ndis.mp_adapter_ctx;
        s_off.mp_if_avail        = ndis.mp_if_avail;
        s_off.mp_if_block        = ndis.mp_if_block;
        s_off.ifb_cur            = ndis.ifb_cur_phys_addr;
        s_off.ifb_perm           = ndis.ifb_perm_phys_addr;
        s_off.ifb_family         = ndis.ifb_family_entry;
        s_off.pa_length          = ndis.pa_length;
        s_off.pa_address         = ndis.pa_address;
        s_off.ethdb_addr         = ndis.ethdb_adapter_addr;
        s_off.valid              = true;
        logging::print( "nic: ndis.sys offsets: mp_next=0x%x mp_ethdb=0x%x mp_ifblock=0x%x ifb_cur=0x%x ifb_perm=0x%x ethdb_addr=0x%x",
            s_off.mp_next_global, s_off.mp_eth_db, s_off.mp_if_block,
            s_off.ifb_cur, s_off.ifb_perm, s_off.ethdb_addr );
    }

    static void generate_mac( std::uint8_t mac[6], const std::uint8_t* old_mac ) {
        FILETIME ft{}; GetSystemTimeAsFileTime( &ft );
        std::uint64_t seed = (std::uint64_t)ft.dwLowDateTime ^ ( (std::uint64_t)ft.dwHighDateTime << 32 );
        seed = (seed ^ (seed>>30)) * 0xbf58476d1ce4e5b9ULL;
        seed = (seed ^ (seed>>27)) * 0x94d049bb133111ebULL;
        seed ^= seed >> 31;

        if ( old_mac && ( old_mac[0] || old_mac[1] || old_mac[2] ) ) {
            mac[0] = old_mac[0];
            mac[1] = old_mac[1];
            mac[2] = old_mac[2];
        } else {
            mac[0] = 0x02;
            mac[1] = (std::uint8_t)( seed >> 8 );
            mac[2] = (std::uint8_t)( seed >> 16 );
        }
        mac[3] = (std::uint8_t)( seed >> 24 );
        mac[4] = (std::uint8_t)( seed >> 32 );
        mac[5] = (std::uint8_t)( seed >> 40 );
    }

static void patch_phys_addr( std::uint64_t ifb_va, std::uint32_t field_off, const std::uint8_t mac[6] ) {
        if ( !s_off.pa_address ) return;
        const std::uint16_t len = kread_val<std::uint16_t>( ifb_va + field_off + s_off.pa_length );
        if ( len == 6 )
            kwrite( ifb_va + field_off + s_off.pa_address, mac, 6 );
    }

    static void patch_miniport( std::uint64_t mp_va, const std::uint8_t mac[6] ) {

        if ( s_off.mp_if_avail && s_off.mp_if_block ) {
            const std::uint32_t avail = kread_val<std::uint32_t>( mp_va + s_off.mp_if_avail );
            if ( avail ) {
                const std::uint64_t ifb = kread_val<std::uint64_t>( mp_va + s_off.mp_if_block );
                if ( is_kva(ifb) ) {
                    if ( s_off.ifb_cur  ) patch_phys_addr( ifb, s_off.ifb_cur,  mac );
                    if ( s_off.ifb_perm ) patch_phys_addr( ifb, s_off.ifb_perm, mac );
                }
            }
        }

        logging::print( "nic: miniport 0x%llx MAC patched %02X:%02X:%02X:%02X:%02X:%02X",
            mp_va, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5] );
    }

    static std::uint32_t walk_miniport_list() {
        if ( !is_kva( s_off.miniport_list_rva ) ) return 0;


        const std::uint64_t mp_head_va = kread_val<std::uint64_t>( s_off.miniport_list_rva );
        if ( !is_kva( mp_head_va ) ) {
            logging::print( "nic: miniport list head is null or invalid (0x%llx)", mp_head_va );
            return 0;
        }

        std::uint32_t count = 0;
        std::uint64_t mp = mp_head_va;

        for ( std::uint32_t i = 0; i < 64 && is_kva(mp); ++i ) {
            const std::uint64_t ethdb = s_off.mp_eth_db ? kread_val<std::uint64_t>( mp + s_off.mp_eth_db ) : 0;
            logging::print( "nic: mp[%u]=0x%llx ethdb=0x%llx", i, mp, ethdb );

            if ( is_kva(ethdb) ) {
                std::uint8_t old_mac[6] = {};
                if ( s_off.ethdb_addr ) kread( ethdb + s_off.ethdb_addr, old_mac, 6 );
                std::uint8_t new_mac[6] = {};
                generate_mac( new_mac, old_mac );
                if ( count == 0 ) memcpy( s_first_mac, new_mac, 6 );
                patch_miniport( mp, new_mac );
                ++count;
            }

            if ( !s_off.mp_next_global ) break;
            mp = kread_val<std::uint64_t>( mp + s_off.mp_next_global );
        }
        return count;
    }

    static constexpr std::uint32_t kWppFamilyHeadOff = 0x128;

    static std::uint32_t walk_ifblock_family() {
        if ( !s_off.wpp_cb_rva || !s_off.ifb_family ) return 0;

        const std::uint64_t sentinel_va = s_off.wpp_cb_rva + kWppFamilyHeadOff;
        const std::uint64_t sentinel_flink = kread_val<std::uint64_t>( sentinel_va );
        const std::uint64_t sentinel_blink = kread_val<std::uint64_t>( sentinel_va + 8 );
        if ( !is_kva(sentinel_flink) || !is_kva(sentinel_blink) ) return 0;

        logging::print( "nic: ifblock sentinel=0x%llx flink=0x%llx", sentinel_va, sentinel_flink );

        std::uint32_t count = 0;
        std::uint64_t entry = sentinel_flink;
        for ( std::uint32_t i = 0; i < 128 && is_kva(entry) && entry != sentinel_va; ++i ) {
            const std::uint64_t ifb_va = entry - s_off.ifb_family;
            const std::uint64_t next   = kread_val<std::uint64_t>( entry );

            if ( s_off.ifb_cur && s_off.pa_address ) {
                const std::uint16_t cur_len = kread_val<std::uint16_t>( ifb_va + s_off.ifb_cur + s_off.pa_length );
                if ( cur_len == 6 ) {
                    std::uint8_t old_mac[6] = {};
                    kread( ifb_va + s_off.ifb_cur + s_off.pa_address, old_mac, 6 );
                    std::uint8_t new_mac[6] = {};

                    if ( mac_is_set( s_first_mac ) && same_oui( old_mac, s_first_mac ) ) {
                        memcpy( new_mac, s_first_mac, 6 );
                    } else {
                        generate_mac( new_mac, old_mac );
                    }

                    kwrite( ifb_va + s_off.ifb_cur  + s_off.pa_address, new_mac, 6 );
                    if ( s_off.ifb_perm ) {
                        const std::uint16_t perm_len = kread_val<std::uint16_t>( ifb_va + s_off.ifb_perm + s_off.pa_length );
                        if ( perm_len == 6 )
                            kwrite( ifb_va + s_off.ifb_perm + s_off.pa_address, new_mac, 6 );
                    }
                    ++count;
                }
            }

            entry = next;
        }
        return count;
    }

    static void flush_arp_cache() {

        HMODULE hLib = LoadLibraryA( "iphlpapi.dll" );
        if ( !hLib ) return;


        using FlushIpNetTable2_t = DWORD( __stdcall* )( USHORT, ULONG );
        auto fn = reinterpret_cast<FlushIpNetTable2_t>(
            GetProcAddress( hLib, "FlushIpNetTable2" ) );

        if ( fn ) {

            const DWORD r = fn( 0, 0 );
            logging::print( "nic: ARP/neighbor cache flushed (status=%u)", r );
        }
        FreeLibrary( hLib );
    }

    inline void install() {
        resolve_offsets();
        if ( !s_off.valid ) {
            logging::print( "nic: NDIS offset resolution failed, skipping NIC spoof" );
            return;
        }

        const std::uint32_t mp_count  = walk_miniport_list();
        const std::uint32_t ifb_count = walk_ifblock_family();
        logging::print( "nic: patched %u miniport(s), %u IF_BLOCK(s)", mp_count, ifb_count );

        flush_arp_cache();
    }

}
