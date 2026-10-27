#pragma once
#include "helpers.hxx"

namespace spoof::uuid_cache {
    using namespace helpers;

    static std::uint64_t locate_node_va( std::uint64_t fn_va ) {
        if ( !fn_va ) return 0;

        std::uint8_t body[ 0x300 ] = {};
        if ( !kread( fn_va, body, sizeof( body ) ) ) return 0;

        for ( std::uint32_t i = 0; i + 7 <= sizeof( body ); ++i ) {
            if ( body[ i ] == 0x0F && body[ i + 1 ] == 0xB7 && body[ i + 2 ] == 0x05 ) {
                std::int32_t disp = *reinterpret_cast<const std::int32_t*>( body + i + 3 );

                std::uint64_t word_va = ( fn_va + i + 7 ) + static_cast<std::int64_t>( disp );
                return word_va - 4;
            }
        }
        return 0;
    }

    inline void install( const std::uint8_t mac[ 6 ] ) {
        const std::uint64_t fn_va = pdb::get_symbol_address( "NtAllocateUuids" );
        if ( !fn_va ) {
            logging::print( "uuid_cache: NtAllocateUuids not found in PDB" );
            return;
        }

        const std::uint64_t node_va = locate_node_va( fn_va );
        if ( !node_va ) {
            logging::print( "uuid_cache: UUID node pattern not found in NtAllocateUuids" );
            return;
        }

        std::uint8_t old_node[ 6 ] = {};
        kread( node_va, old_node, 6 );
        logging::print( "uuid_cache: node at 0x%llx cur=%02X:%02X:%02X:%02X:%02X:%02X",
            node_va,
            old_node[0], old_node[1], old_node[2], old_node[3], old_node[4], old_node[5] );

        kwrite( node_va, mac, 6 );

        logging::print( "uuid_cache: patched to %02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
    }

}
