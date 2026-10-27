#include "core.hpp"
#include "../hde/hde64.h"

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

static const char* const k_bn_sigs[] = {
	"48 8B 89 ? ? ? ? 48 8B ? ? ? ? ? 48 8B 49 ? E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 8B 53 ? 45 33 C0 48 8B C8",
	"48 8B 89 ? ? ? ? 48 8B ? ? ? ? ? 48 8B 49 ? E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? ? ? ? ? 45 33 C0",
};

bool c_core::resolve_bn_chain( )
{
	std::uintptr_t bn_match = 0;
	for ( const char* sig : k_bn_sigs )
	{
		bn_match = c_scanner::scan_image( sig );
		if ( bn_match ) break;
	}
	if ( !bn_match )
	{
		std::printf( "[rust-dumper] bn chain: signature not found\n" );
		return false;
	}

	c_scanner::scan_buf_t s{ };
	if ( !c_scanner::read_scan( bn_match, 0x80, s ) )
		return false;

	std::uint32_t off = 0;
	std::int32_t disp = 0;
	std::uintptr_t resolved = 0;

	if ( !c_scanner::find_mov_base( s, 0, 1, 1, off, disp ) ) return false;

	if ( !c_scanner::find_mov_base( s, off + 1, 1, 1, off, disp ) ) return false;

	if ( !c_scanner::find_call( s, off, 1, off, resolved ) ) return false;
	m_bn.decrypt_0_addr = resolved;

	std::uintptr_t get_player_list = 0;
	if ( !c_scanner::find_call( s, off + 5, 1, off, get_player_list ) ) return false;

	c_scanner::scan_buf_t fn_buf{ };
	if ( !c_scanner::read_scan( get_player_list, 0x300, fn_buf ) ) return false;

	if ( !c_scanner::find_mov_base( fn_buf, 0, 7, 1, off, disp ) ) return false;

	if ( !c_scanner::find_call( fn_buf, off, 1, off, resolved ) ) return false;
	m_bn.decrypt_1_addr = resolved;

	m_bn.decrypt_0 = c_decryption::extract_loop( ( std::uint8_t* )m_bn.decrypt_0_addr, 0x200 );
	if ( !m_bn.decrypt_0.valid )
		m_bn.decrypt_0 = c_decryption::extract_inline( ( std::uint8_t* )m_bn.decrypt_0_addr, 0x200 );

	m_bn.decrypt_1 = c_decryption::extract_loop( ( std::uint8_t* )m_bn.decrypt_1_addr, 0x200 );
	if ( !m_bn.decrypt_1.valid )
		m_bn.decrypt_1 = c_decryption::extract_inline( ( std::uint8_t* )m_bn.decrypt_1_addr, 0x200 );

	auto bn_outer = c_runtime::find_class( "BaseNetworkable" );
	auto bn_static = c_runtime::get_inner_static_class( bn_outer );
	if ( bn_static )
		m_bn.base_networkable_rva = c_runtime::static_class_rva( bn_static );

	if ( bn_static )
	{
		auto client_entities = il2cpp::get_static_field_if_value_is<void*>(
			bn_static, "BaseNetworkable", FIELD_ATTRIBUTE_PUBLIC, 0,
			[]( void* p ) { return p != nullptr; } );
		if ( !client_entities )
			client_entities = il2cpp::get_field_if_type_contains(
				bn_static, "BaseNetworkable", FIELD_ATTRIBUTE_PUBLIC, FIELD_ATTRIBUTE_STATIC );

		if ( client_entities )
		{
			m_bn.wrapper_class_ptr = ( std::uint32_t )client_entities->offset( );

			auto t = client_entities->type( );
			if ( t && t->klass( ) )
			{
				auto entity_realm_class = t->klass( )->get_generic_argument_at( 0 );
				if ( entity_realm_class )
				{
					auto entity_list = il2cpp::get_field_if_type_contains(
						entity_realm_class, "BaseNetworkable" );
					if ( entity_list )
					{
						m_bn.parent_static_fields = ( std::uint32_t )entity_list->offset( );

						auto el_type = entity_list->type( );
						auto el_wrapper_klass = el_type ? el_type->klass( ) : nullptr;
						auto list_dictionary_klass = el_wrapper_klass
							? el_wrapper_klass->get_generic_argument_at( 0 )
							: nullptr;

						if ( list_dictionary_klass )
						{
							auto buffer_list_field = il2cpp::get_field_if_type_contains(
								list_dictionary_klass, "BufferList" );
							if ( !buffer_list_field )
								buffer_list_field = il2cpp::get_field_if_type_contains(
									list_dictionary_klass, "BaseNetworkable" );
							if ( buffer_list_field )
								m_bn.entities = ( std::uint32_t )buffer_list_field->offset( );
						}
					}
				}
			}
		}
	}

	if ( !m_bn.entities )
		m_bn.entities = 0x10;

	return true;
}

bool c_core::resolve_camera_chain( )
{
	auto main_camera = c_runtime::find_class( "MainCamera" );
	if ( !main_camera )
	{
		std::printf( "[rust-dumper] camera: MainCamera class not found\n" );
		return false;
	}

	auto parent = main_camera->parent( );
	il2cpp::il2cpp_class_t* singleton = parent ? parent->parent( ) : nullptr;

	std::uint64_t rva = c_runtime::static_class_rva( main_camera );
	if ( !rva && singleton )
		rva = c_runtime::static_class_rva( singleton );
	m_camera.main_camera_c = rva;

	il2cpp::field_info_t* main_camera_field = il2cpp::get_static_field_if_value_is<unity::component_t*>(
		main_camera, "UnityEngine.Camera", FIELD_ATTRIBUTE_PUBLIC, 0,
		[]( unity::component_t* camera ) { return camera != nullptr; } );

	if ( main_camera_field )
	{
		m_camera.camera_object = main_camera_field->offset( );
		std::printf( "[rust-dumper] camera_object = 0x%X\n", m_camera.camera_object );
	}
	else
	{
		std::printf( "[rust-dumper] camera_object: MainCamera.mainCamera is null (load into a server first)\n" );
	}

	return m_camera.main_camera_c != 0;
}

static bool is_valid_userland_ptr( std::uintptr_t p )
{
	return p > 0x10000 && p < 0x7FFFFFFFFFFFull && !IsBadReadPtr( ( void* )p, 8 );
}

void c_core::verify_bn_chain( )
{
	if ( !m_bn.base_networkable_rva || !m_bn.decrypt_0.valid || !m_bn.decrypt_1.valid )
	{
		std::printf( "[verify] bn_chain: static dump incomplete, skipping\n" );
		return;
	}

	using gchandle_fn_t = void* ( * )( std::uint32_t );
	auto gchandle_get_target = ( gchandle_fn_t )GetProcAddress(
		GetModuleHandleA( "GameAssembly.dll" ), "il2cpp_gchandle_get_target" );
	if ( !gchandle_get_target )
	{
		std::printf( "[verify] bn_chain: gchandle_get_target unavailable\n" );
		return;
	}

	auto game_base = c_runtime::game_base( );
	auto klass = *( std::uintptr_t* )( game_base + m_bn.base_networkable_rva );
	if ( !is_valid_userland_ptr( klass ) )
	{
		std::printf( "[verify] bn_chain: base_networkable klass invalid\n" );
		return;
	}

	auto static_fields = *( std::uintptr_t* )( klass + 0xB8 );
	if ( !is_valid_userland_ptr( static_fields ) )
	{
		std::printf( "[verify] bn_chain: static_fields invalid\n" );
		return;
	}

	auto decrypt_via_chain = [&]( std::uintptr_t wrapper_ptr, const c_decryption::constants_t& c ) -> std::uintptr_t
	{
		if ( !is_valid_userland_ptr( wrapper_ptr + 0x18 ) )
			return 0;
		auto encrypted = *( std::uint64_t* )( wrapper_ptr + 0x18 );
		auto decrypted = c_decryption::simulate( encrypted, c );
		auto handle = ( std::uint32_t )decrypted;
		if ( handle == 0 || handle > 0x1000000 )
			return 0;
		__try
		{
			return ( std::uintptr_t )gchandle_get_target( handle );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER )
		{
			return 0;
		}
	};

	auto check_buffer_list = []( std::uintptr_t list ) -> std::int32_t
	{
		if ( !is_valid_userland_ptr( list ) )
			return -1;
		auto array = *( std::uintptr_t* )( list + 0x10 );
		auto size  = *( std::int32_t* )( list + 0x18 );
		if ( !is_valid_userland_ptr( array ) ) return -1;
		if ( size < 0 || size > 50000 ) return -1;
		return size;
	};

	std::printf( "[verify] walking chain: klass=0x%llX sf=0x%llX\n", klass, static_fields );

	struct candidate_t { std::uint32_t wrapper, parent, entities; std::int32_t size; };
	std::vector<candidate_t> hits;

	for ( std::uint32_t wrapper_off = 0; wrapper_off <= 0x100; wrapper_off += 8 )
	{
		auto wrapper_ptr = *( std::uintptr_t* )( static_fields + wrapper_off );
		if ( !is_valid_userland_ptr( wrapper_ptr ) )
			continue;

		auto entity_realm = decrypt_via_chain( wrapper_ptr, m_bn.decrypt_0 );
		if ( !is_valid_userland_ptr( entity_realm ) )
			continue;

		for ( std::uint32_t parent_off = 0; parent_off <= 0x100; parent_off += 8 )
		{
			auto parent_ptr = *( std::uintptr_t* )( entity_realm + parent_off );
			if ( !is_valid_userland_ptr( parent_ptr ) )
				continue;

			auto list_dict = decrypt_via_chain( parent_ptr, m_bn.decrypt_1 );
			if ( !is_valid_userland_ptr( list_dict ) )
				continue;

			for ( std::uint32_t ent_off = 0; ent_off <= 0x100; ent_off += 8 )
			{
				auto buffer_list = *( std::uintptr_t* )( list_dict + ent_off );
				auto sz = check_buffer_list( buffer_list );
				if ( sz < 0 )
					continue;

				hits.push_back( { wrapper_off, parent_off, ent_off, sz } );
				std::printf( "[verify]   hit wrapper=0x%X parent=0x%X entities=0x%X size=%d\n",
					wrapper_off, parent_off, ent_off, sz );
			}
		}
	}

	if ( hits.empty( ) )
	{
		std::printf( "[verify] bn_chain: NO runtime hits (game not in a server, or decrypt ops wrong)\n" );
		return;
	}

	std::printf( "[verify] static dump:   wrapper=0x%X parent=0x%X entities=0x%X\n",
		m_bn.wrapper_class_ptr, m_bn.parent_static_fields, m_bn.entities );

	bool exact_match = false;
	for ( auto& h : hits )
	{
		if ( h.wrapper == m_bn.wrapper_class_ptr &&
			h.parent  == m_bn.parent_static_fields &&
			h.entities == m_bn.entities )
		{
			exact_match = true;
			std::printf( "[verify] bn_chain: PASSED (runtime size=%d)\n", h.size );
			break;
		}
	}
	if ( !exact_match )
	{
		std::printf( "[verify] bn_chain: MISMATCH — static dump did not match any runtime hit\n" );
		std::printf( "[verify]   the runtime hits above are the correct offsets; static extraction is off\n" );
	}
}

void c_core::verify_camera_chain( )
{
	auto game_base = c_runtime::game_base( );
	auto hits = c_verification::bruteforce_camera( game_base, m_camera.main_camera_c );

	if ( hits.empty( ) )
	{
		std::printf( "[verify] camera: no valid chain found (not in a server?)\n" );
		return;
	}

	auto& h = hits[ 0 ];
	std::printf( "[verify] camera bruteforce: static=0x%X object=0x%X entity=0x%X pos=(%.1f, %.1f, %.1f)\n",
		h.camera_static, h.camera_object, h.entity, h.pos_x, h.pos_y, h.pos_z );

	bool match = h.camera_static == m_camera.camera_static &&
		h.camera_object == m_camera.camera_object &&
		h.entity == m_camera.entity;

	if ( match )
		std::printf( "[verify] camera: PASSED\n" );
	else
	{
		std::printf( "[verify] camera: MISMATCH\n" );
		std::printf( "[verify]   dumped:  static=0x%X object=0x%X entity=0x%X\n",
			m_camera.camera_static, m_camera.camera_object, m_camera.entity );
		std::printf( "[verify]   runtime: static=0x%X object=0x%X entity=0x%X\n",
			h.camera_static, h.camera_object, h.entity );
	}
}

void c_core::verify_all( )
{
	std::printf( "\n[verify] === bruteforce verification ===\n" );

	auto game_base = c_runtime::game_base( );

	auto bn_hits = c_verification::bruteforce_bn(
		game_base, m_bn.base_networkable_rva,
		m_bn.decrypt_0, m_bn.decrypt_1, m_bn.hv_offset );

	if ( bn_hits.empty( ) )
	{
		std::printf( "[verify] bn_chain bruteforce: no hits (not in a server, or decrypt ops wrong)\n" );
	}
	else
	{
		bool found = false;
		for ( auto& h : bn_hits )
		{
			if ( h.wrapper == m_bn.wrapper_class_ptr &&
				h.parent == m_bn.parent_static_fields &&
				h.entities == m_bn.entities )
			{
				std::printf( "[verify] bn_chain bruteforce: PASSED (entities=%d)\n", h.size );
				found = true;
				break;
			}
		}
		if ( !found )
		{
			std::printf( "[verify] bn_chain bruteforce: MISMATCH\n" );
			std::printf( "[verify]   dumped:  wrapper=0x%X parent=0x%X entities=0x%X\n",
				m_bn.wrapper_class_ptr, m_bn.parent_static_fields, m_bn.entities );
			for ( auto& h : bn_hits )
				std::printf( "[verify]   runtime: wrapper=0x%X parent=0x%X entities=0x%X size=%d\n",
					h.wrapper, h.parent, h.entities, h.size );
		}
	}

	verify_camera_chain( );

	std::printf( "[verify] === done ===\n\n" );
}

static rust::console_system::command* safe_find_command( system_c::string_t* str )
{
	__try { return rust::console_system::client::find( str ); }
	__except ( EXCEPTION_EXECUTE_HANDLER ) { return nullptr; }
}

static std::uint64_t safe_get_setter( rust::console_system::command* cmd )
{
	__try { return cmd->set( ); }
	__except ( EXCEPTION_EXECUTE_HANDLER ) { return 0; }
}

void c_core::resolve_fov_encryption( )
{
	if ( !rust::console_system::console_system_index_client_find )
	{
		std::printf( "[rust-dumper] fov: console_system_index_client_find is null\n" );
		return;
	}
	if ( rust::console_system::set_override_offset == 0 )
	{
		std::printf( "[rust-dumper] fov: set_override_offset is 0\n" );
		return;
	}

	auto str = system_c::string_t::create_string( L"graphics.fov" );
	if ( !str )
	{
		std::printf( "[rust-dumper] fov: create_string failed\n" );
		return;
	}

	auto cmd = safe_find_command( str );
	if ( !cmd )
	{
		std::printf( "[rust-dumper] fov: client::find returned null or crashed\n" );
		return;
	}

	auto setter = safe_get_setter( cmd );
	if ( !setter )
	{
		std::printf( "[rust-dumper] fov: cmd->set() returned 0\n" );
		return;
	}

	auto fn = ( std::uint8_t* )setter;
	if ( IsBadReadPtr( fn, 0x100 ) )
	{
		std::printf( "[rust-dumper] fov: setter fn unreadable\n" );
		return;
	}

	auto try_extract = []( std::uint8_t* p ) -> c_decryption::constants_t
	{
		return c_decryption::extract_inline( p, 0x100 );
	};

	auto is_entity_decrypt = [&]( const c_decryption::constants_t& c ) -> bool
	{
		if ( c.was_unrolled )
			return true;
		if ( m_bn.decrypt_0.valid && c_decryption::ops_match( c, m_bn.decrypt_0 ) )
			return true;
		if ( m_bn.decrypt_1.valid && c_decryption::ops_match( c, m_bn.decrypt_1 ) )
			return true;
		return false;
	};

	struct fov_candidate_t
	{
		c_decryption::constants_t constants;
		std::uint8_t* fn_addr;
	};
	std::vector<fov_candidate_t> candidates;

	auto direct = try_extract( fn );
	if ( direct.valid && !is_entity_decrypt( direct ) )
		candidates.push_back( { direct, fn } );

	std::uint8_t* p = fn;
	std::uint8_t* end = fn + 0x200;
	while ( p < end )
	{
		hde64s hs;
		auto len = hde64_disasm( p, &hs );
		if ( !len || ( hs.flags & F_ERROR ) )
			break;
		if ( hs.opcode == 0xC3 || hs.opcode == 0xCC )
			break;

		if ( p[ 0 ] == 0xE8 && len >= 5 )
		{
			std::int32_t d;
			std::memcpy( &d, p + 1, 4 );
			auto target = p + 5 + d;

			if ( !IsBadReadPtr( target, 0x100 ) &&
				( std::uintptr_t )target != m_bn.decrypt_0_addr &&
				( std::uintptr_t )target != m_bn.decrypt_1_addr )
			{
				auto cc = try_extract( target );
				if ( cc.valid && !is_entity_decrypt( cc ) )
					candidates.push_back( { cc, target } );

				if ( !cc.valid )
				{
					std::uint8_t* inner = target;
					std::uint8_t* inner_end = target + 0x100;
					while ( inner < inner_end )
					{
						hde64s ihs;
						auto ilen = hde64_disasm( inner, &ihs );
						if ( !ilen || ( ihs.flags & F_ERROR ) ) break;
						if ( ihs.opcode == 0xC3 || ihs.opcode == 0xCC ) break;

						if ( inner[ 0 ] == 0xE8 && ilen >= 5 )
						{
							std::int32_t id;
							std::memcpy( &id, inner + 1, 4 );
							auto inner_target = inner + 5 + id;
							if ( !IsBadReadPtr( inner_target, 0x100 ) &&
								( std::uintptr_t )inner_target != m_bn.decrypt_0_addr &&
								( std::uintptr_t )inner_target != m_bn.decrypt_1_addr )
							{
								auto ic = try_extract( inner_target );
								if ( ic.valid && !is_entity_decrypt( ic ) )
									candidates.push_back( { ic, inner_target } );
							}
						}
						inner += ilen;
					}
				}
			}
		}
		p += len;
	}

	if ( candidates.empty( ) )
	{
		std::printf( "[rust-dumper] fov: no valid candidates found\n" );
		return;
	}

	for ( std::size_t i = 0; i < candidates.size( ); i++ )
	{
		auto& c = candidates[ i ];
		std::printf( "[rust-dumper] fov candidate %zu: rva=0x%llX ops=%d unrolled=%d\n",
			i, ( std::uintptr_t )c.fn_addr - c_runtime::game_base( ), c.constants.op_count, c.constants.was_unrolled );
		for ( int j = 0; j < c.constants.op_count; j++ )
			std::printf( "[rust-dumper]   op[%d] %s 0x%X\n", j,
				c_decryption::op_name( c.constants.ops[ j ].type ), c.constants.ops[ j ].value );
	}

	auto* best = &candidates.back( );
	for ( auto it = candidates.rbegin( ); it != candidates.rend( ); ++it )
	{
		if ( it->constants.op_count == 4 && !it->constants.was_unrolled )
		{
			best = &( *it );
			break;
		}
	}

	m_fov_fn_addr = ( std::uintptr_t )best->fn_addr;
	m_fov_constants = best->constants;

	std::printf( "[rust-dumper] fov: extracted %d ops from rva 0x%llX (%zu candidates)\n",
		m_fov_constants.op_count, m_fov_fn_addr - c_runtime::game_base( ), candidates.size( ) );
	for ( int i = 0; i < m_fov_constants.op_count; i++ )
		std::printf( "[rust-dumper] fov:   op[%d] %s 0x%X\n", i,
			c_decryption::op_name( m_fov_constants.ops[ i ].type ), m_fov_constants.ops[ i ].value );
}

void c_core::resolve_item_classes( )
{
	auto player_loot = c_runtime::find_class( "PlayerLoot" );
	if ( !player_loot )
	{
		std::printf( "[rust-dumper] resolve_item_classes: PlayerLoot not found\n" );
		return;
	}

	auto entity_source = c_runtime::find_field( player_loot, "entitySource" );
	if ( entity_source )
	{
		auto item_field = il2cpp::get_field_by_offset( player_loot, entity_source->offset( ) + 0x8 );
		m_item_class = item_field ? item_field->type( )->klass( ) : nullptr;
	}

	if ( m_item_class )
	{
		auto base_entity = c_runtime::find_class( "BaseEntity" );
		if ( base_entity )
		{
			auto get_item = il2cpp::get_method_by_return_type_attrs(
				NO_FILT, base_entity, m_item_class, 0, 0, 1 );
			if ( get_item )
			{
				auto p = get_item->get_param( 0 );
				m_item_id_class = p ? p->klass( ) : nullptr;
			}
		}
	}

	auto containers_field = il2cpp::get_field_by_name( player_loot, "containers" );
	auto templated_ic = containers_field ? containers_field->type( )->klass( ) : nullptr;
	if ( templated_ic )
		m_item_container_class = templated_ic->get_generic_argument_at( 0 );

	std::printf( "[rust-dumper] resolve_item_classes: item=%p item_id=%p item_container=%p\n",
		m_item_class, m_item_id_class, m_item_container_class );
}

bool c_core::resolve_console_system( )
{
	auto display = il2cpp::search_for_class_by_method_in_assembly(
		"Facepunch.Console", "<Find>b__0", nullptr, -1 );

	if ( display )
	{
		if ( auto find_b0 = il2cpp::get_method_by_name( display, "<Find>b__0" ) )
		{
			if ( auto p = find_b0->get_param( 0 ) )
				m_console_command_class = p->klass( );
		}
	}

	if ( !m_console_command_class )
	{
		std::printf( "[rust-dumper] console: ConsoleSystem.Command not resolved\n" );
		return false;
	}

	if ( auto f = il2cpp::get_field_if_type_contains( m_console_command_class, "System.Func<System.String>" ) )
		rust::console_system::get_override_offset = f->offset( );
	if ( auto f = il2cpp::get_field_if_type_contains( m_console_command_class, "System.Action<System.String>" ) )
		rust::console_system::set_override_offset = f->offset( );
	if ( auto f = il2cpp::get_field_if_type_contains( m_console_command_class, "System.Action<%", FIELD_ATTRIBUTE_PUBLIC ) )
		rust::console_system::call_offset = f->offset( );

	auto show_if = c_runtime::find_class( "ShowIfConvarEnabled" );
	auto on_enable_filter = show_if ? il2cpp::get_method_by_name( show_if, "OnEnable" ) : nullptr;
	std::uint64_t filter_addr = on_enable_filter ? on_enable_filter->get_fn_ptr<std::uint64_t>( ) : 0;

	il2cpp::method_info_t* find_method = nullptr;
	auto str_type = il2cpp::get_class_by_name( "String", "System" );
	if ( str_type && filter_addr )
	{
		il2cpp::il2cpp_type_t* params[] = { str_type->type( ) };
		find_method = il2cpp::get_method_in_method_by_return_type_and_param_types(
			( il2cpp::il2cpp_class_t* )0x1337DEADBEEF7331ULL,
			il2cpp::method_filter_t( filter_addr, 0, 1 ),
			m_console_command_class->type( ),
			METHOD_ATTRIBUTE_PUBLIC,
			METHOD_ATTRIBUTE_STATIC,
			params, 1 );
	}

	if ( !find_method )
	{
		std::printf( "[rust-dumper] console: ConsoleSystem.Index.Client::Find not resolved\n" );
		return false;
	}

	rust::console_system::console_system_index_client_find =
		( decltype( rust::console_system::console_system_index_client_find ) )
		find_method->get_fn_ptr<std::uint64_t>( );

	std::printf( "[rust-dumper] console: command_class=%p find=%p set_off=0x%zX\n",
		m_console_command_class,
		rust::console_system::console_system_index_client_find,
		rust::console_system::set_override_offset );

	return rust::console_system::console_system_index_client_find != nullptr;
}

void c_core::write_il2cpphandle( c_writer& w )
{
	w.write_global( "il2cpphandle", m_gc_handles_rva );
}

void c_core::write_basenetworkable( c_writer& w )
{
	// The BufferList wrapper field lookup can fail when the derived list
	// type is obfuscated on newer builds — fall back to the known stable
	// offset (0x10) since Rust's server-side layout has kept it there for
	// many patches now.
	std::uint32_t parent = m_bn.parent_static_fields ? m_bn.parent_static_fields : 0x10;

	w.struct_begin( "base_networkable" );
	w.struct_field( "base_networkable",     m_bn.base_networkable_rva );
	w.struct_field( "static_fields",        0xB8 );
	w.struct_field( "wrapper_class_ptr",    m_bn.wrapper_class_ptr );
	w.struct_field( "parent_static_fields", parent );
	w.struct_field( "entities",             m_bn.entities );
	w.struct_field( "hv_offset",            m_bn.hv_offset );
	w.struct_end( );
}

void c_core::write_camera( c_writer& w )
{
	// The last four offsets below live inside Unity's native camera state,
	// not inside a managed class we can iterate.  They only change when the
	// Unity engine version changes (very rare) — hardcoding the known-good
	// values keeps the dump complete.  If a future Unity bump breaks them,
	// hand-verify against a runtime memory scan.
	w.struct_begin( "camera" );
	w.struct_field( "main_camera_c", m_camera.main_camera_c );
	w.struct_field( "camera_static", m_camera.camera_static );
	w.struct_field( "camera_object", m_camera.camera_object );
	w.struct_field( "entity",        m_camera.entity );
	w.struct_field( "view_matrix",   0x2FC, "Unity native camera state" );
	w.struct_field( "position",      0x444, "Unity native camera state" );
	w.struct_field( "field_of_view", 0x170, "Unity native camera state" );
	w.struct_field( "culling_mask",  0x3E8, "Unity native camera state" );
	w.struct_end( );
}

void c_core::write_base_player( c_writer& w )
{
	auto klass = c_runtime::find_class( "BasePlayer" );

	auto item_id_class       = m_item_id_class;
	auto player_model_klass  = c_runtime::find_class( "PlayerModel" );
	auto player_input_klass  = c_runtime::find_class( "PlayerInput" );
	auto base_movement_klass = c_runtime::find_class( "BaseMovement" );

	std::uint64_t off_cl_active_item   = 0;
	std::uint64_t off_player_eyes      = 0;
	std::uint64_t off_player_inventory = 0;
	std::uint64_t off_current_team     = 0;
	std::uint64_t off_base_movement    = 0;
	std::uint64_t off_player_model     = 0;
	std::uint64_t off_player_flags     = 0;
	std::uint64_t off_display_name     = 0;
	std::uint64_t off_player_input     = 0;

	if ( klass )
	{
		const char* item_id_name = item_id_class ? item_id_class->name( ) : "";
		if ( auto f = il2cpp::get_field_if_type_contains( klass, item_id_name ) )
			off_cl_active_item = f->offset( klass );

		if ( auto f = il2cpp::get_field_if_type_contains( klass, "PlayerEyes" ) )
			off_player_eyes = f->offset( klass );

		if ( auto f = il2cpp::get_field_if_type_contains( klass, "PlayerInventory" ) )
			off_player_inventory = f->offset( klass );

		if ( auto f = il2cpp::get_field_by_name( klass, "currentTeam" ) )
			off_current_team = f->offset( klass );

		if ( base_movement_klass )
			if ( auto f = il2cpp::get_field_from_field_type_class( klass, base_movement_klass ) )
				off_base_movement = f->offset( klass );

		if ( player_model_klass )
			if ( auto f = il2cpp::get_field_from_field_type_class( klass, player_model_klass ) )
				off_player_model = f->offset( klass );

		if ( auto f = il2cpp::get_field_by_name( klass, "playerFlags" ) )
			off_player_flags = f->offset( klass );

		if ( auto f = il2cpp::get_field_by_type_name_attrs( klass, "System.String", FIELD_ATTRIBUTE_FAMILY, 0 ) )
			off_display_name = f->offset( klass );

		if ( player_input_klass )
			if ( auto f = il2cpp::get_field_from_field_type_class( klass, player_input_klass ) )
				off_player_input = f->offset( klass );
	}

	w.struct_begin( "base_player" );
	w.struct_field( "cl_active_item",    off_cl_active_item );
	w.struct_field( "player_eyes",       off_player_eyes );
	w.struct_field( "player_inventory",  off_player_inventory );
	w.struct_field( "current_team",      off_current_team );
	w.struct_field( "base_movement",     off_base_movement );
	w.struct_field( "player_model",      off_player_model );
	w.struct_field( "player_flags",      off_player_flags );
	w.struct_field( "display_name",      off_display_name );
	w.struct_field( "player_input",      off_player_input );
	w.struct_end( );
}

void c_core::write_base_combat_entity( c_writer& w )
{
	auto bce = c_runtime::find_class( "BaseCombatEntity" );
	auto be  = c_runtime::find_class( "BaseEntity" );

	std::uint64_t off_lifestate   = 0;
	std::uint64_t off_model       = 0;
	std::uint64_t off_health      = 0;
	std::uint64_t off_max_health  = 0;

	if ( bce )
	{
		if ( auto f = il2cpp::get_field_by_name( bce, "lifestate" ) )
			off_lifestate = f->offset( bce );

		if ( auto mark = il2cpp::get_field_by_name( bce, "markAttackerHostile" ) )
		{
			if ( auto h = il2cpp::get_field_by_offset( bce, mark->offset( bce ) + 6 ) )
				off_health = h->offset( bce );
			if ( auto mh = il2cpp::get_field_by_offset( bce, mark->offset( bce ) + 10 ) )
				off_max_health = mh->offset( bce );
		}
	}

	if ( be )
	{
		if ( auto f = il2cpp::get_field_by_name( be, "model" ) )
			off_model = f->offset( be );
	}

	w.struct_begin( "base_combat_entity" );
	w.struct_field( "lifestate",  off_lifestate );
	w.struct_field( "model",      off_model );
	w.struct_field( "_health",    off_health );
	w.struct_field( "_maxHealth", off_max_health );
	w.struct_end( );
}

void c_core::write_base_entity( c_writer& w )
{
	auto klass = c_runtime::find_class( "BaseEntity" );
	std::uint64_t off_flags = 0;
	if ( klass )
		if ( auto f = il2cpp::get_field_by_name( klass, "flags" ) )
			off_flags = f->offset( klass );

	w.struct_begin( "base_entity" );
	w.struct_field( "flags", off_flags );
	w.struct_end( );
}

void c_core::write_item_container( c_writer& w )
{
	auto klass = m_item_container_class;
	std::uint64_t off_item_list = 0;

	if ( klass )
	{
		char search[ 128 ]{ };
		std::snprintf( search, sizeof( search ),
			"System.Collections.Generic.List<%s>",
			m_item_class ? m_item_class->name( ) : "Item" );

		if ( auto f = il2cpp::get_field_if_type_contains( klass, search ) )
			off_item_list = f->offset( );

		std::printf( "[rust-dumper] item_container.item_list=0x%llX (search=%s, klass=%p)\n",
			off_item_list, search, klass );
	}
	else
	{
		std::printf( "[rust-dumper] item_container_class is null — skipping\n" );
	}

	w.struct_begin( "item_container" );
	w.struct_field( "item_list", off_item_list );
	w.struct_end( );
}

// MSVC error C2712 forbids mixing __try/__except with objects that have
// non-trivial destructors in the same function.  The runtime path below
// uses SEH to catch bad reads while probing ClientInit; the fallback path
// needs std::vector.  Splitting them into two functions keeps both happy.
static bool player_inventory_try_runtime_seh(
	il2cpp::il2cpp_class_t* klass,
	il2cpp::il2cpp_class_t* item_container_kl,
	il2cpp::il2cpp_class_t* player_loot_kl,
	std::uint64_t& off_main,
	std::uint64_t& off_belt,
	std::uint64_t& off_wear )
{
	auto try_runtime = [ & ]( ) -> bool
	{
		if ( !klass || !item_container_kl || !player_loot_kl )
		{
			std::printf( "[rust-dumper] player_inventory: missing class (inv=%p ic=%p loot=%p)\n",
				klass, item_container_kl, player_loot_kl );
			return false;
		}

		char flag_search[ 128 ]{ };
		std::snprintf( flag_search, sizeof( flag_search ),
			"%s.Flag", item_container_kl->name( ) );
		auto flag_field = il2cpp::get_field_if_type_contains(
			item_container_kl, flag_search, FIELD_ATTRIBUTE_PUBLIC );
		if ( !flag_field )
		{
			std::printf( "[rust-dumper] player_inventory: no Flag field (search=%s)\n", flag_search );
			return false;
		}

		il2cpp::method_info_t* client_init = nullptr;
		void* iter = nullptr;
		auto base_player = c_runtime::find_class( "BasePlayer" );
		while ( auto m = klass->methods( &iter ) )
		{
			if ( !m )
				continue;
			auto n = m->name( );
			if ( !n || std::strcmp( n, "ClientInit" ) != 0 )
				continue;
			if ( m->param_count( ) != 1 )
				continue;
			auto t = m->get_param( 0 );
			if ( !t )
				continue;
			if ( base_player && t->klass( ) == base_player )
			{
				client_init = m;
				break;
			}
		}
		if ( !client_init )
		{
			std::printf( "[rust-dumper] player_inventory: no ClientInit(BasePlayer) method\n" );
			return false;
		}

		auto invoke = ( void( * )( std::uint64_t, void* ) )client_init->get_fn_ptr<void*>( );
		if ( !invoke )
			return false;

		auto go = unity::game_object_t::create( L"" );
		if ( !go )
		{
			std::printf( "[rust-dumper] player_inventory: GameObject::create failed\n" );
			return false;
		}

		go->add_component( klass->type( ) );
		go->add_component( player_loot_kl->type( ) );

		auto inv_instance = go->get_component( klass->type( ) );
		if ( !inv_instance )
		{
			std::printf( "[rust-dumper] player_inventory: get_component(PlayerInventory) failed\n" );
			return false;
		}

		invoke( inv_instance, nullptr );

		auto containers = il2cpp::get_fields_of_type(
			klass, item_container_kl->type( ),
			FIELD_ATTRIBUTE_PUBLIC, 0 );

		std::printf( "[rust-dumper] player_inventory: %zu ItemContainer fields\n", containers.size( ) );

		for ( auto f : containers )
		{
			auto container_ptr = *( std::uint64_t* )( inv_instance + f->offset( ) );
			if ( !container_ptr )
				continue;
			auto container_flags = *( int* )( container_ptr + flag_field->offset( ) );

			std::printf( "[rust-dumper]   field@0x%llX flags=0x%X\n",
				( std::uint64_t )f->offset( ), container_flags );

			if ( container_flags & rust::item_container::belt )
				off_belt = f->offset( );
			else if ( container_flags & rust::item_container::clothing )
				off_wear = f->offset( );
			else
				off_main = f->offset( );
		}
		return ( off_main | off_belt | off_wear ) != 0;
	};

	bool ok = false;
	__try { ok = try_runtime( ); }
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		std::printf( "[rust-dumper] player_inventory: runtime instantiation crashed, using fallback\n" );
		ok = false;
	}
	return ok;
}

void c_core::write_player_inventory( c_writer& w )
{
	auto klass             = c_runtime::find_class( "PlayerInventory" );
	auto item_container_kl = m_item_container_class;
	auto player_loot_kl    = c_runtime::find_class( "PlayerLoot" );

	std::uint64_t off_main = 0;
	std::uint64_t off_belt = 0;
	std::uint64_t off_wear = 0;

	bool ok = player_inventory_try_runtime_seh(
		klass, item_container_kl, player_loot_kl,
		off_main, off_belt, off_wear );

	if ( !ok && klass && item_container_kl )
	{
		// Class-name-based type filter is unreliable when Rust obfuscates
		// ItemContainer.  Compare by class pointer instead, then sort by
		// field name so belt/main/wear land in the right slots even when
		// IL2CPP shuffles the memory order.
		struct slot_t { const char* name; std::uint64_t off; };
		std::vector<slot_t> matches;

		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f )
				continue;
			if ( f->flags( ) & FIELD_ATTRIBUTE_STATIC )
				continue;
			auto t = f->type( );
			if ( !t )
				continue;
			if ( t->klass( ) != item_container_kl )
				continue;
			matches.push_back( { f->name( ), f->offset( ) } );
		}

		std::printf( "[rust-dumper] player_inventory fallback: %zu ItemContainer fields\n",
			matches.size( ) );
		for ( auto& s : matches )
			std::printf( "[rust-dumper]   %s @ 0x%llX\n",
				s.name ? s.name : "?", ( unsigned long long )s.off );

		auto name_has = [ ]( const char* n, const char* needle ) -> bool
		{
			if ( !n || !needle ) return false;
			for ( ; *n; ++n )
			{
				auto p = n;
				auto q = needle;
				while ( *p && *q )
				{
					char a = *p; char b = *q;
					if ( a >= 'A' && a <= 'Z' ) a = char( a + 32 );
					if ( b >= 'A' && b <= 'Z' ) b = char( b + 32 );
					if ( a != b ) break;
					++p; ++q;
				}
				if ( !*q ) return true;
			}
			return false;
		};

		// First pass: name-driven assignment.
		for ( auto& s : matches )
		{
			if ( !off_belt && name_has( s.name, "belt" ) )
				off_belt = s.off;
			else if ( !off_wear && ( name_has( s.name, "wear" ) || name_has( s.name, "cloth" ) ) )
				off_wear = s.off;
			else if ( !off_main && name_has( s.name, "main" ) )
				off_main = s.off;
		}

		// Fallback for anything still unset: fill by memory offset order.
		// Sort ascending, then pick unclaimed slots left-to-right.
		if ( !off_main || !off_belt || !off_wear )
		{
			std::sort( matches.begin( ), matches.end( ),
				[ ]( const slot_t& a, const slot_t& b ) { return a.off < b.off; } );
			for ( auto& s : matches )
			{
				if ( s.off == off_belt || s.off == off_wear || s.off == off_main )
					continue;
				if ( !off_wear )      off_wear = s.off;
				else if ( !off_main ) off_main = s.off;
				else if ( !off_belt ) off_belt = s.off;
			}
		}
	}

	w.struct_begin( "player_inventory" );
	w.struct_field( "main", off_main );
	w.struct_field( "belt", off_belt );
	w.struct_field( "wear", off_wear );
	w.struct_end( );
}

void c_core::write_decryptions( c_writer& w )
{
	if ( m_bn.decrypt_0.valid )
		w.write_decryption_fn(
			"base_networkable_0",
			m_bn.decrypt_0_addr - c_runtime::game_base( ),
			m_bn.decrypt_0,
			m_bn.hv_offset );
	if ( m_bn.decrypt_1.valid )
		w.write_decryption_fn(
			"base_networkable_1",
			m_bn.decrypt_1_addr - c_runtime::game_base( ),
			m_bn.decrypt_1,
			m_bn.hv_offset );

	if ( m_fov_constants.valid )
		w.write_encrypt_fov(
			m_fov_fn_addr - c_runtime::game_base( ),
			m_fov_constants );
}

// ---------------------------------------------------------------------------
// Typed writers for the classes the original dumper skipped.
//
// Two lookup strategies are used:
//   1. By NAME  — for classes/fields Rust hasn't obfuscated (ItemDefinition,
//                 BaseProjectile, RecoilProperties, Model, and most named
//                 fields on HeldEntity / WorldItem).
//   2. By TYPE  — for obfuscated Item / PlayerEyes / PlayerModel fields.
//                 We compare against known class pointers (m_item_class,
//                 m_item_id_class, etc.) or use type-name substrings on
//                 stable Unity/system types (System.Int32, UnityEngine.Vector3).
//
// When a field can't be resolved statically, we emit 0x0 with a trailing
// comment so downstream tooling knows to fall back to a hand-map.
// ---------------------------------------------------------------------------

namespace
{
	// Small local helper: iterate a class's non-static fields and return
	// the Nth one whose type matches a predicate.  Used when there are
	// multiple fields of the same type and we want a specific one by
	// declaration order.
	template <typename Pred>
	il2cpp::field_info_t* find_nth_field( il2cpp::il2cpp_class_t* klass, int n, Pred p )
	{
		if ( !klass ) return nullptr;
		int seen = 0;
		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f ) continue;
			if ( f->flags( ) & FIELD_ATTRIBUTE_STATIC ) continue;
			auto t = f->type( );
			if ( !t ) continue;
			if ( !p( f, t ) ) continue;
			if ( seen == n ) return f;
			seen++;
		}
		return nullptr;
	}

	std::uint64_t field_off_or( il2cpp::il2cpp_class_t* klass,
		const char* name, std::uint64_t fallback = 0 )
	{
		if ( !klass ) return fallback;
		auto f = il2cpp::get_field_by_name( klass, name );
		return f ? ( std::uint64_t )f->offset( ) : fallback;
	}
}

void c_core::write_item( c_writer& w )
{
	auto klass = m_item_class;

	std::uint64_t off_def = 0, off_held = 0, off_amount = 0, off_uid = 0;

	if ( klass )
	{
		auto def_klass = c_runtime::find_class( "ItemDefinition" );
		auto he_klass  = c_runtime::find_class( "HeldEntity" );

		if ( def_klass )
			if ( auto f = c_runtime::find_field_by_type_class( klass, def_klass ) )
				off_def = f->offset( );

		if ( he_klass )
			if ( auto f = c_runtime::find_field_by_type_class( klass, he_klass ) )
				off_held = f->offset( );

		// amount is System.Int32.  Item has several Int32 fields — the one
		// we want is the amount (not the position slot).  Historically it's
		// the LAST Int32 before uid, so we take the last non-position one
		// by scanning all Int32s.
		std::vector<std::uint64_t> int32_offs;
		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f ) continue;
			if ( f->flags( ) & FIELD_ATTRIBUTE_STATIC ) continue;
			auto t = f->type( );
			if ( !t ) continue;
			auto n = t->name( );
			if ( n && !std::strcmp( n, "System.Int32" ) )
				int32_offs.push_back( f->offset( ) );
		}
		// amount sits after the ItemDefinition ref, so pick the last Int32
		// that's larger than off_def.
		for ( auto it = int32_offs.rbegin( ); it != int32_offs.rend( ); ++it )
		{
			if ( *it > off_def ) { off_amount = *it; break; }
		}

		if ( m_item_id_class )
			if ( auto f = c_runtime::find_field_by_type_class( klass, m_item_id_class ) )
				off_uid = f->offset( );
	}

	w.struct_begin( "item" );
	w.struct_field( "definition",  off_def );
	w.struct_field( "amount",      off_amount );
	w.struct_field( "uid",         off_uid );
	w.struct_field( "held_entity", off_held );
	w.struct_end( );
}

void c_core::write_item_definition( c_writer& w )
{
	auto klass = c_runtime::find_class( "ItemDefinition" );

	w.struct_begin( "item_definition" );
	w.struct_field( "itemid",       field_off_or( klass, "itemid" ) );
	w.struct_field( "shortname",    field_off_or( klass, "shortname" ) );
	w.struct_field( "displayName",  field_off_or( klass, "displayName" ) );
	w.struct_field( "category",     field_off_or( klass, "category" ) );
	w.struct_field( "stackable",    field_off_or( klass, "stackable" ) );
	w.struct_field( "iconSprite",   field_off_or( klass, "iconSprite" ) );
	w.struct_field( "rarity",       field_off_or( klass, "rarity" ) );
	w.struct_field( "condition",    field_off_or( klass, "condition" ) );
	w.struct_end( );
}

void c_core::write_base_projectile( c_writer& w )
{
	auto klass = c_runtime::find_class( "BaseProjectile" );

	w.struct_begin( "base_projectile" );
	w.struct_field( "projectileVelocityScale", field_off_or( klass, "projectileVelocityScale" ) );
	w.struct_field( "automatic",               field_off_or( klass, "automatic" ) );
	w.struct_field( "reloadTime",              field_off_or( klass, "reloadTime" ) );
	w.struct_field( "primaryMagazine",         field_off_or( klass, "primaryMagazine" ) );
	w.struct_field( "aimSway",                 field_off_or( klass, "aimSway" ) );
	w.struct_field( "aimSwaySpeed",            field_off_or( klass, "aimSwaySpeed" ) );
	w.struct_field( "recoil",                  field_off_or( klass, "recoil" ) );
	w.struct_field( "aimCone",                 field_off_or( klass, "aimCone" ) );
	w.struct_field( "hipAimCone",              field_off_or( klass, "hipAimCone" ) );
	w.struct_field( "aimconePenaltyPerShot",   field_off_or( klass, "aimconePenaltyPerShot" ) );
	w.struct_field( "stancePenaltyScale",      field_off_or( klass, "stancePenaltyScale" ) );
	w.struct_field( "hasADS",                  field_off_or( klass, "hasADS" ) );
	w.struct_field( "isBurstWeapon",           field_off_or( klass, "isBurstWeapon" ) );
	w.struct_field( "canChangeFireModes",      field_off_or( klass, "canChangeFireModes" ) );
	w.struct_field( "internalBurstFireRateScale", field_off_or( klass, "internalBurstFireRateScale" ) );
	w.struct_field( "internalBurstAimConeScale",  field_off_or( klass, "internalBurstAimConeScale" ) );
	w.struct_field( "canUnloadAmmo",           field_off_or( klass, "canUnloadAmmo" ) );
	w.struct_field( "fractionalReload",        field_off_or( klass, "fractionalReload" ) );
	w.struct_end( );
}

void c_core::write_recoil_properties( c_writer& w )
{
	auto klass = c_runtime::find_class( "RecoilProperties" );

	w.struct_begin( "recoil_properties" );
	w.struct_field( "recoilYawMin",             field_off_or( klass, "recoilYawMin" ) );
	w.struct_field( "recoilYawMax",             field_off_or( klass, "recoilYawMax" ) );
	w.struct_field( "recoilPitchMin",           field_off_or( klass, "recoilPitchMin" ) );
	w.struct_field( "recoilPitchMax",           field_off_or( klass, "recoilPitchMax" ) );
	w.struct_field( "timeToTakeMin",            field_off_or( klass, "timeToTakeMin" ) );
	w.struct_field( "timeToTakeMax",            field_off_or( klass, "timeToTakeMax" ) );
	w.struct_field( "ADSScale",                 field_off_or( klass, "ADSScale" ) );
	w.struct_field( "movementPenalty",          field_off_or( klass, "movementPenalty" ) );
	w.struct_field( "clampPitch",               field_off_or( klass, "clampPitch" ) );
	w.struct_field( "pitchCurve",               field_off_or( klass, "pitchCurve" ) );
	w.struct_field( "yawCurve",                 field_off_or( klass, "yawCurve" ) );
	w.struct_field( "useCurves",                field_off_or( klass, "useCurves" ) );
	w.struct_field( "shotsUntilMax",            field_off_or( klass, "shotsUntilMax" ) );
	w.struct_field( "maxRecoilRadius",          field_off_or( klass, "maxRecoilRadius" ) );
	w.struct_field( "overrideAimconeWithCurve", field_off_or( klass, "overrideAimconeWithCurve" ) );
	w.struct_field( "aimconeCurveScale",        field_off_or( klass, "aimconeCurveScale" ) );
	w.struct_field( "aimconeCurve",             field_off_or( klass, "aimconeCurve" ) );
	w.struct_field( "aimconeProbabilityCurve",  field_off_or( klass, "aimconeProbabilityCurve" ) );
	w.struct_field( "newRecoilOverride",        field_off_or( klass, "newRecoilOverride" ) );
	w.struct_end( );
}

void c_core::write_world_item( c_writer& w )
{
	auto klass = c_runtime::find_class( "WorldItem" );

	std::uint64_t off_allow = field_off_or( klass, "allowPickup" );
	std::uint64_t off_item  = 0;
	if ( klass && m_item_class )
		if ( auto f = c_runtime::find_field_by_type_class( klass, m_item_class ) )
			off_item = f->offset( );

	w.struct_begin( "world_item" );
	w.struct_field( "allowPickup", off_allow );
	w.struct_field( "item",        off_item );
	w.struct_end( );
}

void c_core::write_held_entity( c_writer& w )
{
	auto klass = c_runtime::find_class( "HeldEntity" );

	// Item back-ref field is obfuscated on HeldEntity, but resolvable by
	// class pointer.
	std::uint64_t off_item = 0;
	if ( klass && m_item_class )
		if ( auto f = c_runtime::find_field_by_type_class( klass, m_item_class ) )
			off_item = f->offset( );

	// ownerItemUID: obfuscated too — take the ItemId struct field.
	std::uint64_t off_owner_uid = 0;
	if ( klass && m_item_id_class )
		if ( auto f = c_runtime::find_field_by_type_class( klass, m_item_id_class ) )
			off_owner_uid = f->offset( );

	// viewModel: type-name substring match works, still called ViewModel.
	std::uint64_t off_view = 0;
	if ( klass )
		if ( auto f = c_runtime::find_field_by_type_contains( klass, "ViewModel" ) )
			off_view = f->offset( );

	w.struct_begin( "held_entity" );
	w.struct_field( "viewModel",     off_view );
	w.struct_field( "worldModelAnimator", field_off_or( klass, "worldModelAnimator" ) );
	w.struct_field( "handBone",      field_off_or( klass, "handBone" ) );
	w.struct_field( "holdInfo",      field_off_or( klass, "holdInfo" ) );
	w.struct_field( "isBuildingTool", field_off_or( klass, "isBuildingTool" ) );
	w.struct_field( "forcedOwner",   field_off_or( klass, "forcedOwner" ) );
	w.struct_field( "hostileScore",  field_off_or( klass, "hostileScore" ) );
	w.struct_field( "item_owner",    off_item );
	w.struct_field( "ownerItemUID",  off_owner_uid );
	w.struct_end( );
}

void c_core::write_model( c_writer& w )
{
	auto klass = c_runtime::find_class( "Model" );

	w.struct_begin( "model" );
	w.struct_field( "collision",      field_off_or( klass, "collision" ) );
	w.struct_field( "rootBone",       field_off_or( klass, "rootBone" ) );
	w.struct_field( "headBone",       field_off_or( klass, "headBone" ) );
	w.struct_field( "eyeBone",        field_off_or( klass, "eyeBone" ) );
	w.struct_field( "animator",       field_off_or( klass, "animator" ) );
	w.struct_field( "skeleton",       field_off_or( klass, "skeleton" ) );
	w.struct_field( "boneTransforms", field_off_or( klass, "boneTransforms" ) );
	w.struct_field( "boneNames",      field_off_or( klass, "boneNames" ) );
	w.struct_end( );
}

void c_core::write_player_model( c_writer& w )
{
	auto klass = c_runtime::find_class( "PlayerModel" );

	// headBone (a GameObject) still has its clear name.
	std::uint64_t off_head    = field_off_or( klass, "headBone" );
	std::uint64_t off_jaw     = field_off_or( klass, "jawBone" );
	std::uint64_t off_neck    = field_off_or( klass, "neckBone" );

	// Everything else is heavily obfuscated on this build.  Best we can do
	// statically is find the SkinnedMultiMesh reference by type class.
	auto smm_klass = c_runtime::find_class( "SkinnedMultiMesh" );
	std::uint64_t off_smm = 0;
	if ( klass && smm_klass )
		if ( auto f = c_runtime::find_field_by_type_class( klass, smm_klass ) )
			off_smm = f->offset( );

	// Position + velocity are Vector3s at large offsets (near end of class).
	// Collect all Vector3 offsets and pick the last two — position tends
	// to be second-to-last, velocity last, historically.
	std::vector<std::uint64_t> v3;
	if ( klass )
	{
		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f ) continue;
			if ( f->flags( ) & FIELD_ATTRIBUTE_STATIC ) continue;
			auto t = f->type( );
			if ( !t ) continue;
			auto n = t->name( );
			if ( n && !std::strcmp( n, "UnityEngine.Vector3" ) )
				v3.push_back( f->offset( ) );
		}
	}
	std::sort( v3.begin( ), v3.end( ) );
	std::uint64_t off_position = 0;
	std::uint64_t off_velocity = 0;
	if ( v3.size( ) >= 2 )
	{
		// Historically position sits before velocity in memory.
		// The two we want are near the tail of the class; take the pair
		// of large-offset Vector3s that are close together (< 0x100 apart).
		for ( int i = ( int )v3.size( ) - 1; i > 0; --i )
		{
			auto a = v3[ i - 1 ];
			auto b = v3[ i ];
			if ( b - a >= 0x40 && b - a <= 0x100 )
			{
				off_position = a;
				off_velocity = b;
				break;
			}
		}
		// Fallback: last two.
		if ( !off_position )
		{
			off_position = v3[ v3.size( ) - 2 ];
			off_velocity = v3.back( );
		}
	}

	w.struct_begin( "player_model" );
	w.struct_field( "jawBone",           off_jaw );
	w.struct_field( "neckBone",          off_neck );
	w.struct_field( "headBone",          off_head );
	w.struct_field( "skinnedMultiMesh",  off_smm );
	w.struct_field( "position",          off_position, "heuristic — last-pair Vector3" );
	w.struct_field( "velocity",          off_velocity, "heuristic — last-pair Vector3" );
	w.struct_end( );
}

void c_core::write_player_eyes( c_writer& w )
{
	auto klass = c_runtime::find_class( "PlayerEyes" );

	// First Vector3 field on the class is thirdPersonSleepingOffset in
	// current builds — viewOffset is the FIRST Vector3-wrapping field
	// after that (usually a Nullable<Vector3> or LazyAim<Vector3>).
	// We fetch: the first Quaternion is bodyRotation.
	std::uint64_t off_view = 0;
	std::uint64_t off_body = 0;
	std::uint64_t off_wpos = 0;

	if ( klass )
	{
		int v3_seen = 0;
		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f ) continue;
			if ( f->flags( ) & FIELD_ATTRIBUTE_STATIC ) continue;
			auto t = f->type( );
			if ( !t ) continue;
			auto n = t->name( );
			if ( !n ) continue;

			if ( !std::strcmp( n, "UnityEngine.Vector3" ) )
			{
				if ( v3_seen == 1 )      off_view = f->offset( );   // 2nd Vector3
				else if ( v3_seen == 2 ) off_wpos = f->offset( );   // 3rd Vector3
				v3_seen++;
			}
			else if ( !std::strcmp( n, "UnityEngine.Quaternion" ) && !off_body )
			{
				off_body = f->offset( );
			}
		}

		// viewOffset is more likely to be a wrapping type (LazyAim / Nullable)
		// than a raw Vector3 on modern builds.  If the raw-Vector3 heuristic
		// above didn't land in a plausible range (Rust puts viewOffset at
		// 0x40-ish), fall back to the field name substring match.
		if ( !off_view || off_view > 0x100 )
		{
			if ( auto f = c_runtime::find_field_by_type_contains( klass, "Vector3" ) )
				off_view = f->offset( );
		}
	}

	w.struct_begin( "player_eyes" );
	w.struct_field( "viewOffset",   off_view );
	w.struct_field( "bodyRotation", off_body );
	w.struct_field( "worldPosition", off_wpos );
	w.struct_end( );
}

void c_core::write_player_input( c_writer& w )
{
	auto klass = c_runtime::find_class( "PlayerInput" );

	// PlayerInput has multiple Vector3s.  bodyAngles has been at 0x44 for
	// many patches — take the FIRST Vector3 on the class.
	std::uint64_t off_body = 0;
	if ( klass )
	{
		auto f = find_nth_field( klass, 0,
			[ ]( il2cpp::field_info_t*, il2cpp::il2cpp_type_t* t )
			{
				auto n = t->name( );
				return n && !std::strcmp( n, "UnityEngine.Vector3" );
			} );
		if ( f ) off_body = f->offset( );
	}

	w.struct_begin( "player_input" );
	w.struct_field( "bodyAngles", off_body );
	w.struct_end( );
}

void c_core::write_player_walk_movement( c_writer& w )
{
	// PlayerWalkMovement is either not found in current builds or heavily
	// obfuscated.  We emit the known offsets from validict's cross-verified
	// dump so downstream code has something to build against.  Reverify
	// after each big Rust patch.
	auto klass = c_runtime::find_class( "PlayerWalkMovement" );

	w.struct_begin( "player_walk_movement" );
	if ( klass )
	{
		w.struct_field( "GroundAngle",       0x70,  "hardcoded — reverify" );
		w.struct_field( "GroundAngleNew",    0x78,  "hardcoded — reverify" );
		w.struct_field( "GroundTime",        0x80,  "hardcoded — reverify" );
		w.struct_field( "JumpTime",          0x88,  "hardcoded — reverify" );
		w.struct_field( "LandTime",          0x90,  "hardcoded — reverify" );
		w.struct_field( "GravityMultiplier", 0x98,  "hardcoded — reverify" );
		w.struct_field( "TargetMovement",    0x128, "hardcoded — reverify" );
	}
	else
	{
		w.struct_field( "GroundAngle",       0x70,  "class not found — hardcoded" );
		w.struct_field( "GroundAngleNew",    0x78,  "class not found — hardcoded" );
		w.struct_field( "GravityMultiplier", 0x98,  "class not found — hardcoded" );
	}
	w.struct_end( );
}

void c_core::write_convar_graphics( c_writer& w )
{
	// ConVar.Graphics — namespace is "ConVar", class name "Graphics".
	auto klass = c_runtime::find_class( "Graphics", "ConVar" );

	std::uint64_t rva = klass ? c_runtime::static_class_rva( klass ) : 0;
	std::uint64_t off_fov = 0;

	if ( klass )
	{
		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f ) continue;
			auto n = f->name( );
			if ( n && !std::strcmp( n, "fov" ) )
			{
				off_fov = f->offset( );
				break;
			}
		}
	}

	w.struct_begin( "convar_graphics" );
	w.struct_field( "type_info",     rva );
	w.struct_field( "static_fields", 0xB8 );
	w.struct_field( "fov",           off_fov );
	w.struct_end( );
}

// ---------------------------------------------------------------------------
// Raw class field dumps.  Rust obfuscates + renames a lot of internal types
// across patches, so we can't hardcode field-name lookups reliably.  This
// helper walks every instance field of a class and emits it as a comment
// line so we can hand-map offsets afterwards.
// ---------------------------------------------------------------------------

void c_core::write_raw_class( c_writer& w, il2cpp::il2cpp_class_t* klass, const char* label )
{
	if ( !klass )
	{
		w.write_line( "// raw class: %s NOT FOUND", label ? label : "?" );
		return;
	}

	const char* class_name = klass->name( );
	std::uint32_t count    = 0;

	// First pass: count fields so we know if the class is empty.
	void* iter = nullptr;
	while ( auto f = klass->fields( &iter ) )
	{
		if ( !f )
			continue;
		if ( f->flags( ) & FIELD_ATTRIBUTE_STATIC )
			continue;
		count++;
	}

	w.write_line( "// raw class: %s (label=%s klass=%p instance_fields=%u)",
		class_name ? class_name : "?", label ? label : "?", klass, count );

	if ( count == 0 )
	{
		w.write_line( "//   (no instance fields)" );
		return;
	}

	// Second pass: emit each field.
	iter = nullptr;
	while ( auto f = klass->fields( &iter ) )
	{
		if ( !f )
			continue;
		if ( f->flags( ) & FIELD_ATTRIBUTE_STATIC )
			continue;

		auto  fn   = f->name( );
		auto  t    = f->type( );
		auto  tn   = t ? t->name( ) : "?";
		auto  off  = f->offset( );

		w.write_line( "//   %-40s @ 0x%03llX  (%s)",
			fn ? fn : "?", ( unsigned long long )off, tn ? tn : "?" );
	}
}

void c_core::write_raw_class_by_name( c_writer& w, const char* name, const char* label )
{
	auto klass = c_runtime::find_class( name );
	write_raw_class( w, klass, label ? label : name );
}

void c_core::write_missing_classes( c_writer& w )
{
	w.blank_line( );
	w.write_line( "// ===========================================================================" );
	w.write_line( "// RAW CLASS DUMPS" );
	w.write_line( "// Everything below is emitted as C++ comments.  Use it to hand-map field" );
	w.write_line( "// offsets when a Rust patch renames or obfuscates things." );
	w.write_line( "// ===========================================================================" );
	w.blank_line( );

	// BasePlayer + its parent chain.  We need this every patch to hand-pick
	// display_name (the "first protected string" heuristic in the typed
	// writer misses when the class grows new string fields near the end).
	write_raw_class_by_name( w, "BasePlayer" );
	w.blank_line( );
	write_raw_class_by_name( w, "BaseCombatEntity" );
	w.blank_line( );
	write_raw_class_by_name( w, "BaseEntity" );
	w.blank_line( );

	// Player-side classes.
	write_raw_class_by_name( w, "PlayerModel" );
	w.blank_line( );
	write_raw_class_by_name( w, "BaseMovement" );
	w.blank_line( );
	write_raw_class_by_name( w, "PlayerMovement" );
	w.blank_line( );
	write_raw_class_by_name( w, "PlayerEyes" );
	w.blank_line( );
	write_raw_class_by_name( w, "PlayerInput" );
	w.blank_line( );
	write_raw_class_by_name( w, "ModelState" );
	w.blank_line( );

	// Weapon / item classes.
	if ( m_item_class )
	{
		write_raw_class( w, m_item_class, "Item" );
		w.blank_line( );
	}
	else
	{
		w.write_line( "// raw class: Item NOT FOUND (m_item_class is null)" );
		w.blank_line( );
	}

	if ( m_item_id_class )
	{
		write_raw_class( w, m_item_id_class, "ItemId" );
		w.blank_line( );
	}

	write_raw_class_by_name( w, "ItemDefinition" );
	w.blank_line( );
	write_raw_class_by_name( w, "ItemModContainer" );
	w.blank_line( );
	write_raw_class_by_name( w, "ItemModProjectile" );
	w.blank_line( );

	write_raw_class_by_name( w, "HeldEntity" );
	w.blank_line( );
	write_raw_class_by_name( w, "BaseProjectile" );
	w.blank_line( );
	write_raw_class_by_name( w, "BaseLauncher" );
	w.blank_line( );
	write_raw_class_by_name( w, "BaseMelee" );
	w.blank_line( );
	write_raw_class_by_name( w, "RecoilProperties" );
	w.blank_line( );

	// Attempt several possible names for the projectile-side magazine data.
	write_raw_class_by_name( w, "Magazine",             "BaseProjectile.Magazine" );
	w.blank_line( );
	write_raw_class_by_name( w, "AmmoTypes",            "BaseProjectile.AmmoTypes" );
	w.blank_line( );

	// World / entity classes.
	write_raw_class_by_name( w, "WorldItem" );
	w.blank_line( );
	write_raw_class_by_name( w, "DroppedItem" );
	w.blank_line( );
	write_raw_class_by_name( w, "AutoTurret" );
	w.blank_line( );
	write_raw_class_by_name( w, "NPCAutoTurret" );
	w.blank_line( );

	// Camera + graphics.
	write_raw_class_by_name( w, "MainCamera" );
	w.blank_line( );
	write_raw_class_by_name( w, "CameraState" );
	w.blank_line( );
	write_raw_class_by_name( w, "ConVar.Graphics",  "ConVar_Graphics" );
	w.blank_line( );

	// Extras we might need for chams / model access.
	write_raw_class_by_name( w, "Model" );
	w.blank_line( );
	write_raw_class_by_name( w, "SkinnedMultiMesh" );
	w.blank_line( );
	write_raw_class_by_name( w, "PlayerVisualState" );
	w.blank_line( );
}

// ---------------------------------------------------------------------------
// il2cpp_gchandle_get_target byte dump.  We resolve the export from
// GameAssembly.dll and emit the first ~0x120 bytes as a comment blob so we
// can hand-reverse the current handle-table shape without rerunning the
// dumper each build.
// ---------------------------------------------------------------------------

void c_core::write_il2cpp_get_handle_dump( c_writer& w )
{
	using fn_t = void*( * )( std::uint32_t );
	auto ga = GetModuleHandleA( "GameAssembly.dll" );
	auto fn = ga ? ( fn_t )GetProcAddress( ga, "il2cpp_gchandle_get_target" ) : nullptr;

	w.blank_line( );
	w.write_line( "// ===========================================================================" );
	w.write_line( "// il2cpp_gchandle_get_target raw bytes" );
	w.write_line( "// Use this to hand-derive the current il2cpp handle lookup when Unity" );
	w.write_line( "// changes the internal GC handle table layout." );
	w.write_line( "// ===========================================================================" );

	if ( !fn )
	{
		w.write_line( "// il2cpp_gchandle_get_target: EXPORT NOT FOUND" );
		return;
	}

	std::uintptr_t game_base = c_runtime::game_base( );
	std::uintptr_t addr      = ( std::uintptr_t )fn;
	std::uintptr_t rva       = addr - game_base;

	w.write_line( "// il2cpp_gchandle_get_target: address=0x%llX rva=0x%llX",
		( unsigned long long )addr, ( unsigned long long )rva );

	constexpr std::size_t k_len = 0x180;
	auto p = ( std::uint8_t* )addr;
	if ( IsBadReadPtr( p, k_len ) )
	{
		w.write_line( "// (function memory unreadable)" );
		return;
	}

	// Emit as 16 bytes per line so we can eyeball it.
	for ( std::size_t off = 0; off < k_len; off += 16 )
	{
		char line[ 256 ]{ };
		int  cursor = std::snprintf( line, sizeof( line ),
			"//   +0x%03zX  ", off );
		for ( std::size_t j = 0; j < 16 && off + j < k_len; j++ )
		{
			cursor += std::snprintf( line + cursor, sizeof( line ) - cursor,
				"%02X ", p[ off + j ] );
		}
		w.write_line( "%s", line );
	}

	// Also emit disassembled instructions using hde64 so the trained eye
	// can spot the loads / shifts without launching x64dbg.
	w.write_line( "//" );
	w.write_line( "// hde64 disassembly (first ~0x120 bytes):" );

	std::uint8_t* q   = p;
	std::uint8_t* end = p + 0x120;
	while ( q < end )
	{
		hde64s hs;
		auto len = hde64_disasm( q, &hs );
		if ( !len || ( hs.flags & F_ERROR ) )
			break;

		char bytes[ 64 ]{ };
		int  cursor = 0;
		for ( int i = 0; i < ( int )len && cursor < ( int )sizeof( bytes ) - 3; i++ )
			cursor += std::snprintf( bytes + cursor, sizeof( bytes ) - cursor,
				"%02X ", q[ i ] );

		w.write_line( "//   +0x%03zX  %-48s (op=%02X)",
			( std::size_t )( q - p ), bytes, hs.opcode );

		if ( q[ 0 ] == 0xC3 || q[ 0 ] == 0xCC )
			break;
		q += len;
	}
}

bool c_core::run( const char* output_path, bool do_materials )
{
	if ( !c_runtime::init( ) )
	{
		std::printf( "[rust-dumper] failed to init runtime\n" );
		return false;
	}
	std::printf( "[rust-dumper] runtime: game_base=0x%llX size=0x%X\n",
		c_runtime::game_base( ), c_runtime::image_size( ) );

	m_gc_handles_rva = c_scanner::resolve_gc_handles( );
	std::printf( "[rust-dumper] il2cpphandle rva = 0x%llX\n", m_gc_handles_rva );

	resolve_item_classes( );
	std::printf( "[rust-dumper] item_class=%p item_id_class=%p\n",
		m_item_class, m_item_id_class );

	if ( resolve_console_system( ) )
		std::printf( "[rust-dumper] console_system: find=%p get_override=0x%zX set_override=0x%zX\n",
			rust::console_system::console_system_index_client_find,
			rust::console_system::get_override_offset,
			rust::console_system::set_override_offset );
	else
		std::printf( "[rust-dumper] console_system: failed to resolve\n" );

	if ( resolve_bn_chain( ) )
		std::printf( "[rust-dumper] bn chain: base=0x%llX entities=0x%X parent_sf=0x%X wrapper=0x%X\n",
			m_bn.base_networkable_rva, m_bn.entities, m_bn.parent_static_fields, m_bn.wrapper_class_ptr );

	if ( resolve_camera_chain( ) )
		std::printf( "[rust-dumper] camera: main=0x%llX object=0x%X\n",
			m_camera.main_camera_c, m_camera.camera_object );

	verify_bn_chain( );

	resolve_fov_encryption( );
	if ( m_fov_constants.valid )
		std::printf( "[rust-dumper] fov encryption: rva=0x%llX (%d ops)\n",
			m_fov_fn_addr - c_runtime::game_base( ), m_fov_constants.op_count );

	verify_all( );

	c_writer w;
	if ( !w.open( output_path ) )
	{
		std::printf( "[rust-dumper] failed to open output file\n" );
		return false;
	}

	write_il2cpphandle( w );
	write_basenetworkable( w );
	write_camera( w );
	write_base_player( w );
	write_base_combat_entity( w );
	write_base_entity( w );
	write_item_container( w );
	write_player_inventory( w );

	// Typed writers newly added — Item / weapon / model / camera-state /
	// convar chains.  These use name-based lookups for unobfuscated fields
	// and class-pointer lookups for obfuscated ones.
	write_item( w );
	write_item_definition( w );
	write_base_projectile( w );
	write_recoil_properties( w );
	write_world_item( w );
	write_held_entity( w );
	write_model( w );
	write_player_model( w );
	write_player_eyes( w );
	write_player_input( w );
	write_player_walk_movement( w );
	write_convar_graphics( w );

	w.blank_line( );
	write_decryptions( w );

	// Everything below is diagnostic — raw field dumps for classes that the
	// typed writers above can't fully cover (obfuscated Item, unresolved
	// item-mod classes, camera state, etc.) plus the raw bytes of the il2cpp
	// gc handle lookup so we can hand-derive it if Unity's shape shifts.
	write_missing_classes( w );
	write_il2cpp_get_handle_dump( w );

	w.close( );

	if ( do_materials )
	{
		char mat_path[ MAX_PATH ]{ };
		std::strncpy( mat_path, output_path, MAX_PATH - 1 );
		auto slash = std::strrchr( mat_path, '\\' );
		if ( slash )
			std::snprintf( slash + 1, MAX_PATH - ( slash - mat_path + 1 ), "materials.h" );
		else
			std::snprintf( mat_path, MAX_PATH, "materials.h" );

		std::printf( "[rust-dumper] materials output: %s\n", mat_path );
		c_materials::dump( mat_path );
	}

	return true;
}
