#include "verification.hpp"

#include <windows.h>
#include <cstdio>
#include <cmath>

static bool valid_ptr( std::uintptr_t p )
{
	return p > 0x10000 && p < 0x7FFFFFFFFFFFull && !IsBadReadPtr( ( void* )p, 8 );
}

static std::uintptr_t decrypt_handle(
	std::uintptr_t wrapper_ptr,
	std::uint64_t hv_offset,
	const c_decryption::constants_t& c )
{
	if ( !valid_ptr( wrapper_ptr + hv_offset ) )
		return 0;

	auto encrypted = *( std::uint64_t* )( wrapper_ptr + hv_offset );
	auto decrypted = c_decryption::simulate( encrypted, c );
	auto handle = ( std::uint32_t )decrypted;

	if ( handle == 0 || handle > 0x1000000 )
		return 0;

	using gchandle_fn_t = void* ( * )( std::uint32_t );
	static auto gchandle_get_target = ( gchandle_fn_t )GetProcAddress(
		GetModuleHandleA( "GameAssembly.dll" ), "il2cpp_gchandle_get_target" );

	if ( !gchandle_get_target )
		return 0;

	__try { return ( std::uintptr_t )gchandle_get_target( handle ); }
	__except ( EXCEPTION_EXECUTE_HANDLER ) { return 0; }
}

static std::int32_t check_buffer_list( std::uintptr_t list )
{
	if ( !valid_ptr( list ) )
		return -1;

	auto array = *( std::uintptr_t* )( list + 0x10 );
	auto size  = *( std::int32_t* )( list + 0x18 );

	if ( !valid_ptr( array ) ) return -1;
	if ( size < 0 || size > 50000 ) return -1;

	return size;
}

std::vector<c_verification::bn_hit_t> c_verification::bruteforce_bn(
	std::uint64_t game_base,
	std::uint64_t bn_rva,
	const c_decryption::constants_t& decrypt_0,
	const c_decryption::constants_t& decrypt_1,
	std::uint64_t hv_offset )
{
	std::vector<bn_hit_t> hits;

	if ( !bn_rva || !decrypt_0.valid || !decrypt_1.valid )
		return hits;

	auto klass = *( std::uintptr_t* )( game_base + bn_rva );
	if ( !valid_ptr( klass ) )
		return hits;

	auto static_fields = *( std::uintptr_t* )( klass + 0xB8 );
	if ( !valid_ptr( static_fields ) )
		return hits;

	for ( std::uint32_t w = 0; w <= 0x100; w += 8 )
	{
		auto wrapper_ptr = *( std::uintptr_t* )( static_fields + w );
		if ( !valid_ptr( wrapper_ptr ) )
			continue;

		auto entity_realm = decrypt_handle( wrapper_ptr, hv_offset, decrypt_0 );
		if ( !valid_ptr( entity_realm ) )
			continue;

		for ( std::uint32_t p = 0; p <= 0x100; p += 8 )
		{
			auto parent_ptr = *( std::uintptr_t* )( entity_realm + p );
			if ( !valid_ptr( parent_ptr ) )
				continue;

			auto list_dict = decrypt_handle( parent_ptr, hv_offset, decrypt_1 );
			if ( !valid_ptr( list_dict ) )
				continue;

			for ( std::uint32_t e = 0; e <= 0x100; e += 8 )
			{
				auto buffer_list = *( std::uintptr_t* )( list_dict + e );
				auto sz = check_buffer_list( buffer_list );
				if ( sz < 10 )
					continue;

				hits.push_back( { w, p, e, sz } );
			}
		}
	}

	return hits;
}

struct view_matrix_t { float m[ 4 ][ 4 ]; };

std::vector<c_verification::camera_hit_t> c_verification::bruteforce_camera(
	std::uint64_t game_base,
	std::uint64_t main_camera_rva )
{
	std::vector<camera_hit_t> hits;

	if ( !main_camera_rva )
		return hits;

	auto main_camera = *( std::uintptr_t* )( game_base + main_camera_rva );
	if ( !valid_ptr( main_camera ) )
		return hits;

	for ( std::uint32_t c1 = 0; c1 <= 0x100; c1 += 8 )
	{
		auto camera_static = *( std::uintptr_t* )( main_camera + c1 );
		if ( !valid_ptr( camera_static ) )
			continue;

		for ( std::uint32_t c2 = 0; c2 <= 0x100; c2 += 8 )
		{
			auto camera_object = *( std::uintptr_t* )( camera_static + c2 );
			if ( !valid_ptr( camera_object ) )
				continue;

			for ( std::uint32_t c3 = 0; c3 <= 0x100; c3 += 8 )
			{
				auto entity = *( std::uintptr_t* )( camera_object + c3 );
				if ( !valid_ptr( entity ) )
					continue;

				if ( IsBadReadPtr( ( void* )( entity + 0x30c ), sizeof( view_matrix_t ) ) )
					continue;

				auto vm = *( view_matrix_t* )( entity + 0x30c );

				if ( std::isnan( vm.m[ 0 ][ 0 ] ) || std::isinf( vm.m[ 0 ][ 0 ] ) )
					continue;
				if ( vm.m[ 0 ][ 0 ] == 0.f || vm.m[ 1 ][ 1 ] == 0.f || vm.m[ 2 ][ 2 ] == 0.f )
					continue;
				if ( std::fabs( vm.m[ 0 ][ 0 ] ) > 10.f || std::fabs( vm.m[ 1 ][ 1 ] ) > 10.f )
					continue;

				if ( IsBadReadPtr( ( void* )( entity + 0x454 ), 12 ) )
					continue;

				float px = *( float* )( entity + 0x454 );
				float py = *( float* )( entity + 0x458 );
				float pz = *( float* )( entity + 0x45c );

				if ( std::isnan( px ) || std::isnan( py ) || std::isnan( pz ) )
					continue;
				if ( py < 0.5f || py > 2000.f )
					continue;
				if ( std::fabs( px ) < 1.f || std::fabs( pz ) < 1.f )
					continue;
				if ( std::fabs( px ) > 50000.f || std::fabs( pz ) > 50000.f )
					continue;

				hits.push_back( { c1, c2, c3, px, py, pz } );
				return hits;
			}
		}
	}

	return hits;
}

bool c_verification::check_bn(
	std::uint64_t game_base,
	std::uint64_t bn_rva,
	std::uint32_t wrapper_off,
	std::uint32_t parent_off,
	std::uint32_t entities_off,
	const c_decryption::constants_t& decrypt_0,
	const c_decryption::constants_t& decrypt_1,
	std::uint64_t hv_offset )
{
	if ( !bn_rva || !decrypt_0.valid || !decrypt_1.valid )
		return false;

	auto klass = *( std::uintptr_t* )( game_base + bn_rva );
	if ( !valid_ptr( klass ) )
		return false;

	auto static_fields = *( std::uintptr_t* )( klass + 0xB8 );
	if ( !valid_ptr( static_fields ) )
		return false;

	auto wrapper_ptr = *( std::uintptr_t* )( static_fields + wrapper_off );
	if ( !valid_ptr( wrapper_ptr ) )
		return false;

	auto entity_realm = decrypt_handle( wrapper_ptr, hv_offset, decrypt_0 );
	if ( !valid_ptr( entity_realm ) )
		return false;

	auto parent_ptr = *( std::uintptr_t* )( entity_realm + parent_off );
	if ( !valid_ptr( parent_ptr ) )
		return false;

	auto list_dict = decrypt_handle( parent_ptr, hv_offset, decrypt_1 );
	if ( !valid_ptr( list_dict ) )
		return false;

	auto buffer_list = *( std::uintptr_t* )( list_dict + entities_off );
	return check_buffer_list( buffer_list ) >= 10;
}

bool c_verification::check_camera(
	std::uint64_t game_base,
	std::uint64_t main_camera_rva,
	std::uint32_t camera_static,
	std::uint32_t camera_object,
	std::uint32_t entity )
{
	if ( !main_camera_rva )
		return false;

	auto mc = *( std::uintptr_t* )( game_base + main_camera_rva );
	if ( !valid_ptr( mc ) )
		return false;

	auto cs = *( std::uintptr_t* )( mc + camera_static );
	if ( !valid_ptr( cs ) )
		return false;

	auto co = *( std::uintptr_t* )( cs + camera_object );
	if ( !valid_ptr( co ) )
		return false;

	auto ent = *( std::uintptr_t* )( co + entity );
	if ( !valid_ptr( ent ) )
		return false;

	if ( IsBadReadPtr( ( void* )( ent + 0x454 ), 12 ) )
		return false;

	float py = *( float* )( ent + 0x458 );
	return !std::isnan( py ) && py > 0.5f && py < 2000.f;
}
