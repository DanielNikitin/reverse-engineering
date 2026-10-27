#include "materials.hpp"
#include "../runtime/runtime.hpp"

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using find_all_fn_t = void* ( * )( void* );
using get_name_fn_t = system_c::string_t* ( * )( void* );

static void* safe_find_all( find_all_fn_t fn, void* type_obj )
{
	__try { return fn( type_obj ); }
	__except ( EXCEPTION_EXECUTE_HANDLER ) { return nullptr; }
}

static system_c::string_t* safe_get_name( get_name_fn_t fn, void* obj )
{
	__try { return fn( obj ); }
	__except ( EXCEPTION_EXECUTE_HANDLER ) { return nullptr; }
}

static std::int32_t safe_read_instance_id( void* obj )
{
	__try
	{
		auto cached_ptr = *( std::uintptr_t* )( ( std::uint8_t* )obj + 0x10 );
		if ( cached_ptr && !IsBadReadPtr( ( void* )cached_ptr, 0x10 ) )
			return *( std::int32_t* )( cached_ptr + 0x08 );
		return *( std::int32_t* )( ( std::uint8_t* )obj + 0x18 );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER ) { return 0; }
}

static std::string sanitize_name( const wchar_t* raw, int len )
{
	if ( !raw || len <= 0 )
		return "unknown";

	std::string result;
	result.reserve( len );

	char first = ( char )raw[ 0 ];
	if ( ( first >= 'a' && first <= 'z' ) || ( first >= 'A' && first <= 'Z' ) || first == '_' )
		result += first;
	else
		result += '_';

	for ( int i = 1; i < len; i++ )
	{
		char c = ( char )raw[ i ];
		if ( ( c >= 'a' && c <= 'z' ) || ( c >= 'A' && c <= 'Z' ) || ( c >= '0' && c <= '9' ) || c == '_' )
			result += c;
		else
			result += '_';
	}

	return result;
}

bool c_materials::dump( const char* output_path )
{
	auto material_klass = il2cpp::get_class_by_name( "Material", "UnityEngine" );
	if ( !material_klass )
	{
		std::printf( "[materials] Material class not found\n" );
		return false;
	}

	auto material_type = material_klass->type( );
	if ( !material_type )
	{
		std::printf( "[materials] Material type is null\n" );
		return false;
	}

	auto type_obj = il2cpp::type_get_object( material_type );
	if ( !type_obj )
	{
		std::printf( "[materials] type_get_object failed\n" );
		return false;
	}

	static find_all_fn_t find_all = nullptr;
	if ( !find_all )
	{
		auto resources_klass = il2cpp::get_class_by_name( "Resources", "UnityEngine" );
		if ( resources_klass )
		{
			auto method = il2cpp::get_method_by_name( resources_klass, "FindObjectsOfTypeAll", 1 );
			if ( method )
				find_all = ( find_all_fn_t )method->get_fn_ptr<void*>( );
		}
	}
	if ( !find_all )
	{
		find_all = ( find_all_fn_t )il2cpp::resolve_icall(
			"UnityEngine.Resources::FindObjectsOfTypeAll(System.Type)" );
	}
	if ( !find_all )
	{
		std::printf( "[materials] FindObjectsOfTypeAll not found\n" );
		return false;
	}

	static get_name_fn_t get_name = nullptr;
	if ( !get_name )
	{
		auto object_klass = il2cpp::get_class_by_name( "Object", "UnityEngine" );
		if ( object_klass )
		{
			auto method = il2cpp::get_method_by_name( object_klass, "get_name", 0 );
			if ( method )
				get_name = ( get_name_fn_t )method->get_fn_ptr<void*>( );
		}
	}
	if ( !get_name )
	{
		get_name = ( get_name_fn_t )il2cpp::resolve_icall( "UnityEngine.Object::get_name()" );
	}
	if ( !get_name )
	{
		std::printf( "[materials] Object.get_name not found\n" );
		return false;
	}

	auto array = safe_find_all( find_all, type_obj );
	if ( !array )
	{
		std::printf( "[materials] FindObjectsOfTypeAll returned null\n" );
		return false;
	}

	auto count = *( std::int32_t* )( ( std::uint8_t* )array + 0x18 );
	auto elements = ( std::uint64_t* )( ( std::uint8_t* )array + 0x20 );

	if ( count <= 0 || count > 500000 )
	{
		std::printf( "[materials] invalid material count: %d\n", count );
		return false;
	}

	std::printf( "[materials] found %d materials, dumping...\n", count );

	struct material_entry_t
	{
		std::string safe_name;
		std::int32_t instance_id;
	};

	std::vector<material_entry_t> entries;
	entries.reserve( count );

	for ( std::int32_t i = 0; i < count; i++ )
	{
		auto obj = ( void* )elements[ i ];
		if ( !obj || IsBadReadPtr( obj, 0x20 ) )
			continue;

		auto name_str = safe_get_name( get_name, obj );
		if ( !name_str || IsBadReadPtr( name_str, 0x14 ) )
			continue;

		if ( name_str->size <= 0 || name_str->size > 256 )
			continue;

		auto safe = sanitize_name( name_str->str, name_str->size );
		if ( safe.empty( ) || safe == "unknown" )
			continue;

		auto instance_id = safe_read_instance_id( obj );
		entries.push_back( { safe, instance_id } );
	}

	std::printf( "[materials] %zu valid materials extracted\n", entries.size( ) );

	auto file = std::fopen( output_path, "w" );
	if ( !file )
	{
		std::printf( "[materials] failed to open output: %s\n", output_path );
		return false;
	}

	std::fprintf( file, "#pragma once\n\n" );
	std::fprintf( file, "namespace materials {\n" );

	for ( auto& entry : entries )
		std::fprintf( file, "\tinline static constexpr int %s = %d;\n", entry.safe_name.c_str( ), entry.instance_id );

	std::fprintf( file, "}\n" );
	std::fclose( file );

	std::printf( "[materials] output written to %s (%zu entries)\n", output_path, entries.size( ) );
	return true;
}
