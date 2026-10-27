#pragma once

#include "il2cpp_lib.hpp"
#include "unity_lib.hpp"
#include "rust_lib.hpp"

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>

class c_runtime
{
public:
	static bool init( )
	{
		il2cpp::init( );

		s_game_base = ( std::uint64_t )GetModuleHandleA( "GameAssembly.dll" );
		if ( !s_game_base )
			return false;

		auto dos = ( PIMAGE_DOS_HEADER )s_game_base;
		auto nt = ( PIMAGE_NT_HEADERS )( s_game_base + dos->e_lfanew );
		s_image_size = nt->OptionalHeader.SizeOfImage;
		return true;
	}

	static std::uint64_t game_base( )  { return s_game_base; }
	static std::uint32_t image_size( ) { return s_image_size; }

	static il2cpp::il2cpp_class_t* find_class( const char* name, const char* ns = "" )
	{
		return il2cpp::get_class_by_name( name, ns );
	}

	static il2cpp::method_info_t* find_method( il2cpp::il2cpp_class_t* klass, const char* name )
	{
		if ( !klass )
			return nullptr;
		return il2cpp::get_method_by_name( klass, name );
	}

	static il2cpp::field_info_t* find_field( il2cpp::il2cpp_class_t* klass, const char* name )
	{
		if ( !klass )
			return nullptr;
		return il2cpp::get_field_by_name( klass, name );
	}

	static il2cpp::field_info_t* find_field_by_type_class( il2cpp::il2cpp_class_t* klass, il2cpp::il2cpp_class_t* type_klass )
	{
		if ( !klass || !type_klass )
			return nullptr;
		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f )
				continue;
			auto t = f->type( );
			if ( !t )
				continue;
			if ( t->klass( ) == type_klass )
				return f;
		}
		return nullptr;
	}

	static il2cpp::field_info_t* find_field_by_type_contains( il2cpp::il2cpp_class_t* klass, const char* substr )
	{
		if ( !klass || !substr || !*substr )
			return nullptr;
		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f )
				continue;
			auto t = f->type( );
			if ( !t )
				continue;
			auto tn = t->name( );
			if ( tn && std::strstr( tn, substr ) )
				return f;
		}
		return nullptr;
	}

	static il2cpp::field_info_t* find_field_by_type_name_and_flag(
		il2cpp::il2cpp_class_t* klass,
		const char* type_name,
		std::uint32_t required_flag )
	{
		if ( !klass || !type_name )
			return nullptr;
		void* iter = nullptr;
		while ( auto f = klass->fields( &iter ) )
		{
			if ( !f )
				continue;
			if ( !( f->flags( ) & required_flag ) )
				continue;
			auto t = f->type( );
			if ( !t )
				continue;
			auto tn = t->name( );
			if ( tn && !std::strcmp( tn, type_name ) )
				return f;
		}
		return nullptr;
	}

	static il2cpp::il2cpp_class_t* get_inner_static_class( il2cpp::il2cpp_class_t* klass )
	{
		if ( !klass || !klass->type( ) )
			return nullptr;
		void* iter = nullptr;
		while ( auto nested = klass->nested_types( &iter ) )
		{
			if ( !nested )
				continue;
			if ( nested->method_count( ) != 1 )
				continue;
			if ( !il2cpp::get_method_by_name( nested, ".cctor" ) )
				continue;
			return nested;
		}
		return nullptr;
	}

	static std::uint64_t find_klass_slot_in_data( il2cpp::il2cpp_class_t* klass )
	{
		if ( !klass )
			return 0;

		auto dos = ( PIMAGE_DOS_HEADER )s_game_base;
		auto nt = ( PIMAGE_NT_HEADERS )( s_game_base + dos->e_lfanew );
		auto sb = ( std::uint8_t* )&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader;

		auto needle = ( std::uint64_t )klass;

		auto scan_section = [ & ] ( PIMAGE_SECTION_HEADER sec ) -> std::uint64_t {
			std::uint64_t cur = s_game_base + sec->VirtualAddress;
			std::uint64_t end = cur + ( sec->SizeOfRawData > sec->Misc.VirtualSize ? sec->SizeOfRawData : sec->Misc.VirtualSize );
			while ( cur + sizeof( std::uint64_t ) <= end )
			{
				if ( *( std::uint64_t* )cur == needle )
					return cur;
				cur += 8;
			}
			return 0;
		};

		for ( std::uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++ )
		{
			auto sec = ( PIMAGE_SECTION_HEADER )( sb + i * sizeof( IMAGE_SECTION_HEADER ) );
			char name[ 9 ]{ };
			std::memcpy( name, sec->Name, 8 );
			if ( std::strcmp( name, ".data" ) != 0 )
				continue;
			if ( auto a = scan_section( sec ) )
				return a;
		}

		for ( std::uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++ )
		{
			auto sec = ( PIMAGE_SECTION_HEADER )( sb + i * sizeof( IMAGE_SECTION_HEADER ) );
			if ( sec->Characteristics & IMAGE_SCN_MEM_EXECUTE ) continue;
			if ( sec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE ) continue;

			char name[ 9 ]{ };
			std::memcpy( name, sec->Name, 8 );
			if ( !std::strcmp( name, ".data" ) ) continue;
			if ( !std::strcmp( name, ".pdata" ) ) continue;
			if ( !std::strcmp( name, ".rsrc" ) ) continue;
			if ( !std::strcmp( name, ".reloc" ) ) continue;
			if ( auto a = scan_section( sec ) )
				return a;
		}
		return 0;
	}

	static std::uint64_t static_class_rva( il2cpp::il2cpp_class_t* klass )
	{
		if ( auto slot = find_klass_slot_in_data( klass ) )
			return slot - s_game_base;
		return 0;
	}

private:
	inline static std::uint64_t s_game_base = 0;
	inline static std::uint32_t s_image_size = 0;
};
