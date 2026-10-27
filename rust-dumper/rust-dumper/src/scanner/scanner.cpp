#include "scanner.hpp"
#include "../runtime/runtime.hpp"
#include "../hde/hde64.h"

#include <windows.h>
#include <cstring>
#include <vector>

static bool parse_sig( const char* sig, std::vector<int>& out )
{
	out.clear( );
	for ( const char* p = sig; *p; )
	{
		while ( *p == ' ' || *p == '\t' )
			p++;
		if ( !*p )
			break;
		if ( *p == '?' )
		{
			out.push_back( -1 );
			p++;
			if ( *p == '?' )
				p++;
			continue;
		}
		int v = 0;
		int digits = 0;
		while ( digits < 2 && *p && *p != ' ' )
		{
			char c = *p;
			int d =
				( c >= '0' && c <= '9' ) ? c - '0' :
				( c >= 'a' && c <= 'f' ) ? c - 'a' + 10 :
				( c >= 'A' && c <= 'F' ) ? c - 'A' + 10 : -1;
			if ( d < 0 )
				break;
			v = v * 16 + d;
			digits++;
			p++;
		}
		out.push_back( v );
	}
	return !out.empty( );
}

std::uintptr_t c_scanner::scan_image( const char* sig )
{
	auto base = ( const std::uint8_t* )c_runtime::game_base( );
	auto size = ( std::size_t )c_runtime::image_size( );

	std::vector<int> pat;
	if ( !parse_sig( sig, pat ) || pat.size( ) > size )
		return 0;

	const std::size_t limit = size - pat.size( );
	for ( std::size_t i = 0; i <= limit; i++ )
	{
		bool ok = true;
		for ( std::size_t j = 0; j < pat.size( ); j++ )
		{
			if ( pat[ j ] >= 0 && base[ i + j ] != ( std::uint8_t )pat[ j ] )
			{
				ok = false;
				break;
			}
		}
		if ( ok )
			return c_runtime::game_base( ) + i;
	}
	return 0;
}

bool c_scanner::read_scan( std::uintptr_t addr, std::uint32_t len, scan_buf_t& out )
{
	if ( !addr || IsBadReadPtr( ( void* )addr, len ) )
		return false;
	out.buf = ( const std::uint8_t* )addr;
	out.len = len;
	out.base = addr;
	return true;
}

bool c_scanner::find_mov_base(
	const scan_buf_t& s,
	std::uint32_t start,
	std::uint8_t base_reg,
	int nth,
	std::uint32_t& out_pos,
	std::int32_t& out_disp )
{
	int count = 0;
	for ( std::uint32_t i = start; i + 4 <= s.len; i++ )
	{
		if ( s.buf[ i ] != 0x48 || s.buf[ i + 1 ] != 0x8B )
			continue;

		std::uint8_t modrm = s.buf[ i + 2 ];
		std::uint8_t mod = ( modrm >> 6 ) & 3;
		std::uint8_t rm = modrm & 7;

		if ( rm != base_reg || rm == 4 || mod == 0 || mod == 3 )
			continue;

		if ( ++count < nth )
			continue;

		out_pos = i;
		if ( mod == 1 )
		{
			out_disp = ( std::int8_t )s.buf[ i + 3 ];
		}
		else
		{
			if ( i + 7 > s.len )
				continue;
			std::memcpy( &out_disp, &s.buf[ i + 3 ], 4 );
		}
		return true;
	}
	return false;
}

bool c_scanner::find_call(
	const scan_buf_t& s,
	std::uint32_t start,
	int nth,
	std::uint32_t& out_pos,
	std::uintptr_t& out_target )
{
	int count = 0;
	for ( std::uint32_t i = start; i + 5 <= s.len; i++ )
	{
		if ( s.buf[ i ] != 0xE8 )
			continue;
		if ( ++count < nth )
			continue;

		std::int32_t rel;
		std::memcpy( &rel, &s.buf[ i + 1 ], 4 );

		out_pos = i;
		out_target = s.base + i + 5 + rel;
		return true;
	}
	return false;
}

static bool is_writable_rva( std::uint64_t rva )
{
	auto game_base = c_runtime::game_base( );
	auto dos = ( PIMAGE_DOS_HEADER )game_base;
	auto nt = ( PIMAGE_NT_HEADERS )( game_base + dos->e_lfanew );
	auto sb = ( std::uint8_t* )&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader;
	for ( std::uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++ )
	{
		auto sec = ( PIMAGE_SECTION_HEADER )( sb + i * sizeof( IMAGE_SECTION_HEADER ) );
		if ( rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize )
			return ( sec->Characteristics & IMAGE_SCN_MEM_WRITE ) != 0;
	}
	return false;
}

static std::uint8_t* follow_thunk( std::uint8_t* fn )
{
	for ( int hop = 0; hop < 3 && fn && !IsBadReadPtr( fn, 0x20 ); hop++ )
	{
		if ( fn[ 0 ] == 0xFF && fn[ 1 ] == 0x25 )
		{
			std::int32_t d;
			std::memcpy( &d, fn + 2, 4 );
			auto slot = ( std::uintptr_t )fn + 6 + d;
			if ( IsBadReadPtr( ( void* )slot, 8 ) )
				return fn;
			fn = *( std::uint8_t** )slot;
			continue;
		}
		if ( fn[ 0 ] == 0xE9 )
		{
			std::int32_t d;
			std::memcpy( &d, fn + 1, 4 );
			fn = fn + 5 + d;
			continue;
		}
		break;
	}
	return fn;
}

static std::uint64_t scan_image_pattern( const char* sig )
{
	auto base = ( const std::uint8_t* )c_runtime::game_base( );
	auto size = ( std::size_t )c_runtime::image_size( );
	std::size_t pat_len = std::strlen( sig );
	if ( pat_len > size )
		return 0;
	for ( std::size_t i = 0; i + pat_len <= size; i++ )
	{
		bool ok = true;
		for ( std::size_t j = 0; j < pat_len; j++ )
		{
			if ( sig[ j ] == ( char )0xCC )
				continue;
			if ( base[ i + j ] != ( std::uint8_t )sig[ j ] )
			{
				ok = false;
				break;
			}
		}
		if ( ok )
			return ( std::uint64_t )( base + i );
	}
	return 0;
}

static std::uint64_t first_writable_lea_in_window( std::uint8_t* fn, std::size_t window )
{
	auto game_base = c_runtime::game_base( );
	auto cur_end = fn + window;
	auto p = fn;
	while ( p < cur_end )
	{
		hde64s hs;
		auto len = hde64_disasm( p, &hs );
		if ( !len ) { p++; continue; }
		if ( hs.flags & F_ERROR ) { p += len; continue; }

		if ( ( p[ 0 ] == 0x48 || p[ 0 ] == 0x4C ) && len >= 7 )
		{
			std::uint8_t op = p[ 1 ];
			std::uint8_t modrm = p[ 2 ];
			if ( ( op == 0x8D || op == 0x8B ) && ( modrm & 0xC7 ) == 0x05 )
			{
				std::int32_t disp;
				std::memcpy( &disp, p + 3, 4 );
				auto tgt = ( std::uintptr_t )p + 7 + disp;
				if ( tgt >= game_base )
				{
					auto rva = tgt - game_base;
					if ( is_writable_rva( rva ) )
						return rva;
				}
			}
		}
		p += len;
	}
	return 0;
}

std::uint64_t c_scanner::resolve_gc_handles( )
{
	auto game_base = c_runtime::game_base( );

	if ( auto sig = scan_image_pattern( "\x48\x8D\x05\xCC\xCC\xCC\xCC\x83\xE1\x07\xC1\xCC\x03" ) )
	{
		std::int32_t disp;
		std::memcpy( &disp, ( std::uint8_t* )sig + 3, 4 );
		auto tgt = sig + 7 + disp;
		if ( tgt >= game_base )
			return tgt - game_base;
	}

	static const char* exports[] = {
		"il2cpp_gchandle_get_target",
		"il2cpp_gchandle_new_weakref",
		"il2cpp_gchandle_get_target_typed",
	};
	auto game_module = GetModuleHandleA( "GameAssembly.dll" );

	for ( const char* name : exports )
	{
		auto fn = ( std::uint8_t* )GetProcAddress( game_module, name );
		if ( !fn ) continue;
		fn = follow_thunk( fn );
		if ( !fn || IsBadReadPtr( fn, 0x400 ) ) continue;
		if ( ( std::uintptr_t )fn < game_base ) continue;

		if ( auto rva = first_writable_lea_in_window( fn, 0x400 ) )
			return rva;
	}

	for ( const char* name : exports )
	{
		auto fn = ( std::uint8_t* )GetProcAddress( game_module, name );
		if ( !fn ) continue;
		fn = follow_thunk( fn );
		if ( !fn || IsBadReadPtr( fn, 0x200 ) ) continue;

		std::size_t pos = 0;
		while ( pos < 0x200 )
		{
			hde64s hs;
			auto len = hde64_disasm( fn + pos, &hs );
			if ( !len || ( hs.flags & F_ERROR ) ) break;
			if ( hs.opcode == 0xC3 || hs.opcode == 0xCC ) break;

			if ( ( fn[ pos ] == 0x48 || fn[ pos ] == 0x4C ) && len >= 7 )
			{
				std::uint8_t op = fn[ pos + 1 ];
				std::uint8_t modrm = fn[ pos + 2 ];
				if ( ( op == 0x8D || op == 0x8B ) && ( modrm & 0xC7 ) == 0x05 )
				{
					std::int32_t disp;
					std::memcpy( &disp, fn + pos + 3, 4 );
					auto tgt = ( std::uintptr_t )( fn + pos ) + 7 + disp;
					if ( tgt >= game_base )
						return tgt - game_base;
				}
			}
			pos += len;
		}
	}

	return 0;
}
