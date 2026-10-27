#include "decryption.hpp"
#include "../hde/hde64.h"

#include <windows.h>
#include <cstring>

const char* c_decryption::op_name( std::uint8_t type )
{
	switch ( type )
	{
	case op_t::op_add: return "ADD";
	case op_t::op_sub: return "SUB";
	case op_t::op_xor: return "XOR";
	case op_t::op_rol: return "ROL";
	default:          return "???";
	}
}

c_decryption::constants_t c_decryption::extract_loop( std::uint8_t* fn, std::size_t scan_size )
{
	constants_t c{ };
	if ( IsBadReadPtr( fn, scan_size ) )
		return c;

	std::size_t loop_start = 0;
	std::size_t loop_end = 0;

	for ( std::size_t i = 0; i + 6 <= scan_size && i < 0x100; i++ )
	{
		if ( fn[ i ] == 0x41 && fn[ i + 1 ] >= 0xB8 && fn[ i + 1 ] <= 0xBF &&
			fn[ i + 2 ] == 0x02 && fn[ i + 3 ] == 0x00 && fn[ i + 4 ] == 0x00 && fn[ i + 5 ] == 0x00 )
		{
			loop_start = i + 6;
			break;
		}
		if ( i + 5 <= scan_size && fn[ i ] >= 0xB8 && fn[ i ] <= 0xBF &&
			fn[ i + 1 ] == 0x02 && fn[ i + 2 ] == 0x00 && fn[ i + 3 ] == 0x00 && fn[ i + 4 ] == 0x00 )
		{
			loop_start = i + 5;
			break;
		}
	}

	if ( !loop_start )
		return c;

	for ( std::size_t i = loop_start; i + 4 <= scan_size && i < loop_start + 0x80; i++ )
	{
		if ( fn[ i ] == 0x41 && fn[ i + 1 ] == 0x83 &&
			fn[ i + 2 ] >= 0xE8 && fn[ i + 2 ] <= 0xEF && fn[ i + 3 ] == 0x01 )
		{
			loop_end = i;
			break;
		}
		if ( fn[ i ] == 0x83 &&
			fn[ i + 1 ] >= 0xE8 && fn[ i + 1 ] <= 0xEF && fn[ i + 2 ] == 0x01 )
		{
			loop_end = i;
			break;
		}
		if ( fn[ i ] == 0x41 && fn[ i + 1 ] == 0xFF &&
			fn[ i + 2 ] >= 0xC8 && fn[ i + 2 ] <= 0xCF )
		{
			loop_end = i;
			break;
		}
		if ( fn[ i ] == 0xFF &&
			fn[ i + 1 ] >= 0xC8 && fn[ i + 1 ] <= 0xCF )
		{
			loop_end = i;
			break;
		}
	}

	if ( !loop_end || loop_end <= loop_start )
		return c;

	for ( std::size_t i = loop_start; i < loop_end && c.op_count < max_ops; )
	{
		bool has_rex = ( fn[ i ] >= 0x40 && fn[ i ] <= 0x4F );
		bool rex_w = has_rex && ( fn[ i ] & 0x08 );
		std::size_t op_off = has_rex ? i + 1 : i;

		if ( rex_w )
		{
			hde64s hs;
			auto len = hde64_disasm( fn + i, &hs );
			if ( !len || ( hs.flags & F_ERROR ) )
				len = 1;
			i += len;
			continue;
		}

		if ( fn[ op_off ] == 0x05 && op_off + 5 <= loop_end )
		{
			std::uint32_t imm;
			std::memcpy( &imm, &fn[ op_off + 1 ], 4 );
			c.ops[ c.op_count++ ] = { op_t::op_add, imm };
			i = op_off + 5;
			continue;
		}
		if ( fn[ op_off ] == 0x2D && op_off + 5 <= loop_end )
		{
			std::uint32_t imm;
			std::memcpy( &imm, &fn[ op_off + 1 ], 4 );
			c.ops[ c.op_count++ ] = { op_t::op_sub, imm };
			i = op_off + 5;
			continue;
		}
		if ( fn[ op_off ] == 0x35 && op_off + 5 <= loop_end )
		{
			std::uint32_t imm;
			std::memcpy( &imm, &fn[ op_off + 1 ], 4 );
			c.ops[ c.op_count++ ] = { op_t::op_xor, imm };
			i = op_off + 5;
			continue;
		}
		if ( fn[ op_off ] == 0x81 && op_off + 6 <= loop_end )
		{
			std::uint8_t modrm = fn[ op_off + 1 ];
			std::uint8_t mod = ( modrm >> 6 ) & 3;
			std::uint8_t reg = ( modrm >> 3 ) & 7;
			if ( mod == 3 )
			{
				std::uint32_t imm;
				std::memcpy( &imm, &fn[ op_off + 2 ], 4 );
				if ( reg == 0 )
					c.ops[ c.op_count++ ] = { op_t::op_add, imm };
				else if ( reg == 5 )
					c.ops[ c.op_count++ ] = { op_t::op_sub, imm };
				else if ( reg == 6 )
					c.ops[ c.op_count++ ] = { op_t::op_xor, imm };
				i = op_off + 6;
				continue;
			}
		}
		if ( fn[ op_off ] == 0x83 && op_off + 3 <= loop_end )
		{
			std::uint8_t modrm = fn[ op_off + 1 ];
			std::uint8_t mod = ( modrm >> 6 ) & 3;
			std::uint8_t reg = ( modrm >> 3 ) & 7;
			if ( mod == 3 )
			{
				auto imm = ( std::uint32_t )( std::int32_t )( std::int8_t )fn[ op_off + 2 ];
				if ( reg == 0 )
					c.ops[ c.op_count++ ] = { op_t::op_add, imm };
				else if ( reg == 5 )
					c.ops[ c.op_count++ ] = { op_t::op_sub, imm };
				i = op_off + 3;
				continue;
			}
		}
		if ( fn[ op_off ] == 0xC1 && op_off + 3 <= loop_end )
		{
			std::uint8_t modrm = fn[ op_off + 1 ];
			std::uint8_t mod = ( modrm >> 6 ) & 3;
			std::uint8_t reg = ( modrm >> 3 ) & 7;
			if ( mod == 3 && ( reg == 0 || reg == 4 ) && fn[ op_off + 2 ] < 32 )
			{
				c.ops[ c.op_count++ ] = { op_t::op_rol, fn[ op_off + 2 ] };
				i = op_off + 3;
				continue;
			}
		}

		i++;
	}

	if ( c.op_count >= 4 && ( c.op_count % 2 ) == 0 )
	{
		int half = c.op_count / 2;
		bool unrolled = true;
		for ( int k = 0; k < half; k++ )
		{
			if ( c.ops[ k ].type != c.ops[ k + half ].type ||
				c.ops[ k ].value != c.ops[ k + half ].value )
				unrolled = false;
		}
		if ( unrolled )
		{
			c.op_count = half;
			c.was_unrolled = true;
		}
	}

	c.valid = c.op_count >= 2;
	return c;
}

c_decryption::constants_t c_decryption::extract_inline( std::uint8_t* fn, std::size_t scan_size )
{
	constants_t c{ };
	if ( IsBadReadPtr( fn, scan_size ) )
		return c;

	std::size_t pos = 0;
	while ( pos < scan_size && c.op_count < max_ops )
	{
		hde64s hs;
		auto len = hde64_disasm( fn + pos, &hs );
		if ( !len )
			break;
		if ( hs.flags & F_ERROR )
		{
			pos += len;
			continue;
		}
		if ( hs.opcode == 0xC3 || hs.opcode == 0xCC )
			break;
		if ( hs.opcode == 0xE9 || hs.opcode == 0xEB )
			break;
		if ( hs.opcode == 0xFF && hs.modrm_reg == 4 )
			break;

		if ( hs.rex_w )
		{
			pos += len;
			continue;
		}

		if ( hs.opcode == 0x81 && hs.modrm_mod == 3 && ( hs.flags & F_IMM32 ) )
		{
			if ( hs.modrm_reg == 6 )
				c.ops[ c.op_count++ ] = { op_t::op_xor, hs.imm.imm32 };
			else if ( hs.modrm_reg == 0 )
				c.ops[ c.op_count++ ] = { op_t::op_add, hs.imm.imm32 };
			else if ( hs.modrm_reg == 5 )
				c.ops[ c.op_count++ ] = { op_t::op_sub, hs.imm.imm32 };
		}
		if ( hs.opcode == 0x35 && ( hs.flags & F_IMM32 ) )
			c.ops[ c.op_count++ ] = { op_t::op_xor, hs.imm.imm32 };
		if ( hs.opcode == 0x05 && ( hs.flags & F_IMM32 ) )
			c.ops[ c.op_count++ ] = { op_t::op_add, hs.imm.imm32 };
		if ( hs.opcode == 0x2D && ( hs.flags & F_IMM32 ) )
			c.ops[ c.op_count++ ] = { op_t::op_sub, hs.imm.imm32 };
		if ( hs.opcode == 0xC1 && hs.modrm_mod == 3 &&
			( hs.modrm_reg == 0 || hs.modrm_reg == 4 ) && hs.imm.imm8 < 32 )
			c.ops[ c.op_count++ ] = { op_t::op_rol, ( std::uint32_t )hs.imm.imm8 };

		pos += len;
	}

	if ( c.op_count >= 4 && ( c.op_count % 2 ) == 0 )
	{
		int half = c.op_count / 2;
		bool unrolled = true;
		for ( int k = 0; k < half; k++ )
		{
			if ( c.ops[ k ].type != c.ops[ k + half ].type ||
				c.ops[ k ].value != c.ops[ k + half ].value )
				unrolled = false;
		}
		if ( unrolled )
		{
			c.op_count = half;
			c.was_unrolled = true;
		}
	}

	if ( c.op_count >= 2 )
	{
		bool has_large = false;
		for ( int i = 0; i < c.op_count; i++ )
			if ( c.ops[ i ].type != op_t::op_rol && c.ops[ i ].value > 0x10000 )
				has_large = true;
		c.valid = has_large;
	}
	return c;
}
