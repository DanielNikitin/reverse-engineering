#pragma once

#include <cstdint>
#include <cstddef>

class c_decryption
{
public:
	struct op_t
	{
		enum : std::uint8_t
		{
			op_add = 0,
			op_xor = 1,
			op_rol = 2,
			op_sub = 3,
		};
		std::uint8_t  type;
		std::uint32_t value;
	};

	static constexpr int max_ops = 16;

	struct constants_t
	{
		op_t ops[ max_ops ]{ };
		int  op_count = 0;
		bool valid = false;
		bool was_unrolled = false;
	};

	static constants_t extract_loop( std::uint8_t* fn, std::size_t scan_size );
	static constants_t extract_inline( std::uint8_t* fn, std::size_t scan_size );

	static const char* op_name( std::uint8_t type );

	static std::uint64_t simulate( std::uint64_t encrypted, const constants_t& c )
	{
		auto* parts = reinterpret_cast<std::uint32_t*>( &encrypted );
		for ( int half = 0; half < 2; half++ )
		{
			std::uint32_t v = parts[ half ];
			for ( int i = 0; i < c.op_count; i++ )
			{
				switch ( c.ops[ i ].type )
				{
				case op_t::op_add: v += c.ops[ i ].value; break;
				case op_t::op_sub: v -= c.ops[ i ].value; break;
				case op_t::op_xor: v ^= c.ops[ i ].value; break;
				case op_t::op_rol: v = ( v << c.ops[ i ].value ) | ( v >> ( 32 - c.ops[ i ].value ) ); break;
				}
			}
			parts[ half ] = v;
		}
		return encrypted;
	}

	static bool ops_match( const constants_t& a, const constants_t& b )
	{
		if ( a.op_count != b.op_count ) return false;
		for ( int i = 0; i < a.op_count; i++ )
			if ( a.ops[ i ].type != b.ops[ i ].type || a.ops[ i ].value != b.ops[ i ].value )
				return false;
		return true;
	}
};
