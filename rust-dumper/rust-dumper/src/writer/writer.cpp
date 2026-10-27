#include "writer.hpp"

bool c_writer::open( const char* path )
{
	m_file = std::fopen( path, "w" );
	return m_file != nullptr;
}

void c_writer::close( )
{
	if ( m_file )
	{
		std::fclose( m_file );
		m_file = nullptr;
	}
}

std::string c_writer::fmt_value( std::uint64_t v )
{
	char buf[ 32 ];
	if ( v >= 0x1000 )
		std::snprintf( buf, sizeof( buf ), "0x%llX", v );
	else
		std::snprintf( buf, sizeof( buf ), "0x%llx", v );
	return buf;
}

void c_writer::write_global( const char* name, std::uint64_t value )
{
	if ( !m_file ) return;
	std::fprintf( m_file, "inline static constexpr uintptr_t %s = %s;\n",
		name, fmt_value( value ).c_str( ) );
}

void c_writer::struct_begin( const char* name )
{
	if ( !m_file ) return;
	std::fprintf( m_file, "struct %s\n{\n", name );
}

void c_writer::struct_field( const char* name, std::uint64_t value )
{
	if ( !m_file ) return;
	std::fprintf( m_file, "\tinline static constexpr uintptr_t %s = %s;\n",
		name, fmt_value( value ).c_str( ) );
}

void c_writer::struct_field( const char* name, std::uint64_t value, const char* trailing )
{
	if ( !m_file ) return;
	std::fprintf( m_file, "\tinline static constexpr uintptr_t %s = %s; //%s\n",
		name, fmt_value( value ).c_str( ), trailing );
}

void c_writer::struct_end( )
{
	if ( !m_file ) return;
	std::fprintf( m_file, "};\n" );
}

void c_writer::blank_line( )
{
	if ( !m_file ) return;
	std::fputc( '\n', m_file );
}

void c_writer::write_line( const char* fmt, ... )
{
	if ( !m_file ) return;
	va_list args;
	va_start( args, fmt );
	std::vfprintf( m_file, fmt, args );
	va_end( args );
	std::fputc( '\n', m_file );
}

void c_writer::write_decryption_fn(
	const char* name,
	std::uint64_t fn_rva,
	const c_decryption::constants_t& c,
	std::uint64_t hv_offset )
{
	if ( !m_file ) return;

	std::fprintf( m_file, "uintptr_t decryption::%s(uint64_t a1)\n{\n", name );
	std::fprintf( m_file, "\tstd::uintptr_t rax = driver.read<std::uintptr_t>(a1 + 0x%llX);\n", hv_offset );
	std::fprintf( m_file, "\tstd::uint32_t* rdx = (std::uint32_t*)&rax;\n" );
	std::fprintf( m_file, "\tstd::uint32_t r8d = 0x2;\n" );
	std::fprintf( m_file, "\tstd::uint32_t eax, ecx;\n" );
	std::fprintf( m_file, "\tdo {\n" );
	std::fprintf( m_file, "\t\tecx = *(std::uint32_t*)(rdx);\n" );
	std::fprintf( m_file, "\t\teax = *(std::uint32_t*)(rdx);\n" );
	std::fprintf( m_file, "\t\trdx = (std::uint32_t*)((std::uint8_t*)rdx + 0x4);\n" );

	for ( int i = 0; i < c.op_count; i++ )
	{
		const auto& op = c.ops[ i ];
		switch ( op.type )
		{
		case c_decryption::op_t::op_add:
			std::fprintf( m_file, "\t\tecx = ecx + 0x%X;\n", op.value );
			break;
		case c_decryption::op_t::op_sub:
			std::fprintf( m_file, "\t\tecx = ecx - 0x%X;\n", op.value );
			break;
		case c_decryption::op_t::op_xor:
			std::fprintf( m_file, "\t\tecx = ecx ^ 0x%X;\n", op.value );
			break;
		case c_decryption::op_t::op_rol:
			std::fprintf( m_file, "\t\teax = ecx;\n" );
			std::fprintf( m_file, "\t\tecx = ecx << 0x%X;\n", op.value );
			std::fprintf( m_file, "\t\teax = eax >> 0x%X;\n", 32 - op.value );
			std::fprintf( m_file, "\t\tecx = ecx | eax;\n" );
			break;
		}
	}

	std::fprintf( m_file, "\t\t*((std::uint32_t*)rdx - 1) = ecx;\n" );
	std::fprintf( m_file, "\t\t--r8d;\n" );
	std::fprintf( m_file, "\t} while (r8d);\n" );
	std::fprintf( m_file, "\treturn il2cpp_get_handle(rax);\n" );
	std::fprintf( m_file, "}\n\n" );
}

void c_writer::write_encrypt_fov( std::uint64_t fn_rva, const c_decryption::constants_t& c )
{
	if ( !m_file ) return;

	std::fprintf( m_file, "uint32_t decryption::encrypt_fov(float input) {\n" );
	std::fprintf( m_file, "\tuint32_t v = std::bit_cast<uint32_t>(input);\n" );

	for ( int i = 0; i < c.op_count; i++ )
	{
		const auto& op = c.ops[ i ];
		auto type = op.type;
		auto value = op.value;

		if ( type == c_decryption::op_t::op_add && value >= 0x80000000u )
		{
			type = c_decryption::op_t::op_sub;
			value = 0u - value;
		}
		else if ( type == c_decryption::op_t::op_sub && value >= 0x80000000u )
		{
			type = c_decryption::op_t::op_add;
			value = 0u - value;
		}

		switch ( type )
		{
		case c_decryption::op_t::op_add:
			std::fprintf( m_file, "\tv += 0x%08X;\n", value );
			break;
		case c_decryption::op_t::op_sub:
			std::fprintf( m_file, "\tv -= 0x%08X;\n", value );
			break;
		case c_decryption::op_t::op_xor:
			std::fprintf( m_file, "\tv ^= 0x%08X;\n", value );
			break;
		case c_decryption::op_t::op_rol:
			std::fprintf( m_file, "\tv = (v << %u) | (v >> %u);\n",
				value, 32 - value );
			break;
		}
	}
	std::fprintf( m_file, "\treturn v;\n" );
	std::fprintf( m_file, "}\n" );
}
