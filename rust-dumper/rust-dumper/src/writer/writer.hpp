#pragma once

#include "../decryption/decryption.hpp"

#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <string>

class c_writer
{
public:
	bool open( const char* path );
	void close( );
	bool is_open( ) const { return m_file != nullptr; }

	void write_global( const char* name, std::uint64_t value );

	void struct_begin( const char* name );
	void struct_field( const char* name, std::uint64_t value );
	void struct_field( const char* name, std::uint64_t value, const char* trailing );
	void struct_end( );

	// Freeform line writer used by the raw dump section.  Automatically
	// appends a newline.  No escaping — caller controls the payload.
	void write_line( const char* fmt, ... );

	void blank_line( );

	void write_decryption_fn(
		const char* name,
		std::uint64_t fn_rva,
		const c_decryption::constants_t& c,
		std::uint64_t hv_offset );

	void write_encrypt_fov( std::uint64_t fn_rva, const c_decryption::constants_t& c );

private:
	std::FILE* m_file = nullptr;
	static std::string fmt_value( std::uint64_t v );
};
