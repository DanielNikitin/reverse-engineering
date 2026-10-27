#pragma once

#include <cstdint>

class c_scanner
{
public:
	struct scan_buf_t
	{
		const std::uint8_t* buf;
		std::uint32_t       len;
		std::uintptr_t      base;
	};

	static std::uintptr_t scan_image( const char* sig );

	static bool read_scan( std::uintptr_t addr, std::uint32_t len, scan_buf_t& out );

	static bool find_mov_base(
		const scan_buf_t& s,
		std::uint32_t start,
		std::uint8_t  base_reg,
		int           nth,
		std::uint32_t& out_pos,
		std::int32_t&  out_disp );

	static bool find_call(
		const scan_buf_t& s,
		std::uint32_t start,
		int           nth,
		std::uint32_t& out_pos,
		std::uintptr_t& out_target );

	static std::uint64_t resolve_gc_handles( );
};
