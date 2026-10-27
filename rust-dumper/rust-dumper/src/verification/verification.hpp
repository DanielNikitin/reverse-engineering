#pragma once

#include "../decryption/decryption.hpp"

#include <cstdint>
#include <vector>

class c_verification
{
public:
	struct bn_hit_t
	{
		std::uint32_t wrapper;
		std::uint32_t parent;
		std::uint32_t entities;
		std::int32_t  size;
	};

	struct camera_hit_t
	{
		std::uint32_t camera_static;
		std::uint32_t camera_object;
		std::uint32_t entity;
		float pos_x, pos_y, pos_z;
	};

	static std::vector<bn_hit_t> bruteforce_bn(
		std::uint64_t game_base,
		std::uint64_t bn_rva,
		const c_decryption::constants_t& decrypt_0,
		const c_decryption::constants_t& decrypt_1,
		std::uint64_t hv_offset );

	static std::vector<camera_hit_t> bruteforce_camera(
		std::uint64_t game_base,
		std::uint64_t main_camera_rva );

	static bool check_bn(
		std::uint64_t game_base,
		std::uint64_t bn_rva,
		std::uint32_t wrapper_off,
		std::uint32_t parent_off,
		std::uint32_t entities_off,
		const c_decryption::constants_t& decrypt_0,
		const c_decryption::constants_t& decrypt_1,
		std::uint64_t hv_offset );

	static bool check_camera(
		std::uint64_t game_base,
		std::uint64_t main_camera_rva,
		std::uint32_t camera_static,
		std::uint32_t camera_object,
		std::uint32_t entity );
};
