#pragma once

#include "../runtime/runtime.hpp"
#include "../scanner/scanner.hpp"
#include "../decryption/decryption.hpp"
#include "../verification/verification.hpp"
#include "../materials/materials.hpp"
#include "../writer/writer.hpp"

class c_core
{
public:
	bool run( const char* output_path, bool dump_materials = false );

private:
	struct bn_chain_t
	{
		std::uint64_t base_networkable_rva = 0;
		std::uint32_t static_fields        = 0xB8;
		std::uint32_t wrapper_class_ptr    = 0;
		std::uint32_t parent_static_fields = 0;
		std::uint32_t entities             = 0;
		std::uint64_t hv_offset            = 0x18;
		std::uintptr_t decrypt_0_addr      = 0;
		std::uintptr_t decrypt_1_addr      = 0;
		c_decryption::constants_t decrypt_0{ };
		c_decryption::constants_t decrypt_1{ };
	};

	struct camera_chain_t
	{
		std::uint64_t main_camera_c = 0;
		std::uint32_t camera_static = 0xB8;
		std::uint32_t camera_object = 0;
		std::uint32_t entity        = 0x10;
		std::uint32_t culling_mask  = 0x43C;
	};

	bool resolve_bn_chain( );
	bool resolve_camera_chain( );
	bool resolve_console_system( );
	void resolve_fov_encryption( );

	void verify_bn_chain( );
	void verify_camera_chain( );
	void verify_all( );

	void resolve_item_classes( );

	il2cpp::il2cpp_class_t* m_item_class           = nullptr;
	il2cpp::il2cpp_class_t* m_item_id_class        = nullptr;
	il2cpp::il2cpp_class_t* m_item_container_class = nullptr;
	il2cpp::il2cpp_class_t* m_console_command_class = nullptr;

	void write_il2cpphandle( c_writer& w );
	void write_basenetworkable( c_writer& w );
	void write_camera( c_writer& w );
	void write_base_player( c_writer& w );
	void write_base_combat_entity( c_writer& w );
	void write_base_entity( c_writer& w );
	void write_item_container( c_writer& w );
	void write_player_inventory( c_writer& w );
	void write_decryptions( c_writer& w );

	// Typed writers for classes the original dumper skipped.
	void write_item( c_writer& w );
	void write_item_definition( c_writer& w );
	void write_base_projectile( c_writer& w );
	void write_recoil_properties( c_writer& w );
	void write_world_item( c_writer& w );
	void write_held_entity( c_writer& w );
	void write_model( c_writer& w );
	void write_player_model( c_writer& w );
	void write_player_eyes( c_writer& w );
	void write_player_input( c_writer& w );
	void write_player_walk_movement( c_writer& w );
	void write_convar_graphics( c_writer& w );

	// Raw / diagnostic dumps for classes the typed section can't cover on
	// its own.  These emit a `// raw class: <name>` header followed by one
	// comment line per instance field: `//   <name> @ 0xXX (<type>)`.
	void write_raw_class( c_writer& w, il2cpp::il2cpp_class_t* klass, const char* label );
	void write_raw_class_by_name( c_writer& w, const char* name, const char* label = nullptr );
	void write_missing_classes( c_writer& w );

	// Dumps raw bytes at the address that il2cpp_gchandle_get_target
	// resolves to.  We use this to hand-derive the current il2cpp handle
	// lookup shape when the game's build changes the layout.
	void write_il2cpp_get_handle_dump( c_writer& w );

	std::uint64_t                  m_gc_handles_rva = 0;
	bn_chain_t                     m_bn{ };
	camera_chain_t                 m_camera{ };
	std::uintptr_t                 m_fov_fn_addr = 0;
	c_decryption::constants_t      m_fov_constants{ };
};
