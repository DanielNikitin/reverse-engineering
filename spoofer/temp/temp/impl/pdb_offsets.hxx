#pragma once

#define NOMINMAX
#include <Windows.h>
#include <Urlmon.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#pragma comment(lib, "urlmon.lib")

#define PDBLOG(fmt, ...) logging::print("pdb: " fmt, ##__VA_ARGS__)

namespace loader_offsets {

    struct disk_offsets {
        ULONG raid_unit_adapter;
        ULONG raid_unit_identity;
        ULONG raid_unit_vendor_id;
        ULONG raid_unit_product_id;
        ULONG raid_unit_serial_number;
        ULONG raid_unit_stor_async_notify;
        ULONG raid_unit_unit_extension;
        ULONG raid_unit_identify_namespace_data;
        ULONG stor_identity_serial_number;
        ULONG stor_identity_device_id;
        ULONG stor_identity_rich_device_description;
        ULONG rich_desc_vendor_id;
        ULONG rich_desc_model_number;
        ULONG rich_desc_firmware_revision;
        ULONG raid_adapter_miniport;
        ULONG raid_adapter_serial_number;
        ULONG raid_miniport_private_device_ext;
        ULONG raid_hw_device_extension;
        ULONG nvme_adapter_serial_number;
        ULONG nvme_adapter_controller;
        ULONG nvme_controller_identify_controller_data;
        ULONG nvme_namespace_controller;
        ULONG nvme_namespace_identify_data;
        ULONG nvme_namespace_identify_descriptor;
        ULONG nvme_identify_namespace_nguid;
        ULONG nvme_identify_namespace_eui64;
        ULONG nvme_identify_controller_serial;
        ULONG nvme_identify_controller_ieee;
        ULONG stornvme_internal_identify_controller;
        ULONG stornvme_namespace_count;
        ULONG stornvme_namespace_table;
        ULONG stornvme_namespace_serial_low;
        ULONG stornvme_namespace_serial_high;
        ULONG stornvme_namespace_nguid;
        ULONG stornvme_namespace_eui64;
        ULONG volmgr_volume_disk_number;
        ULONG volmgr_volume_partition_length;
        ULONG volmgr_volume_unique_guid;
        ULONG volmgr_volume_is_gpt;
        ULONG volmgr_volume_target_device;
        ULONG mountmgr_device_mounted_list;
        ULONG mountmgr_mounted_unique_id;
        ULONG partmgr_partition_info_ex;
        ULONG partmgr_partition_stable_guid;
        ULONG partmgr_partition_unique_id;
        ULONG partmgr_layout_cache;
        ULONG partmgr_layout_pointer;
        ULONG partmgr_layout_disk_id;
        ULONG stornvme_query_protocol_completion_rva;
        ULONG ataport_device_ata_pt_ioctl_rva;
        ULONG ataport_ide_ata_pt_marshal_rva;
        ULONG storport_rau_ata_pt_ioctl_rva;
        ULONG storport_rau_ata_pt_marshal_rva;
        ULONG storport_ra_send_irp_sync_rva;
    };

    struct dxgkrnl_offsets {
        std::uint64_t edid_cache_rva;
        ULONG    entry_stride;
        ULONG    entry_timestamp;
        ULONG    entry_edid_data;
        ULONG    max_entries;
        std::uint64_t adapter_list_rva;  // RVA of the global LIST_ENTRY head (DxgkpAdapterList etc.)
    };

    struct usbstor_offsets {
        std::uint64_t get_serial_rva;
        ULONG    pdo_to_fdo;
        ULONG    fdo_inq_ptr;
        ULONG    inq_data_off;
        ULONG    inq_serial_desc;
        ULONG    fdo_serial_bytes;
        ULONG    fdo_serial_len;
    };

    struct tcpip_offsets {
        std::uint64_t compartment_set_rva;
        ULONG    cs_count;
        ULONG    cs_table;
        ULONG    cs_entry_offset;
        ULONG    compartment_nb_table;
        ULONG    ht_size_off;
        ULONG    ht_num_entries_off;
        ULONG    ht_directory_off;
        ULONG    nb_entry_offset;
        ULONG    nb_interface;
        ULONG    nb_state;
        ULONG    nb_refcount;
        ULONG    nb_dl_address;
        // FL_INTERFACE walk for SendARP local-address patching; all three required, 0 = unavailable
        ULONG    compartment_if_list;   // offset of LIST_ENTRY InterfaceList in _TCP_COMPARTMENT
        ULONG    if_compartment_link;   // offset of LIST_ENTRY CompartmentLink in _FL_INTERFACE
        ULONG    if_dl_phys_addr;       // offset of DL_PHYSICAL_ADDRESS in _FL_INTERFACE
    };

    struct ndis_offsets {
        ULONG64 miniport_list_rva;
        ULONG64 wpp_main_cb_rva;
        ULONG mp_next_global;
        ULONG mp_physical_medium;
        ULONG mp_eth_db;
        ULONG mp_adapter_ctx;
        ULONG mp_if_avail;
        ULONG mp_if_block;
        ULONG ifb_cur_phys_addr;
        ULONG ifb_perm_phys_addr;
        ULONG ifb_family_entry;
        ULONG pa_length;
        ULONG pa_address;
        ULONG ethdb_adapter_addr;
    };

}

namespace pdb_offsets {
namespace detail {

constexpr char pdb_magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53";
constexpr std::uint32_t tpi_stream = 2;
constexpr std::uint16_t s_ldata32  = 0x110C;
constexpr std::uint16_t s_gdata32  = 0x110D;
constexpr std::uint16_t s_pub32    = 0x110E;
constexpr std::uint16_t s_lproc32  = 0x110F;
constexpr std::uint16_t s_gproc32  = 0x1110;
constexpr std::uint16_t lf_fieldlist    = 0x1203;
constexpr std::uint16_t lf_bclass       = 0x1400;
constexpr std::uint16_t lf_vbclass      = 0x1401;
constexpr std::uint16_t lf_ivbclass     = 0x1402;
constexpr std::uint16_t lf_index        = 0x1404;
constexpr std::uint16_t lf_vfunctab     = 0x1409;
constexpr std::uint16_t lf_enumerate    = 0x1502;
constexpr std::uint16_t lf_member       = 0x150D;
constexpr std::uint16_t lf_static_member= 0x150E;
constexpr std::uint16_t lf_method       = 0x150F;
constexpr std::uint16_t lf_nesttype     = 0x1510;
constexpr std::uint16_t lf_onemethod    = 0x1511;
constexpr std::uint16_t lf_structure    = 0x1505;
constexpr std::uint16_t lf_class        = 0x1504;
constexpr std::uint16_t lf_char         = 0x8000;
constexpr std::uint16_t lf_short        = 0x8001;
constexpr std::uint16_t lf_ushort       = 0x8002;
constexpr std::uint16_t lf_long         = 0x8003;
constexpr std::uint16_t lf_ulong        = 0x8004;
constexpr std::uint16_t lf_quadword     = 0x8009;
constexpr std::uint16_t lf_uquadword    = 0x800A;

#pragma pack(push, 1)
struct msf_super_block {
    char magic[32];
    std::uint32_t block_size, free_block_map_block, num_blocks;
    std::uint32_t num_directory_bytes, unknown, block_map_addr;
};
struct tpi_header {
    std::uint32_t version, header_size, type_index_begin, type_index_end, type_record_bytes;
    std::uint16_t hash_stream_index, hash_aux_stream_index;
    std::uint32_t hash_key_size, num_hash_buckets;
    std::int32_t  hash_value_buffer_offset; std::uint32_t hash_value_buffer_length;
    std::int32_t  index_offset_buffer_offset; std::uint32_t index_offset_buffer_length;
    std::int32_t  hash_adj_buffer_offset; std::uint32_t hash_adj_buffer_length;
};
struct cv_info_pdb70 { std::uint32_t signature; GUID guid; std::uint32_t age; char pdb_file_name[1]; };
struct dbi_header {
    std::int32_t signature; std::uint32_t version_header, age;
    std::uint16_t global_stream_index, build_number, public_stream_index, pdb_dll_version;
    std::uint16_t sym_record_stream, pdb_dll_rbld;
    std::int32_t mod_info_size, section_contribution_size, section_map_size;
    std::int32_t source_info_size, type_server_size;
    std::uint32_t mfc_type_server_index;
    std::int32_t optional_dbg_header_size, ec_substream_size;
    std::uint16_t flags, machine; std::uint32_t padding;
};
struct pubsym32  { std::uint16_t record_len, record_type; std::uint32_t flags, offset; std::uint16_t segment; char name[1]; };
struct datasym32 { std::uint16_t record_len, record_type; std::uint32_t type_index, offset; std::uint16_t segment; char name[1]; };
struct procsym32_prefix {
    std::uint16_t record_len, record_type;
    std::uint32_t parent, end, next, length, debug_start, debug_end, type_index, offset;
    std::uint16_t segment; std::uint8_t flags; char name[1];
};
struct section_contribution {
    std::uint16_t section; char padding1[2]; std::int32_t offset, size;
    std::uint32_t characteristics; std::uint16_t module_index; char padding2[2];
    std::uint32_t data_crc, reloc_crc;
};
struct dbi_module_info {
    std::uint32_t opened; section_contribution contribution;
    std::uint16_t flags, module_symbol_stream;
    std::uint32_t symbol_bytes, c11_bytes, c13_bytes;
    std::uint16_t source_file_count; char padding[2];
    std::uint32_t unused, source_file_name_index, pdb_file_path_name_index;
    char module_name[1];
};
#pragma pack(pop)

struct stream_data  { std::uint32_t size = 0; std::vector<std::uint8_t> data; };
struct member_data  { std::string name; std::uint64_t offset = 0; };
struct type_data    { std::uint32_t index=0; std::uint16_t kind=0, properties=0; std::uint32_t field_list=0; std::string name; std::vector<member_data> members; };
struct public_symbol{ std::string name; std::uint32_t offset=0; std::uint16_t segment=0; };
struct pdb_context  { std::vector<std::uint8_t> raw; std::vector<stream_data> streams; std::uint32_t type_index_begin=0; std::vector<type_data> types; std::vector<public_symbol> public_symbols; };

static std::wstring get_system_module_path(const wchar_t* module_name) {
    wchar_t system_dir[MAX_PATH] = {};
    if (!GetSystemDirectoryW(system_dir, MAX_PATH)) return {};
    std::filesystem::path base(system_dir);
    auto full = base / module_name;
    if (std::filesystem::exists(full)) return full.wstring();
    auto drv = base / L"drivers" / module_name;
    if (std::filesystem::exists(drv)) return drv.wstring();
    return full.wstring();
}

static bool read_file_safe(const std::wstring& path, std::vector<std::uint8_t>* data) {

    {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (f) {
            auto sz = f.tellg();
            if (sz > 0) {
                f.seekg(0);
                data->resize((std::size_t)sz);
                if (f.read(reinterpret_cast<char*>(data->data()), sz)) return true;
            }
        }
    }

    wchar_t tmp_dir[MAX_PATH] = {}, tmp_file[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tmp_dir)) return false;
    if (!GetTempFileNameW(tmp_dir, L"pdb", 0, tmp_file)) return false;
    if (!CopyFileW(path.c_str(), tmp_file, FALSE)) { DeleteFileW(tmp_file); return false; }
    bool ok = false;
    {
        std::ifstream f(tmp_file, std::ios::binary | std::ios::ate);
        if (f) {
            auto sz = f.tellg();
            if (sz > 0) {
                f.seekg(0);
                data->resize((std::size_t)sz);
                ok = !!f.read(reinterpret_cast<char*>(data->data()), sz);
            }
        }
    }
    DeleteFileW(tmp_file);
    return ok;
}

static bool has_pdb_msf_magic(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    char magic[sizeof(pdb_magic) - 1] = {};
    return f.read(magic, sizeof(magic)) && memcmp(magic, pdb_magic, sizeof(magic)) == 0;
}

static void* rva_to_ptr(std::vector<std::uint8_t>& image, DWORD rva) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return nullptr;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD ss = sec[i].VirtualAddress;
        DWORD sz = (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
        if (rva >= ss && rva < ss + sz) {
            DWORD raw = sec[i].PointerToRawData + (rva - ss);
            if (raw < image.size()) return image.data() + raw;
        }
    }
    return nullptr;
}

static std::wstring widen_ascii(const char* v) {
    std::wstring out; while (*v) out.push_back((unsigned char)*v++); return out;
}

static std::wstring pdb_guid_age(const GUID& g, std::uint32_t age) {
    std::wstringstream ss;
    ss << std::uppercase << std::hex << std::setfill(L'0')
       << std::setw(8) << g.Data1 << std::setw(4) << g.Data2 << std::setw(4) << g.Data3;
    for (unsigned char b : g.Data4) ss << std::setw(2) << (unsigned)b;
    ss << std::hex << age;
    return ss.str();
}

static bool find_module_pdb(const wchar_t* module_name, std::wstring* pdb_path) {
    const auto module_path = get_system_module_path(module_name);
    if (module_path.empty()) return false;
    std::vector<std::uint8_t> image;
    if (!read_file_safe(module_path, &image)) {
        PDBLOG("[-] Failed to read %ls", module_name);
        return false;
    }
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    auto dbg = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(rva_to_ptr(image, dd.VirtualAddress));
    if (!dbg) return false;
    std::uint32_t cnt = dd.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (std::uint32_t i = 0; i < cnt; ++i) {
        if (dbg[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
        if (dbg[i].PointerToRawData + sizeof(cv_info_pdb70) > image.size()) continue;
        auto cv = reinterpret_cast<cv_info_pdb70*>(image.data() + dbg[i].PointerToRawData);
        if (cv->signature != 'SDSR') continue;
        const auto pdb_file = std::filesystem::path(cv->pdb_file_name).filename();
        const auto pdb_name = widen_ascii(pdb_file.string().c_str());
        const auto guid_age = pdb_guid_age(cv->guid, cv->age);
        wchar_t temp_path[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp_path);
        std::filesystem::path cache = std::filesystem::path(temp_path) / L"physmem_symbols" / pdb_name / guid_age;
        std::filesystem::create_directories(cache);
        auto local = cache / pdb_name;
        if (std::filesystem::exists(local)) {
            if (has_pdb_msf_magic(local)) { *pdb_path = local.wstring(); PDBLOG("[+] Using cached PDB for %ls", module_name); return true; }
            std::error_code ec; std::filesystem::remove(local, ec);
        }
        const auto url = L"https://msdl.microsoft.com/download/symbols/" + pdb_name + L"/" + guid_age + L"/" + pdb_name;
        PDBLOG("[+] Downloading PDB for %ls", module_name);
        if (FAILED(URLDownloadToFileW(nullptr, url.c_str(), local.wstring().c_str(), 0, nullptr))) {
            PDBLOG("[-] Download failed for %ls", module_name); return false;
        }
        if (!has_pdb_msf_magic(local)) {
            std::error_code ec; std::filesystem::remove(local, ec); return false;
        }
        *pdb_path = local.wstring();
        return true;
    }
    return false;
}

static bool get_section_rva(const wchar_t* module_name, std::uint16_t segment, std::uint32_t* section_rva) {
    if (!segment) return false;
    std::vector<std::uint8_t> image;
    if (!read_file_safe(get_system_module_path(module_name), &image)) return false;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (segment > nt->FileHeader.NumberOfSections) return false;
    *section_rva = IMAGE_FIRST_SECTION(nt)[segment - 1].VirtualAddress;
    return true;
}

static bool parse_streams(pdb_context* ctx) {
    if (ctx->raw.size() < sizeof(msf_super_block)) return false;
    auto sb = reinterpret_cast<const msf_super_block*>(ctx->raw.data());
    if (memcmp(sb->magic, pdb_magic, sizeof(pdb_magic) - 1) != 0) return false;
    const std::uint32_t bs = sb->block_size;
    const std::uint32_t dir_blocks = (sb->num_directory_bytes + bs - 1) / bs;
    const std::uint64_t bm_off = (std::uint64_t)sb->block_map_addr * bs;
    if (bm_off + (std::uint64_t)dir_blocks * 4 > ctx->raw.size()) return false;
    auto bm = reinterpret_cast<const std::uint32_t*>(ctx->raw.data() + bm_off);
    std::vector<std::uint8_t> dir((std::size_t)dir_blocks * bs);
    for (std::uint32_t i = 0; i < dir_blocks; ++i) {
        std::uint64_t src = (std::uint64_t)bm[i] * bs;
        if (src + bs > ctx->raw.size()) return false;
        memcpy(dir.data() + (std::size_t)i * bs, ctx->raw.data() + src, bs);
    }
    const std::uint32_t* cur = reinterpret_cast<const std::uint32_t*>(dir.data());
    std::uint32_t sc = *cur++;
    ctx->streams.resize(sc);
    for (std::uint32_t i = 0; i < sc; ++i) ctx->streams[i].size = *cur++;
    for (std::uint32_t i = 0; i < sc; ++i) {
        if (!ctx->streams[i].size || ctx->streams[i].size == 0xFFFFFFFF) continue;
        std::uint32_t nb = (ctx->streams[i].size + bs - 1) / bs;
        ctx->streams[i].data.resize((std::size_t)nb * bs);
        for (std::uint32_t b = 0; b < nb; ++b) {
            std::uint64_t src = (std::uint64_t)(*cur++) * bs;
            if (src + bs > ctx->raw.size()) return false;
            memcpy(ctx->streams[i].data.data() + (std::size_t)b * bs, ctx->raw.data() + src, bs);
        }
    }
    return true;
}

static void add_symbol(pdb_context* ctx, const char* name, std::size_t max_len, std::uint32_t off, std::uint16_t seg) {
    ctx->public_symbols.push_back({ std::string(name, strnlen(name, max_len)), off, seg });
}

static void parse_symbol_records(pdb_context* ctx, const std::uint8_t* ptr, const std::uint8_t* end) {
    while (ptr + 4 <= end) {
        std::uint16_t rlen = *reinterpret_cast<const std::uint16_t*>(ptr);
        if (!rlen || ptr + 2 + rlen > end) break;
        std::uint16_t rtype = *reinterpret_cast<const std::uint16_t*>(ptr + 2);
        if (rtype == s_pub32 && rlen >= sizeof(pubsym32) - 2) {
            auto p = reinterpret_cast<const pubsym32*>(ptr);
            add_symbol(ctx, p->name, rlen - (offsetof(pubsym32, name) - 2), p->offset, p->segment);
        } else if ((rtype == s_gdata32 || rtype == s_ldata32) && rlen >= sizeof(datasym32) - 2) {
            auto p = reinterpret_cast<const datasym32*>(ptr);
            add_symbol(ctx, p->name, rlen - (offsetof(datasym32, name) - 2), p->offset, p->segment);
        } else if ((rtype == s_gproc32 || rtype == s_lproc32) && rlen >= sizeof(procsym32_prefix) - 2) {
            auto p = reinterpret_cast<const procsym32_prefix*>(ptr);
            add_symbol(ctx, p->name, rlen - (offsetof(procsym32_prefix, name) - 2), p->offset, p->segment);
        }
        ptr += 2 + rlen;
    }
}

static bool parse_module_symbols(pdb_context* ctx, const dbi_header* dbi) {
    const std::uint8_t* ptr = reinterpret_cast<const std::uint8_t*>(dbi + 1);
    const std::uint8_t* end = ptr + dbi->mod_info_size;
    while (ptr + sizeof(dbi_module_info) <= end) {
        auto mod = reinterpret_cast<const dbi_module_info*>(ptr);
        if (mod->module_symbol_stream != 0xFFFF &&
            ctx->streams.size() > mod->module_symbol_stream &&
            ctx->streams[mod->module_symbol_stream].data.size() >= 4) {
            const auto& st = ctx->streams[mod->module_symbol_stream];
            const std::uint8_t* sp = st.data.data();
            std::uint32_t sig = *reinterpret_cast<const std::uint32_t*>(sp);
            if (sig == 4 || sig == 0xeffe0000) sp += 4;
            parse_symbol_records(ctx, sp, sp + st.size);
        }
        const std::uint8_t* names = reinterpret_cast<const std::uint8_t*>(mod->module_name);
        auto mn_end = static_cast<const std::uint8_t*>(memchr(names, 0, end - names));
        if (!mn_end) return false;
        auto on_end = static_cast<const std::uint8_t*>(memchr(mn_end + 1, 0, end - mn_end - 1));
        if (!on_end) return false;
        ptr = on_end + 1;
        ptr += (4 - (reinterpret_cast<uintptr_t>(ptr) & 3)) & 3;
    }
    return true;
}

static bool parse_public_symbols(pdb_context* ctx) {
    if (ctx->streams.size() <= 3 || ctx->streams[3].data.size() < sizeof(dbi_header)) return false;
    auto dbi = reinterpret_cast<const dbi_header*>(ctx->streams[3].data.data());
    if (ctx->streams.size() <= dbi->sym_record_stream) return false;
    const auto& st = ctx->streams[dbi->sym_record_stream];
    parse_symbol_records(ctx, st.data.data(), st.data.data() + st.size);
    return parse_module_symbols(ctx, dbi);
}

static bool parse_cv_integer(const std::uint8_t*& ptr, std::uint32_t& rem, std::uint64_t* val) {
    if (rem < 2) return false;
    std::uint16_t leaf = *reinterpret_cast<const std::uint16_t*>(ptr);
    ptr += 2; rem -= 2;
    if (leaf < 0x8000) { *val = leaf; return true; }
    std::uint32_t bytes = 0;
    switch (leaf) {
    case lf_char: bytes=1; break; case lf_short: bytes=2; break;
    case lf_ushort: bytes=2; break; case lf_long: bytes=4; break;
    case lf_ulong: bytes=4; break; case lf_quadword: bytes=8; break;
    case lf_uquadword: bytes=8; break; default: return false;
    }
    if (rem < bytes) return false;
    switch (leaf) {
    case lf_char:      *val = *reinterpret_cast<const std::int8_t*>(ptr);   break;
    case lf_short:     *val = *reinterpret_cast<const std::int16_t*>(ptr);  break;
    case lf_ushort:    *val = *reinterpret_cast<const std::uint16_t*>(ptr); break;
    case lf_long:      *val = *reinterpret_cast<const std::int32_t*>(ptr);  break;
    case lf_ulong:     *val = *reinterpret_cast<const std::uint32_t*>(ptr); break;
    case lf_quadword:  *val = *reinterpret_cast<const std::int64_t*>(ptr);  break;
    case lf_uquadword: *val = *reinterpret_cast<const std::uint64_t*>(ptr); break;
    }
    ptr += bytes; rem -= bytes; return true;
}

static bool read_c_string(const std::uint8_t*& ptr, std::uint32_t& rem, std::string* val) {
    const void* z = memchr(ptr, 0, rem);
    if (!z) return false;
    std::size_t n = static_cast<const std::uint8_t*>(z) - ptr;
    val->assign(reinterpret_cast<const char*>(ptr), n);
    ptr += n + 1; rem -= (std::uint32_t)(n + 1); return true;
}

static bool skip_c_string(const std::uint8_t*& ptr, std::uint32_t& rem) {
    std::string s; return read_c_string(ptr, rem, &s);
}

static void skip_padding(const std::uint8_t*& ptr, std::uint32_t& rem) {
    while (rem && *ptr >= 0xF0) {
        std::uint32_t a = (*ptr & 0x0F) < 1 ? 1u : (unsigned)(*ptr & 0x0F);
        if (a > rem) a = rem;
        ptr += a; rem -= a;
    }
}

static type_data* find_type(pdb_context* ctx, std::uint32_t index) {
    if (index < ctx->type_index_begin) return nullptr;
    std::uint32_t vi = index - ctx->type_index_begin;
    if (vi >= ctx->types.size()) return nullptr;
    return &ctx->types[vi];
}

static bool parse_fieldlist(const std::uint8_t* data, std::uint32_t size, type_data* type) {
    const std::uint8_t* ptr = data;
    std::uint32_t rem = size;
    while (rem >= 2) {
        skip_padding(ptr, rem);
        if (rem < 2) break;
        std::uint16_t leaf = *reinterpret_cast<const std::uint16_t*>(ptr);
        ptr += 2; rem -= 2;
        if (leaf == lf_member) {
            if (rem < 6) return false;
            ptr += 2; ptr += 4; rem -= 6;
            std::uint64_t offset = 0;
            if (!parse_cv_integer(ptr, rem, &offset)) return false;
            std::string name;
            if (!read_c_string(ptr, rem, &name)) return false;
            type->members.push_back({name, offset});
        } else if (leaf == lf_enumerate) {
            if (rem < 2) return false;
            ptr += 2; rem -= 2;
            std::uint64_t v = 0;
            if (!parse_cv_integer(ptr, rem, &v) || !skip_c_string(ptr, rem)) return false;
        } else if (leaf == lf_bclass) {
            if (rem < 6) return false;
            ptr += 2; ptr += 4; rem -= 6;
            std::uint64_t v = 0;
            if (!parse_cv_integer(ptr, rem, &v)) return false;
        } else if (leaf == lf_vbclass || leaf == lf_ivbclass) {
            if (rem < 8) return false;
            ptr += 2; ptr += 4; ptr += 4; rem -= 10;
            std::uint64_t a = 0, b = 0;
            if (!parse_cv_integer(ptr, rem, &a) || !parse_cv_integer(ptr, rem, &b)) return false;
        } else if (leaf == lf_static_member || leaf == lf_nesttype) {
            if (rem < 6) return false;
            ptr += 2; ptr += 4; rem -= 6;
            if (!skip_c_string(ptr, rem)) return false;
        } else if (leaf == lf_method) {
            if (rem < 6) return false;
            ptr += 2; ptr += 4; rem -= 6;
            if (!skip_c_string(ptr, rem)) return false;
        } else if (leaf == lf_onemethod) {
            if (rem < 6) return false;
            std::uint16_t attr = *reinterpret_cast<const std::uint16_t*>(ptr);
            ptr += 2; ptr += 4; rem -= 6;
            std::uint8_t mp = (attr >> 2) & 0x07;
            if (mp == 4 || mp == 5 || mp == 6) {
                if (rem < 4) return false;
                ptr += 4; rem -= 4;
            }
            if (!skip_c_string(ptr, rem)) return false;
        } else if (leaf == lf_vfunctab) {
            if (rem < 4) return false;
            ptr += 4; rem -= 4;
        } else if (leaf == lf_index) {
            if (rem < 4) return false;
            ptr += 4; rem -= 4;
        } else { break; }
    }
    return true;
}

static bool parse_structure(const std::uint8_t* data, std::uint32_t size, std::uint16_t leaf, type_data* type) {
    const std::uint8_t* ptr = data;
    std::uint32_t rem = size;
    if (rem < sizeof(std::uint16_t)*2 + sizeof(std::uint32_t)*3) return false;
    type->kind = leaf;
    ptr += 2;
    type->properties = *reinterpret_cast<const std::uint16_t*>(ptr); ptr += 2;
    type->field_list  = *reinterpret_cast<const std::uint32_t*>(ptr); ptr += 12;
    rem -= 4 + 12;
    std::uint64_t sz = 0;
    if (!parse_cv_integer(ptr, rem, &sz)) return false;
    return read_c_string(ptr, rem, &type->name);
}

static bool parse_tpi(pdb_context* ctx) {
    if (ctx->streams.size() <= tpi_stream || ctx->streams[tpi_stream].data.size() < sizeof(tpi_header)) return false;
    const auto& st = ctx->streams[tpi_stream];
    auto hdr = reinterpret_cast<const tpi_header*>(st.data.data());
    if (hdr->header_size < sizeof(tpi_header) ||
        hdr->type_index_end <= hdr->type_index_begin ||
        hdr->header_size + hdr->type_record_bytes > st.data.size()) return false;
    ctx->type_index_begin = hdr->type_index_begin;
    ctx->types.reserve(hdr->type_index_end - hdr->type_index_begin);
    const std::uint8_t* ptr = st.data.data() + hdr->header_size;
    std::uint32_t rem = hdr->type_record_bytes;
    std::uint32_t idx = hdr->type_index_begin;
    while (rem >= 2 && idx < hdr->type_index_end) {
        std::uint16_t rlen = *reinterpret_cast<const std::uint16_t*>(ptr);
        if (rlen < 2 || rlen + 2 > rem) return false;
        const std::uint8_t* rec = ptr + 2;
        std::uint16_t leaf = *reinterpret_cast<const std::uint16_t*>(rec);
        const std::uint8_t* data = rec + 2;
        std::uint32_t dsz = rlen - 2;
        type_data type = {}; type.index = idx; type.kind = leaf;
        if (leaf == lf_structure || leaf == lf_class)
            parse_structure(data, dsz, leaf, &type);
        else if (leaf == lf_fieldlist)
            parse_fieldlist(data, dsz, &type);
        ctx->types.push_back(std::move(type));
        ptr += rlen + 2; rem -= rlen + 2; ++idx;
    }
    return true;
}

static type_data* find_struct(pdb_context* ctx, const char* name) {
    type_data* fwd = nullptr;
    for (auto& t : ctx->types) {
        if ((t.kind != lf_structure && t.kind != lf_class) || t.name != name) continue;
        if (t.properties & 0x80) { if (!fwd) fwd = &t; continue; }
        return &t;
    }
    return fwd;
}

static bool resolve_field(pdb_context* ctx, const char* struct_name, const char* field_name, ULONG* out) {
    type_data* s = find_struct(ctx, struct_name);
    if (!s) return false;
    type_data* fl = find_type(ctx, s->field_list);
    if (!fl || fl->kind != lf_fieldlist) return false;
    for (const auto& m : fl->members) {
        if (m.name == field_name) {
            *out = (ULONG)m.offset;
            PDBLOG("[+] %s::%s = 0x%lx", struct_name, field_name, *out);
            return true;
        }
    }
    PDBLOG("[-] %s::%s not found", struct_name, field_name);
    return false;
}

static bool resolve_public_symbol_rva(const wchar_t* module_name, pdb_context* ctx,
                                       const char* symbol_name, std::uint64_t* rva,
                                       bool quiet = false) {
    if (!parse_public_symbols(ctx)) return false;
    for (const auto& sym : ctx->public_symbols) {
        if (sym.name != symbol_name) continue;
        std::uint32_t sec_rva = 0;
        if (!get_section_rva(module_name, sym.segment, &sec_rva)) return false;
        *rva = (std::uint64_t)sec_rva + sym.offset;
        PDBLOG("[+] %ls!%s = rva 0x%llx", module_name, symbol_name, (unsigned long long)*rva);
        return true;
    }
    if (!quiet) PDBLOG("[-] %ls!%s not found", module_name, symbol_name);
    return false;
}

static bool read_module_image(const wchar_t* module_name, std::vector<std::uint8_t>* image) {
    const auto path = get_system_module_path(module_name);
    if (path.empty()) return false;
    return read_file_safe(path, image);
}

static const std::uint8_t* module_rva_to_ptr(std::vector<std::uint8_t>& image, std::uint64_t rva) {
    if (rva > MAXDWORD) return nullptr;
    return static_cast<const std::uint8_t*>(rva_to_ptr(image, (DWORD)rva));
}

static bool load_pdb_context(const wchar_t* module_name, pdb_context* ctx, bool parse_types) {
    std::wstring pdb_path;
    if (!find_module_pdb(module_name, &pdb_path)) return false;
    if (!read_file_safe(pdb_path, &ctx->raw)) return false;
    PDBLOG("[+] Parsing PDB for %ls", module_name);
    if (!parse_streams(ctx)) return false;
    return !parse_types || parse_tpi(ctx);
}

static bool extract_disp32(const std::uint8_t* code, std::size_t size, const std::vector<int>& pat, ULONG* out) {
    for (std::size_t i = 0; i + pat.size() <= size; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] >= 0 && code[i+j] != (std::uint8_t)pat[j]) { match = false; break; }
        if (!match) continue;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] == -2 && i+j+4 <= size) { *out = *reinterpret_cast<const ULONG*>(code+i+j); return true; }
    }
    return false;
}

static bool extract_disp8(const std::uint8_t* code, std::size_t size, const std::vector<int>& pat, ULONG* out) {
    for (std::size_t i = 0; i + pat.size() <= size; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] >= 0 && code[i+j] != (std::uint8_t)pat[j]) { match = false; break; }
        if (!match) continue;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] == -2) { *out = code[i+j]; return true; }
    }
    return false;
}

static bool extract_disp8_nth(const std::uint8_t* code, std::size_t size, const std::vector<int>& pat, std::size_t occ, ULONG* out) {
    std::size_t seen = 0;
    for (std::size_t i = 0; i + pat.size() <= size; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] >= 0 && code[i+j] != (std::uint8_t)pat[j]) { match = false; break; }
        if (!match) continue;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] == -2) { if (seen++ == occ) { *out = code[i+j]; return true; } break; }
    }
    return false;
}

static bool resolve_stornvme_layout(pdb_context* ctx, loader_offsets::disk_offsets* d) {
    std::vector<std::uint8_t> image;
    if (!read_module_image(L"stornvme.sys", &image)) return false;
    std::uint64_t serial_rva = 0;
    if (!resolve_public_symbol_rva(L"stornvme.sys", ctx, "FormInquirySerialNumberData", &serial_rva)) return false;
    const std::uint8_t* code = module_rva_to_ptr(image, serial_rva);
    if (!code) return false;
    if (!extract_disp32(code, 0x300, {0x4C,0x8B,0xA9,-2,-1,-1,-1}, &d->stornvme_internal_identify_controller) ||
        !extract_disp32(code, 0x300, {0x4A,0x8B,0x84,0xE6,-2,-1,-1,-1}, &d->stornvme_namespace_table) ||
        !extract_disp8 (code, 0x300, {0x4C,0x8D,0x50,-2}, &d->stornvme_namespace_nguid) ||
        !extract_disp8 (code, 0x300, {0x4C,0x8D,0x78,-2}, &d->stornvme_namespace_eui64) ||
        !extract_disp8_nth(code, 0x300, {0x0F,0xB7,0x48,-2}, 0, &d->stornvme_namespace_serial_high) ||
        !extract_disp8_nth(code, 0x300, {0x0F,0xB7,0x48,-2}, 1, &d->stornvme_namespace_serial_low)) {
        PDBLOG("[-] stornvme FormInquirySerialNumberData pattern scan failed");
        return false;
    }
    std::uint64_t idents_rva = 0;
    if (!resolve_public_symbol_rva(L"stornvme.sys", ctx, "FormInquiryDeviceIdentifiersData", &idents_rva)) return false;
    const std::uint8_t* icode = module_rva_to_ptr(image, idents_rva);
    if (!icode) return false;
    if (!extract_disp32(icode, 0x400, {0x44,0x3B,0xA6,-2,-1,-1,-1}, &d->stornvme_namespace_count)) {
        PDBLOG("[-] stornvme FormInquiryDeviceIdentifiersData pattern scan failed");
        return false;
    }
    PDBLOG("[+] stornvme: ident_ctrl=0x%lx ns_count=0x%lx ns_table=0x%lx nguid=0x%lx eui64=0x%lx",
        d->stornvme_internal_identify_controller, d->stornvme_namespace_count,
        d->stornvme_namespace_table, d->stornvme_namespace_nguid, d->stornvme_namespace_eui64);
    return true;
}

static bool resolve_volmgr_layout(pdb_context* ctx, loader_offsets::disk_offsets* d) {
    std::vector<std::uint8_t> image;
    if (!read_module_image(L"volmgr.sys", &image)) return false;
    std::uint64_t rva = 0;
    if (!resolve_public_symbol_rva(L"volmgr.sys", ctx,
        "?VmpSetPartitionInformation@@YAXPEAVVM_VOLUME_EXTENSION@@PEAU_PARTITION_INFORMATION_EX@@@Z", &rva))
        return false;
    const std::uint8_t* code = module_rva_to_ptr(image, rva);
    if (!code) return false;

    bool ok = extract_disp32(code,0x300,{0x40,0x38,0xA9,-2,-1,-1,-1},&d->volmgr_volume_is_gpt) &&
              extract_disp32(code,0x300,{0x0F,0x10,0x87,-2,-1,-1,-1},&d->volmgr_volume_unique_guid) &&
              extract_disp32(code,0x300,{0x8B,0x87,-2,-1,-1,-1,0x89,0x44},&d->volmgr_volume_disk_number) &&
              extract_disp32(code,0x300,{0x48,0x39,0x91,-2,-1,-1,-1,0x74},&d->volmgr_volume_partition_length);
    if (!ok) {
        ok = extract_disp32(code,0x300,{0x44,0x38,0xA3,-2,-1,-1,-1},&d->volmgr_volume_is_gpt) &&
             extract_disp32(code,0x300,{0x0F,0x10,0x83,-2,-1,-1,-1},&d->volmgr_volume_unique_guid) &&
             extract_disp32(code,0x300,{0x8B,0x83,-2,-1,-1,-1,0x89,0x45},&d->volmgr_volume_disk_number) &&
             extract_disp32(code,0x300,{0x48,0x39,0x83,-2,-1,-1,-1,0x75},&d->volmgr_volume_partition_length);
    }
    if (!ok) { PDBLOG("[-] volmgr VmpSetPartitionInformation pattern scan failed"); return false; }
    std::uint64_t qrva = 0;
    if (!resolve_public_symbol_rva(L"volmgr.sys", ctx,
        "?VmpQueryUniqueIdInternal@@YAJPEAVVM_VOLUME_EXTENSION@@PEAGPEAE@Z", &qrva))
        return false;
    const std::uint8_t* qcode = module_rva_to_ptr(image, qrva);
    if (!qcode) return false;
    if (!extract_disp32(qcode,0x120,{0x49,0x8B,0x82,-2,-1,-1,-1},&d->volmgr_volume_target_device) &&
        !extract_disp32(qcode,0x120,{0x49,0x8B,0x81,-2,-1,-1,-1},&d->volmgr_volume_target_device)) {
        PDBLOG("[-] volmgr VmpQueryUniqueIdInternal pattern scan failed"); return false;
    }
    PDBLOG("[+] volmgr: disk_num=0x%lx guid=0x%lx is_gpt=0x%lx target=0x%lx",
        d->volmgr_volume_disk_number, d->volmgr_volume_unique_guid,
        d->volmgr_volume_is_gpt, d->volmgr_volume_target_device);
    return true;
}

static bool resolve_mountmgr_layout(pdb_context* ctx, loader_offsets::disk_offsets* d) {
    std::vector<std::uint8_t> image;
    if (!read_module_image(L"mountmgr.sys", &image)) return false;
    std::uint64_t rva = 0;
    if (!resolve_public_symbol_rva(L"mountmgr.sys", ctx, "QueryPointsFromMemory", &rva)) return false;
    const std::uint8_t* code = module_rva_to_ptr(image, rva);
    if (!code) return false;
    bool ok = extract_disp8(code,0x700,{0x48,0x8B,0x7E,-2,0x4C,0x8D,0x76},&d->mountmgr_device_mounted_list) &&
              extract_disp8(code,0x700,{0x48,0x8B,0x57,-2,0x41,0x0F,0xB7,0x07},&d->mountmgr_mounted_unique_id);
    if (!ok) {
        bool uid_ok = extract_disp8(code,0x700,{0x49,0x8B,0x46,-2,0x4D,0x8D,0x7E},&d->mountmgr_mounted_unique_id) ||
                      extract_disp8(code,0x700,{0x48,0x8B,0x56,-2,0x0F,0xB7,0x5E},&d->mountmgr_mounted_unique_id);
        ok = extract_disp8(code,0x700,{0x4D,0x8B,0x75,-2,0x49,0x83,0xC5},&d->mountmgr_device_mounted_list) && uid_ok;
    }
    if (!ok) { PDBLOG("[-] mountmgr QueryPointsFromMemory pattern scan failed"); return false; }
    PDBLOG("[+] mountmgr: mounted_list=0x%lx unique_id=0x%lx",
        d->mountmgr_device_mounted_list, d->mountmgr_mounted_unique_id);
    return true;
}

static bool resolve_partmgr_layout(pdb_context* ctx, loader_offsets::disk_offsets* d) {
    std::vector<std::uint8_t> image;
    if (!read_module_image(L"partmgr.sys", &image)) return false;
    std::uint64_t rva = 0;
    if (!resolve_public_symbol_rva(L"partmgr.sys", ctx,
        "?PmBuildUniqueId@@YAJPEAU_DEVICE_EXTENSION@@PEAU_PARTITION_EXTENSION@@@Z", &rva))
        return false;
    const std::uint8_t* code = module_rva_to_ptr(image, rva);
    if (!code) return false;
    if (!extract_disp32(code,0x180,{0x83,0xBA,-2,-1,-1,-1,0x01},&d->partmgr_partition_info_ex) ||
        !extract_disp8 (code,0x180,{0x48,0x8B,0x6F,-2},&d->partmgr_partition_unique_id)) {
        PDBLOG("[-] partmgr PmBuildUniqueId pattern scan failed"); return false;
    }
    std::uint64_t sg_rva = 0;
    if (!resolve_public_symbol_rva(L"partmgr.sys", ctx,
        "?PmBuildStableGuid@@YAJPEAU_DEVICE_EXTENSION@@PEAU_PARTITION_EXTENSION@@@Z", &sg_rva))
        return false;
    const std::uint8_t* sgcode = module_rva_to_ptr(image, sg_rva);
    if (!sgcode) return false;
    if (!extract_disp8(sgcode,0x100,{0x48,0x8D,0x4A,-2},&d->partmgr_partition_stable_guid) &&
        !extract_disp8(sgcode,0x100,{0xF3,0x0F,0x7F,0x42,-2},&d->partmgr_partition_stable_guid)) {
        PDBLOG("[-] partmgr PmBuildStableGuid pattern scan failed"); return false;
    }
    std::uint64_t gl_rva = 0;
    if (!resolve_public_symbol_rva(L"partmgr.sys", ctx, "PmGetDriveLayoutEx", &gl_rva)) return false;
    const std::uint8_t* glcode = module_rva_to_ptr(image, gl_rva);
    if (!glcode) return false;
    bool layout_ok =
        (extract_disp32(glcode,0x500,{0x48,0x8B,0x86,-2,-1,-1,-1},&d->partmgr_layout_pointer) ||
         extract_disp32(glcode,0x500,{0x48,0x8B,0xB5,-2,-1,-1,-1},&d->partmgr_layout_pointer)) &&
        (extract_disp32(glcode,0x500,{0x48,0x8D,0x8E,-2,-1,-1,-1},&d->partmgr_layout_cache) ||
         extract_disp32(glcode,0x500,{0x48,0x8D,0x8D,-2,-1,-1,-1},&d->partmgr_layout_cache));
    if (!layout_ok) { PDBLOG("[-] partmgr PmGetDriveLayoutEx pattern scan failed"); return false; }
    d->partmgr_layout_disk_id = 0x8;
    PDBLOG("[+] partmgr: info_ex=0x%lx stable_guid=0x%lx unique_id=0x%lx layout_cache=0x%lx layout_ptr=0x%lx",
        d->partmgr_partition_info_ex, d->partmgr_partition_stable_guid,
        d->partmgr_partition_unique_id, d->partmgr_layout_cache, d->partmgr_layout_pointer);
    return true;
}

}

inline bool resolve_disk(loader_offsets::disk_offsets* out) {
    if (!out) return false;
    *out = {};


    detail::pdb_context stor_ctx;
    if (!detail::load_pdb_context(L"storport.sys", &stor_ctx, true)) {
        PDBLOG("[-] storport.sys PDB load failed"); return false;
    }


    const char* id_struct = detail::find_struct(&stor_ctx, "_STOR_IDENTITY") ? "_STOR_IDENTITY" : "_STOR_SCSI_IDENTITY";

    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "Adapter",               &out->raid_unit_adapter);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "Identity",              &out->raid_unit_identity);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "VendorId",              &out->raid_unit_vendor_id);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "ProductId",             &out->raid_unit_product_id);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "SerialNumber",          &out->raid_unit_serial_number);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "StorAsyncNotify",       &out->raid_unit_stor_async_notify);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "UnitExtension",         &out->raid_unit_unit_extension);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "IdentifyNamespaceData", &out->raid_unit_identify_namespace_data);

    detail::resolve_field(&stor_ctx, id_struct, "SerialNumber",          &out->stor_identity_serial_number);
    detail::resolve_field(&stor_ctx, id_struct, "DeviceId",              &out->stor_identity_device_id);
    detail::resolve_field(&stor_ctx, id_struct, "RichDeviceDescription", &out->stor_identity_rich_device_description);

    detail::resolve_field(&stor_ctx, "_STOR_RICH_DEVICE_DESCRIPTION", "VendorId",          &out->rich_desc_vendor_id);
    detail::resolve_field(&stor_ctx, "_STOR_RICH_DEVICE_DESCRIPTION", "ModelNumber",       &out->rich_desc_model_number);
    detail::resolve_field(&stor_ctx, "_STOR_RICH_DEVICE_DESCRIPTION", "FirmwareRevision",  &out->rich_desc_firmware_revision);

    detail::resolve_field(&stor_ctx, "_RAID_ADAPTER_EXTENSION", "Miniport",           &out->raid_adapter_miniport);
    detail::resolve_field(&stor_ctx, "_RAID_ADAPTER_EXTENSION", "AdapterSerialNumber",&out->raid_adapter_serial_number);
    detail::resolve_field(&stor_ctx, "_RAID_MINIPORT",          "PrivateDeviceExt",   &out->raid_miniport_private_device_ext);
    detail::resolve_field(&stor_ctx, "_RAID_HW_DEVICE_EXT",     "HwDeviceExtension",  &out->raid_hw_device_extension);


    detail::resolve_field(&stor_ctx, "NVME_IDENTIFY_NAMESPACE_DATA",   "NGUID", &out->nvme_identify_namespace_nguid);
    detail::resolve_field(&stor_ctx, "NVME_IDENTIFY_NAMESPACE_DATA",   "EUI64", &out->nvme_identify_namespace_eui64);
    detail::resolve_field(&stor_ctx, "NVME_IDENTIFY_CONTROLLER_DATA",  "SN",    &out->nvme_identify_controller_serial);
    detail::resolve_field(&stor_ctx, "NVME_IDENTIFY_CONTROLLER_DATA",  "IEEE",  &out->nvme_identify_controller_ieee);


    detail::resolve_field(&stor_ctx, "_NVME_ADAPTER_EXTENSION",    "AdapterSerialNumber",       &out->nvme_adapter_serial_number);
    detail::resolve_field(&stor_ctx, "_NVME_ADAPTER_EXTENSION",    "NVMeController",            &out->nvme_adapter_controller);
    detail::resolve_field(&stor_ctx, "_NVME_CONTROLLER",           "IdentifyControllerData",    &out->nvme_controller_identify_controller_data);
    detail::resolve_field(&stor_ctx, "_NVME_NAMESPACE_EXTENSION",  "NvmeController",            &out->nvme_namespace_controller);
    detail::resolve_field(&stor_ctx, "_NVME_NAMESPACE_EXTENSION",  "IdentifyNamespaceData",     &out->nvme_namespace_identify_data);
    detail::resolve_field(&stor_ctx, "_NVME_NAMESPACE_EXTENSION",  "IdentifyNamespaceDescriptor",&out->nvme_namespace_identify_descriptor);

    if (!out->raid_unit_identity || !out->raid_unit_adapter || !out->stor_identity_serial_number) {
        PDBLOG("[-] Critical storport fields not resolved"); return false;
    }


    detail::pdb_context stornvme_ctx;
    if (!detail::load_pdb_context(L"stornvme.sys", &stornvme_ctx, false))
        PDBLOG("[!] stornvme.sys PDB load failed — private namespace patching disabled");
    else if (!detail::resolve_stornvme_layout(&stornvme_ctx, out))
        PDBLOG("[!] stornvme layout scan failed — private namespace patching disabled");


    detail::pdb_context volmgr_ctx;
    if (!detail::load_pdb_context(L"volmgr.sys", &volmgr_ctx, false)) {
        PDBLOG("[-] volmgr.sys PDB load failed"); return false;
    }
    if (!detail::resolve_volmgr_layout(&volmgr_ctx, out)) {
        PDBLOG("[-] volmgr layout scan failed"); return false;
    }


    detail::pdb_context mountmgr_ctx;
    if (!detail::load_pdb_context(L"mountmgr.sys", &mountmgr_ctx, false)) {
        PDBLOG("[-] mountmgr.sys PDB load failed"); return false;
    }
    if (!detail::resolve_mountmgr_layout(&mountmgr_ctx, out)) {
        PDBLOG("[-] mountmgr layout scan failed"); return false;
    }


    detail::pdb_context partmgr_ctx;
    if (!detail::load_pdb_context(L"partmgr.sys", &partmgr_ctx, false)) {
        PDBLOG("[-] partmgr.sys PDB load failed"); return false;
    }
    if (!detail::resolve_partmgr_layout(&partmgr_ctx, out)) {
        PDBLOG("[-] partmgr layout scan failed"); return false;
    }

    return true;
}

inline bool resolve_dxgkrnl(loader_offsets::dxgkrnl_offsets* out) {
    if (!out) return false;
    *out = {};

    detail::pdb_context ctx;
    if (!detail::load_pdb_context(L"dxgkrnl.sys", &ctx, false)) {
        PDBLOG("[-] dxgkrnl.sys PDB load failed"); return false;
    }

    // EDID cache
    if (!detail::resolve_public_symbol_rva(L"dxgkrnl.sys", &ctx,
            "?s_pEdidCache@EDIDCACHE@DxgMonitor@@0PEAV12@EA", &out->edid_cache_rva) &&
        !detail::resolve_public_symbol_rva(L"dxgkrnl.sys", &ctx,
            "s_pEdidCache", &out->edid_cache_rva)) {

        out->edid_cache_rva = 0x161418ULL;
        PDBLOG("[~] dxgkrnl s_pEdidCache fallback RVA 0x%llx", out->edid_cache_rva);
    }

    out->entry_stride    = 0x98u;
    out->entry_timestamp = 0x08u;
    out->entry_edid_data = 0x20u;
    out->max_entries     = 4u;

    static const char* k_list_syms[] = {
        "DxgkpAdapterList", "gpDxgAdapterList", "DxgkAdapterList", "DxgAdapterList",
        "DxgpAdapterList", "g_DxgAdapterList", "DxgkpAdapterListHead",
        "DxgpAdapterListHead", "g_pAdapterList", "DxgAdapterListHead", nullptr
    };
    for (int i = 0; k_list_syms[i]; ++i) {
        if (detail::resolve_public_symbol_rva(L"dxgkrnl.sys", &ctx,
                k_list_syms[i], &out->adapter_list_rva, true)) break;
    }
    if (!out->adapter_list_rva)
        PDBLOG("[!] dxgkrnl adapter list symbol not found");

    return true;
}

inline bool resolve_usbstor(loader_offsets::usbstor_offsets* out) {
    if (!out) return false;
    *out = {};

    detail::pdb_context ctx;
    if (!detail::load_pdb_context(L"USBSTOR.SYS", &ctx, false)) {
        PDBLOG("[-] USBSTOR.SYS PDB load failed"); return false;
    }


    if (!detail::resolve_public_symbol_rva(L"USBSTOR.SYS", &ctx,
            "USBSTOR_GetDeviceSerialNumber", &out->get_serial_rva)) {
        PDBLOG("[-] USBSTOR_GetDeviceSerialNumber not found"); return false;
    }

    std::vector<std::uint8_t> image;
    if (!detail::read_module_image(L"USBSTOR.SYS", &image)) {
        PDBLOG("[-] USBSTOR.SYS image read failed"); return false;
    }

    const std::uint8_t* code = detail::module_rva_to_ptr(image, out->get_serial_rva);
    if (!code) { PDBLOG("[-] USBSTOR_GetDeviceSerialNumber not in image"); return false; }

    constexpr std::size_t scan_sz = 0x180;


    if (!detail::extract_disp8(code, scan_sz, {0x48, 0x8B, 0x7D, -2}, &out->pdo_to_fdo))
        { out->pdo_to_fdo = 0x40u; PDBLOG("[~] USBSTOR pdo_to_fdo fallback 0x40"); }


    if (!detail::extract_disp8(code, scan_sz, {0x48, 0x8B, 0x47, -2}, &out->fdo_inq_ptr))
        { out->fdo_inq_ptr = 0x10u; PDBLOG("[~] USBSTOR fdo_inq_ptr fallback 0x10"); }


    if (!detail::extract_disp8(code, scan_sz, {0x48, 0x8B, 0x70, -2}, &out->inq_data_off))
        { out->inq_data_off = 0x40u; PDBLOG("[~] USBSTOR inq_data_off fallback 0x40"); }


    if (!detail::extract_disp8(code, scan_sz, {0x48, 0x8B, 0x46, -2}, &out->inq_serial_desc))
        { out->inq_serial_desc = 0x48u; PDBLOG("[~] USBSTOR inq_serial_desc fallback 0x48"); }


    if (!detail::extract_disp8(code, scan_sz, {0x4C, 0x8D, 0x47, -2}, &out->fdo_serial_bytes))
        { out->fdo_serial_bytes = 0x6Cu; PDBLOG("[~] USBSTOR fdo_serial_bytes fallback 0x6C"); }


    if (!detail::extract_disp8(code, scan_sz, {0x89, 0x47, -2}, &out->fdo_serial_len))
        { out->fdo_serial_len = 0x40u; PDBLOG("[~] USBSTOR fdo_serial_len fallback 0x40"); }

    PDBLOG("[+] USBSTOR: pdo_to_fdo=0x%lx inq_ptr=0x%lx inq_data=0x%lx desc=0x%lx serial=0x%lx len=0x%lx",
        out->pdo_to_fdo, out->fdo_inq_ptr, out->inq_data_off,
        out->inq_serial_desc, out->fdo_serial_bytes, out->fdo_serial_len);
    return true;
}

inline bool resolve_ndis(loader_offsets::ndis_offsets* out) {
    if (!out) return false;
    *out = {};

    detail::pdb_context ctx;
    if (!detail::load_pdb_context(L"ndis.sys", &ctx, true)) {
        PDBLOG("[-] ndis.sys PDB load failed"); return false;
    }


    if (!detail::resolve_public_symbol_rva(L"ndis.sys", &ctx,
            "?ndisMiniportList@@3PEAU_NDIS_MINIPORT_BLOCK@@EA", &out->miniport_list_rva))
        detail::resolve_public_symbol_rva(L"ndis.sys", &ctx, "ndisMiniportList", &out->miniport_list_rva);

    detail::resolve_public_symbol_rva(L"ndis.sys", &ctx, "WPP_MAIN_CB", &out->wpp_main_cb_rva);

    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "NextGlobalMiniport",       &out->mp_next_global);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "MiniportPhysicalMediumType",&out->mp_physical_medium);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "EthDB",                    &out->mp_eth_db);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "MiniportAdapterContext",   &out->mp_adapter_ctx);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "IfBlockAvailable",         &out->mp_if_avail);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "IfBlock",                  &out->mp_if_block);

    if (!detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "ifPhysAddress", &out->ifb_cur_phys_addr))
        { out->ifb_cur_phys_addr = 0x464; PDBLOG("[~] ifPhysAddress hardcoded 0x464"); }
    if (!detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "PermanentPhysAddress", &out->ifb_perm_phys_addr))
        { out->ifb_perm_phys_addr = 0x486; PDBLOG("[~] PermanentPhysAddress hardcoded 0x486"); }

    if (!detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "Link",              &out->ifb_family_entry) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "IfFamilyListEntry", &out->ifb_family_entry) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "ndisIfBlockList",   &out->ifb_family_entry) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "FamilyListEntry",   &out->ifb_family_entry))
        { out->ifb_family_entry = 0x4D0; PDBLOG("[~] ifb_family_entry hardcoded 0x4D0"); }

    if (!detail::resolve_field(&ctx, "_IF_PHYSICAL_ADDRESS_LH", "Length",  &out->pa_length) ||
        !detail::resolve_field(&ctx, "_IF_PHYSICAL_ADDRESS_LH", "Address", &out->pa_address))
        { out->pa_length = 0; out->pa_address = 2; }

    if (!detail::resolve_field(&ctx, "_X_FILTER",   "AdapterAddress", &out->ethdb_adapter_addr) &&
        !detail::resolve_field(&ctx, "_ETH_FILTER", "AdapterAddress", &out->ethdb_adapter_addr))
        { out->ethdb_adapter_addr = 0x150; PDBLOG("[~] ethdb_adapter_addr hardcoded 0x150"); }

    return out->mp_next_global && out->mp_eth_db && out->miniport_list_rva;
}

inline bool resolve_tcpip(loader_offsets::tcpip_offsets* out) {
    if (!out) return false;
    *out = {};



    detail::pdb_context ctx;
    if (!detail::load_pdb_context(L"tcpip.sys", &ctx, false)) {
        PDBLOG("[-] tcpip.sys PDB load failed"); return false;
    }


    if (!detail::resolve_public_symbol_rva(L"tcpip.sys", &ctx, "TcpCompartmentSet", &out->compartment_set_rva)) {
        PDBLOG("[-] TcpCompartmentSet not found in tcpip.sys PDB"); return false;
    }


    OSVERSIONINFOW ovi = { sizeof(ovi) };
    using rtl_get_ver_t = NTSTATUS(WINAPI*)(OSVERSIONINFOW*);
    auto rtlGetVersion = reinterpret_cast<rtl_get_ver_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (rtlGetVersion) rtlGetVersion(&ovi);
    const bool is_win11 = ovi.dwBuildNumber >= 22000;


    if (!detail::resolve_field(&ctx, "_TCP_COMPARTMENT_SET", "CompartmentCount", &out->cs_count) &&
        !detail::resolve_field(&ctx, "_TCP_COMPARTMENT_SET", "Count",            &out->cs_count))
        { out->cs_count = is_win11 ? 0x4D9Cu : 0x4D74u; PDBLOG("[~] cs_count fallback 0x%lx", out->cs_count); }

    if (!detail::resolve_field(&ctx, "_TCP_COMPARTMENT_SET", "CompartmentTable", &out->cs_table) &&
        !detail::resolve_field(&ctx, "_TCP_COMPARTMENT_SET", "Table",            &out->cs_table))
        { out->cs_table = is_win11 ? 0x4DA0u : 0x4D78u; PDBLOG("[~] cs_table fallback 0x%lx", out->cs_table); }

    out->cs_entry_offset = 0x30u;

    if (!detail::resolve_field(&ctx, "_TCP_COMPARTMENT", "NeighborSubInterface", &out->compartment_nb_table) &&
        !detail::resolve_field(&ctx, "_TCP_COMPARTMENT", "NeighborTable",        &out->compartment_nb_table))
        { out->compartment_nb_table = 0x290u; PDBLOG("[~] compartment_nb_table fallback 0x290"); }

    if (!detail::resolve_field(&ctx, "_RTL_DYNAMIC_HASH_TABLE", "TableSize",   &out->ht_size_off))
        { out->ht_size_off = 0x08u; }
    if (!detail::resolve_field(&ctx, "_RTL_DYNAMIC_HASH_TABLE", "NumEntries",  &out->ht_num_entries_off))
        { out->ht_num_entries_off = 0x14u; }
    if (!detail::resolve_field(&ctx, "_RTL_DYNAMIC_HASH_TABLE", "Directory",   &out->ht_directory_off))
        { out->ht_directory_off = 0x20u; }

    out->nb_entry_offset = 0x28u;
    out->nb_interface    = 0x08u;

    if (!detail::resolve_field(&ctx, "_NL_NEIGHBOR_ENTRY", "State",     &out->nb_state) &&
        !detail::resolve_field(&ctx, "NL_NEIGHBOR",        "State",     &out->nb_state))
        { out->nb_state = is_win11 ? 0x1Cu : 0x40u; PDBLOG("[~] nb_state fallback 0x%lx", out->nb_state); }

    if (!detail::resolve_field(&ctx, "_NL_NEIGHBOR_ENTRY", "RefCount",  &out->nb_refcount) &&
        !detail::resolve_field(&ctx, "NL_NEIGHBOR",        "RefCount",  &out->nb_refcount))
        { out->nb_refcount = is_win11 ? 0x60u : 0x04u; PDBLOG("[~] nb_refcount fallback 0x%lx", out->nb_refcount); }

    if (!detail::resolve_field(&ctx, "_NL_NEIGHBOR_ENTRY", "DlAddress", &out->nb_dl_address) &&
        !detail::resolve_field(&ctx, "NL_NEIGHBOR",        "DlAddress", &out->nb_dl_address))
        { out->nb_dl_address = is_win11 ? 0xA8u : 0x88u; PDBLOG("[~] nb_dl_address fallback 0x%lx", out->nb_dl_address); }

    {
        detail::pdb_context tpi_ctx;
        if (detail::load_pdb_context(L"tcpip.sys", &tpi_ctx, true)) {
            detail::resolve_field(&tpi_ctx, "_TCP_COMPARTMENT", "InterfaceList",      &out->compartment_if_list);
            if (!out->compartment_if_list)
                detail::resolve_field(&tpi_ctx, "_IP_COMPARTMENT",  "InterfaceList",  &out->compartment_if_list);

            detail::resolve_field(&tpi_ctx, "_FL_INTERFACE", "CompartmentLink",        &out->if_compartment_link);
            if (!out->if_compartment_link)
                detail::resolve_field(&tpi_ctx, "_NL_INTERFACE", "CompartmentLink",    &out->if_compartment_link);

            detail::resolve_field(&tpi_ctx, "_FL_INTERFACE", "DlPhysicalAddress",      &out->if_dl_phys_addr);
            if (!out->if_dl_phys_addr)
                detail::resolve_field(&tpi_ctx, "_NL_INTERFACE", "DlPhysicalAddress",  &out->if_dl_phys_addr);
            if (!out->if_dl_phys_addr)
                detail::resolve_field(&tpi_ctx, "_FL_INTERFACE", "CurrentPhysicalAddress", &out->if_dl_phys_addr);

            if (out->compartment_if_list && out->if_compartment_link && out->if_dl_phys_addr)
                PDBLOG("[+] FL_INTERFACE fields resolved: if_list=0x%lx link=0x%lx phys=0x%lx",
                    out->compartment_if_list, out->if_compartment_link, out->if_dl_phys_addr);
            else
                PDBLOG("[~] FL_INTERFACE field resolution incomplete — SendARP patch disabled");
        } else {
            PDBLOG("[~] tcpip.sys TPI load failed — FL_INTERFACE SendARP patch disabled");
        }
    }

    return true;
}

}
