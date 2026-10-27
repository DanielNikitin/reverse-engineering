#pragma once
#include "shared.hxx"
#include "disk_offsets.hxx"

namespace spoof::disk::stornvme {
    void sync_adapter_serial_cache(std::uint64_t unit_ext_va, const char* ser_buf, std::uint16_t ser_len);
    void patch_namespace_identity(std::uint64_t unit_ext_va, const char* ser_buf, std::uint16_t ser_len);
}

namespace spoof::disk::storport {
    using namespace helpers;

    struct RaidExtLayout {
        std::uint32_t serial_string_off;
        std::uint32_t device_id_ptr_off;
        std::uint32_t rich_desc_ptr_off;
        std::uint32_t vendor_id_off;
        std::uint32_t product_id_off;
        std::uint32_t unit_adapter_off;
        std::uint32_t raid_adapter_miniport_off;
        std::uint32_t miniport_private_ext_off;
    };

    inline RaidExtLayout current_raid_layout() {
        const auto& d = g_disk_off();
        return {
            d.raid_unit_identity + d.stor_identity_serial_number,
            d.raid_unit_identity + d.stor_identity_device_id,
            d.raid_unit_identity + d.stor_identity_rich_device_description,
            d.raid_unit_vendor_id,
            d.raid_unit_product_id,
            d.raid_unit_adapter,
            d.raid_adapter_miniport,
            d.raid_miniport_private_device_ext,
        };
    }

    inline bool ascii_contains_eui(const std::uint8_t* buf, std::uint32_t len) {
        if (!buf || len < 4) return false;
        for (std::uint32_t i = 0; i + 3 < len; ++i) {
            if ((buf[i]|0x20)=='e' && (buf[i+1]|0x20)=='u' && (buf[i+2]|0x20)=='i') return true;
        }
        return false;
    }



    inline std::uint32_t patch_vpd_identification_page(std::uint64_t page_va,
                                                   const char* ser_buf, std::uint16_t ser_len) {
        if (!page_va || !ser_buf || !ser_len) return 0;


        std::uint8_t hdr[4] = {};
        if (!kread(page_va, hdr, 4)) return 0;
        std::uint32_t page_data_len = ((std::uint32_t)hdr[2] << 8) | hdr[3];
        if (page_data_len < 4 || page_data_len > 0x1000) return 0;
        std::uint32_t total_len = page_data_len + 4;

        std::vector<std::uint8_t> page(total_len);
        if (!kread(page_va, page.data(), total_len)) return 0;

        std::uint32_t patched = 0;
        for (std::uint32_t off = 4; off + 4 <= total_len; ) {
            std::uint8_t* desc = page.data() + off;
            std::uint8_t code_set  = desc[0] & 0x0f;
            std::uint8_t id_type   = desc[1] & 0x0f;
            std::uint8_t id_len    = desc[3];
            if (!id_len || off + 4 + id_len > total_len) break;

            if ((id_type==2||id_type==3||id_type==8||id_type==0) &&
                (id_len==8||id_len==16||id_len==20)) {

                if (!s_serial_len) ensure_canonical_from_bytes(desc+4, id_len);
                if (s_identity_len) {
                    if (id_len <= s_identity_len) {
                        std::uint32_t src = s_identity_len - id_len;
                        memcpy(desc+4, s_identity+src, id_len);
                    } else {
                        for (std::uint32_t i = 0; i < id_len; ++i)
                            desc[4+i] = s_identity[i % s_identity_len];
                    }
                }
                ++patched;
            } else if ((code_set==2||code_set==3) && id_len <= 128 &&
                       (ascii_contains_eui(desc+4, id_len) ||
                        ascii_printable(reinterpret_cast<char*>(desc+4), id_len))) {

                if (s_serial_len) {
                    char* cbuf = reinterpret_cast<char*>(desc+4);
                    std::uint32_t start = 0;
                    if (id_len > 4 && (cbuf[0]|0x20)=='e' && (cbuf[1]|0x20)=='u' && (cbuf[2]|0x20)=='i' && cbuf[3]=='.')
                        start = 4;
                    std::uint32_t src = 0;
                    for (std::uint32_t i = start; i < id_len; ++i) {
                        if (start!=4 && (cbuf[i]=='.'||cbuf[i]=='_'||cbuf[i]=='-'||cbuf[i]==' ')) continue;
                        while (src < s_serial_len && (s_serial[src]=='_'||s_serial[src]=='-'||s_serial[src]==' ')) ++src;
                        cbuf[i] = src < s_serial_len ? s_serial[src++] : '0';
                    }
                }
                ++patched;
            }
            off += 4 + id_len;
        }

        if (patched) kwrite(page_va, page.data(), total_len);
        return patched;
    }

    inline bool valid_ansi_serial_at(std::uint64_t ext_va, std::uint32_t string_off) {
        if (!ext_va || !string_off) return false;
        kern_ansi_string as{};
        if (!kread(ext_va + string_off, &as, sizeof(as))) return false;
        if (!as.Length || as.Length > 128 || as.MaximumLength < as.Length) return false;
        if (!is_kva(as.Buffer)) return false;
        char tmp[129] = {};
        if (!kread(as.Buffer, tmp, as.Length)) return false;
        return ascii_printable(tmp, as.Length);
    }

    inline bool raid_layout_matches(std::uint64_t ext_va, const RaidExtLayout& layout) {
        return valid_ansi_serial_at(ext_va, layout.serial_string_off);
    }

    inline void scramble_ascii_va(std::uint64_t buf_va, std::uint32_t length) {
        if (!buf_va || !length) return;
        std::vector<char> buf(length + 1, '\0');
        if (!kread(buf_va, buf.data(), length)) return;
        if (!ascii_printable(buf.data(), length)) return;
        for (std::uint32_t i = 0; i < length; ++i) {
            if (buf[i]==' '||buf[i]=='-'||buf[i]=='_') continue;
            buf[i] = (char)('A' + ((unsigned char)buf[i] + i*13) % 26);
        }
        kwrite(buf_va, buf.data(), length);
    }

    inline void patch_rich_description_va(std::uint64_t ext_va, const RaidExtLayout& layout) {
        if (!ext_va || !layout.rich_desc_ptr_off) return;
        std::uint64_t rich_slot_va = ext_va + layout.rich_desc_ptr_off;
        std::uint64_t rich_va = kread_val<std::uint64_t>(rich_slot_va);
        if (!is_kva(rich_va)) return;
        const auto& off = g_disk_off();
        if (off.rich_desc_vendor_id)
            scramble_ascii_va(rich_va + off.rich_desc_vendor_id, 16);
    }

    inline void patch_raid_device_id_page_va(std::uint64_t ext_va, const RaidExtLayout& layout,
                                              const char* ser_buf, std::uint16_t ser_len) {
        if (!ext_va || !layout.device_id_ptr_off || !ser_buf || !ser_len) return;
        std::uint64_t dev_id_slot_va = ext_va + layout.device_id_ptr_off;
        std::uint64_t dev_id_va = kread_val<std::uint64_t>(dev_id_slot_va);
        if (!is_kva(dev_id_va)) {
            logging::print("disk: RAID VPD device-id slot at +0x%x -> not a KVA", layout.device_id_ptr_off);
            return;
        }
        std::uint32_t p = patch_vpd_identification_page(dev_id_va, ser_buf, ser_len);
        if (p) logging::print("disk: RAID VPD device-id page patched (%u identifiers)", p);
    }

    inline void patch_raid_extension_extras_va(std::uint64_t ext_va, const RaidExtLayout& layout) {
        if (!ext_va) return;
        if (layout.vendor_id_off)
            scramble_ascii_va(ext_va + layout.vendor_id_off, 8);
        patch_rich_description_va(ext_va, layout);
    }

    inline void spoof_raid_units(const wchar_t* driver_name, bool sync_nvme) {
        if (!driver_name) return;
        if (!g_disk_off().raid_unit_identity) {
            logging::print("disk: storport skipping %ls — disk offsets not resolved", driver_name);

        }

        const RaidExtLayout layout = current_raid_layout();
        std::uint32_t patched = 0;

        enum_driver_devices(driver_name, [&](std::uint64_t dev_va) {
            if (dev_type(dev_va) != kDevTypeDisk) return;
            std::uint64_t ext_va = dev_extension(dev_va);
            if (!is_kva(ext_va)) return;

            if (!raid_layout_matches(ext_va, layout)) return;

            kern_ansi_string as{};
            if (!kread(ext_va + layout.serial_string_off, &as, sizeof(as))) return;
            if (!as.Length || as.Length > 128 || !is_kva(as.Buffer)) return;

            char cur_serial[129] = {};
            kread(as.Buffer, cur_serial, as.Length);
            ensure_canonical(cur_serial, as.Length);
            if (!s_serial_len) return;

            logging::print("disk: RAID[%ls] serial before '%.*s'", driver_name, (int)as.Length, cur_serial);

            if (sync_nvme) {
                stornvme::sync_adapter_serial_cache(ext_va, s_serial, s_serial_len);
                stornvme::patch_namespace_identity(ext_va, s_serial, s_serial_len);
            }

            std::uint64_t len_va = ext_va + layout.serial_string_off;
            write_canonical(as.Buffer, as.MaximumLength ? as.MaximumLength : as.Length, len_va);

            if (sync_nvme) {
                stornvme::sync_adapter_serial_cache(ext_va, s_serial, s_serial_len);
                stornvme::patch_namespace_identity(ext_va, s_serial, s_serial_len);
            }

            patch_raid_extension_extras_va(ext_va, layout);
            patch_raid_device_id_page_va(ext_va, layout, s_serial, s_serial_len);
            ++patched;

            logging::print("disk: RAID[%ls] serial after '%.*s'", driver_name, (int)s_serial_len, s_serial);
        });

        logging::print("disk: storport patched %u RAID units (%ls)", patched, driver_name);
    }

}
