#pragma once
#include "shared.hxx"
#include "disk_offsets.hxx"

namespace spoof::disk::mountmgr {
    using namespace helpers;

    static constexpr std::uint32_t kUniqueIdMax = 0x100;
    static constexpr std::uint32_t kMaxListEntries = 256;

    static bool is_valid_list_entry(std::uint64_t flink, std::uint64_t blink) {
        return is_kva(flink) && is_kva(blink);
    }

    static std::uint32_t patch_unique_id_buf(std::uint64_t buf_va) {
        if (!is_kva(buf_va)) return 0;
        std::uint16_t length = kread_val<std::uint16_t>(buf_va);
        if (!length || length > kUniqueIdMax) return 0;
        std::uint64_t data_va = buf_va + sizeof(std::uint16_t);

        std::uint8_t prefix[8] = {};
        kread(data_va, prefix, 8);

        static const std::uint8_t dmio[] = { 'D','M','I','O',':','I','D',':' };
        if (length >= 24 && memcmp(prefix, dmio, 8) == 0) {
            spoof_guid_va(data_va + 8);
            return 1;
        } else if (length == 16) {
            spoof_guid_va(data_va);
            return 1;
        } else if (length >= 2) {
            spoof_general_buf_va(data_va, length);
            return 1;
        }
        return 0;
    }

    static std::uint32_t walk_mounted_list(std::uint64_t head_va, std::uint32_t unique_id_off) {
        std::uint64_t flink = kread_val<std::uint64_t>(head_va);
        std::uint64_t blink = kread_val<std::uint64_t>(head_va + 8);
        if (!is_valid_list_entry(flink, blink)) return 0;

        std::uint32_t patched = 0;
        std::uint32_t visited = 0;
        std::uint64_t entry = flink;
        while (entry != head_va && visited < kMaxListEntries && is_kva(entry)) {
            std::uint64_t next = kread_val<std::uint64_t>(entry);
            if (!is_kva(next)) break;

            if (unique_id_off) {
                std::uint64_t uid_slot_va = entry + unique_id_off;
                std::uint64_t uid_va = kread_val<std::uint64_t>(uid_slot_va);
                if (is_kva(uid_va)) patched += patch_unique_id_buf(uid_va);
            } else {

                std::uint8_t entry_data[128] = {};
                if (kread(entry, entry_data, sizeof(entry_data))) {
                    for (std::uint32_t k = 0; k + 8 <= (std::uint32_t)sizeof(entry_data); k += 8) {
                        std::uint64_t ptr = *reinterpret_cast<const std::uint64_t*>(entry_data + k);
                        if (!is_kva(ptr)) continue;
                        std::uint16_t uid_len = kread_val<std::uint16_t>(ptr);
                        if (uid_len >= 4 && uid_len <= kUniqueIdMax) {
                            patched += patch_unique_id_buf(ptr);
                            if (patched) break;
                        }
                    }
                }
            }

            entry = next;
            ++visited;
        }
        return patched;
    }

    static std::uint32_t patch_mountmgr_device(std::uint64_t dev_va) {
        std::uint64_t ext_va = dev_extension(dev_va);
        if (!is_kva(ext_va)) return 0;

        const auto& off = g_disk_off();
        std::uint32_t patched = 0;

        if (off.mountmgr_device_mounted_list) {
            std::uint64_t head_va = ext_va + off.mountmgr_device_mounted_list;
            patched += walk_mounted_list(head_va, off.mountmgr_mounted_unique_id);
        } else {

            std::vector<std::uint8_t> ext(0x400);
            if (!kread(ext_va, ext.data(), ext.size())) return 0;

            for (std::uint32_t o = 0; o + 16 <= (std::uint32_t)ext.size(); o += 8) {
                std::uint64_t flink = *reinterpret_cast<const std::uint64_t*>(ext.data() + o);
                std::uint64_t blink = *reinterpret_cast<const std::uint64_t*>(ext.data() + o + 8);
                if (!is_valid_list_entry(flink, blink)) continue;
                std::uint64_t head_va = ext_va + o;
                std::uint32_t p = walk_mounted_list(head_va, 0 );
                if (p) { patched += p; break; }
            }
        }

        if (patched) logging::print("disk: mountmgr device 0x%llx patched %u unique IDs", dev_va, patched);
        return patched;
    }

    inline void install() {
        std::uint32_t patched = 0;
        enum_driver_devices(L"\\Driver\\mountmgr", [&](std::uint64_t dev_va) {
            patched += patch_mountmgr_device(dev_va);
        });
        logging::print("disk: mountmgr patched %u unique IDs", patched);
    }

}
