#pragma once
#include "shared.hxx"
#include "disk_offsets.hxx"

namespace spoof::disk::partmgr {
    using namespace helpers;

    static constexpr std::uint32_t kPartStyle         = 0;
    static constexpr std::uint32_t kPartStartOff      = 8;
    static constexpr std::uint32_t kPartLengthOff     = 16;
    static constexpr std::uint32_t kPartNumberOff     = 24;

    static constexpr std::uint32_t kPartGptTypeOff    = 32;
    static constexpr std::uint32_t kPartGptIdOff      = 48;

    static constexpr std::uint32_t kDriveLayoutPartitionEntryOff = 48;
    static constexpr std::uint32_t kPartInfoExSize    = 144;
    static constexpr std::uint32_t kPartStyleGPT      = 1;

    static bool looks_like_partition_info(std::uint64_t info_va) {
        if (!is_kva(info_va)) return false;
        std::uint32_t style = kread_val<std::uint32_t>(info_va + kPartStyle);
        if (style != kPartStyleGPT) return false;
        std::int64_t length = kread_val<std::int64_t>(info_va + kPartLengthOff);
        return length > 0 && length < (std::int64_t)0x1000000000000000LL;
    }

    static void patch_guid(std::uint64_t guid_va) {
        spoof_guid_va(guid_va);
    }

    static std::uint32_t patch_mountdev_unique_id(std::uint64_t uid_va, const std::uint8_t* guid_bytes) {
        if (!is_kva(uid_va)) return 0;
        std::uint16_t length = kread_val<std::uint16_t>(uid_va);
        if (length < 24 || length > 0x100) return 0;
        std::uint64_t data_va = uid_va + sizeof(std::uint16_t);
        std::uint8_t data[8] = {};
        if (!kread(data_va, data, 8)) return 0;
        static const std::uint8_t dmio_prefix[] = { 'D','M','I','O',':','I','D',':' };
        if (memcmp(data, dmio_prefix, 8) != 0) return 0;
        kwrite(data_va + 8, guid_bytes, 16);
        return 1;
    }

    static std::uint32_t patch_partition_extension(std::uint64_t ext_va, std::uint32_t salt) {
        const auto& off = g_disk_off();
        if (!off.partmgr_partition_info_ex) return 0;

        std::uint64_t info_va = ext_va + off.partmgr_partition_info_ex;
        if (!looks_like_partition_info(info_va)) return 0;

        std::uint32_t patched = 0;


        std::uint64_t part_id_va = info_va + kPartGptIdOff;
        patch_guid(part_id_va);
        ++patched;


        if (off.partmgr_partition_stable_guid) {
            std::uint8_t new_guid[16];
            kread(part_id_va, new_guid, 16);
            kwrite(ext_va + off.partmgr_partition_stable_guid, new_guid, 16);
            ++patched;
        }


        if (off.partmgr_partition_unique_id) {
            std::uint64_t uid_slot_va = ext_va + off.partmgr_partition_unique_id;
            std::uint64_t uid_va = kread_val<std::uint64_t>(uid_slot_va);
            if (is_kva(uid_va)) {
                std::uint8_t guid_bytes[16];
                kread(part_id_va, guid_bytes, 16);
                patched += patch_mountdev_unique_id(uid_va, guid_bytes);
            }
        }

        return patched;
    }

    static bool valid_drive_layout(std::uint64_t layout_va) {
        if (!is_kva(layout_va)) return false;
        std::uint32_t style = kread_val<std::uint32_t>(layout_va);
        if (style != kPartStyleGPT) return false;
        std::uint32_t count = kread_val<std::uint32_t>(layout_va + 4);
        return count > 0 && count <= 256;
    }

    static std::uint32_t patch_drive_layout(std::uint64_t layout_va, std::uint32_t salt) {
        if (!valid_drive_layout(layout_va)) return 0;
        const auto& off = g_disk_off();
        std::uint32_t patched = 0;


        spoof_guid_va(layout_va + off.partmgr_layout_disk_id);
        ++patched;


        std::uint32_t count = kread_val<std::uint32_t>(layout_va + 4);
        for (std::uint32_t i = 0; i < count && i < 256; ++i) {
            std::uint64_t entry_va = layout_va + kDriveLayoutPartitionEntryOff + (std::uint64_t)i * kPartInfoExSize;
            std::uint32_t entry_style = kread_val<std::uint32_t>(entry_va + kPartStyle);
            std::int64_t  entry_len   = kread_val<std::int64_t>(entry_va + kPartLengthOff);
            if (entry_style != kPartStyleGPT || entry_len <= 0) continue;
            spoof_guid_va(entry_va + kPartGptIdOff);
            ++patched;
        }
        return patched;
    }

    static bool has_layout_owner_storage(std::uint64_t ext_va) {
        const auto& off = g_disk_off();
        if (off.partmgr_layout_cache && valid_drive_layout(ext_va + off.partmgr_layout_cache))
            return true;
        if (off.partmgr_layout_pointer) {
            std::uint64_t layout_va = kread_val<std::uint64_t>(ext_va + off.partmgr_layout_pointer);
            if (is_kva(layout_va) && valid_drive_layout(layout_va)) return true;
        }
        return false;
    }

    static std::uint32_t patch_layout_owner(std::uint64_t ext_va, std::uint32_t salt) {
        const auto& off = g_disk_off();
        std::uint32_t patched = 0;
        if (off.partmgr_layout_cache)
            patched += patch_drive_layout(ext_va + off.partmgr_layout_cache, salt);
        if (off.partmgr_layout_pointer) {
            std::uint64_t layout_va = kread_val<std::uint64_t>(ext_va + off.partmgr_layout_pointer);
            if (is_kva(layout_va))
                patched += patch_drive_layout(layout_va, salt + 19);
        }
        return patched;
    }


    std::uint32_t patch_device(std::uint64_t dev_va, std::uint32_t index) {
        std::uint64_t ext_va = dev_extension(dev_va);
        if (!is_kva(ext_va)) return 0;
        std::uint32_t patched = 0;
        if (has_layout_owner_storage(ext_va)) {
            patched += patch_layout_owner(ext_va, index);
        } else {
            patched += patch_partition_extension(ext_va, index);
        }
        if (patched) logging::print("disk: partmgr device 0x%llx patched (%u fields)", dev_va, patched);
        return patched;
    }


    static std::uint32_t patch_device_heuristic(std::uint64_t dev_va) {
        std::uint64_t ext_va = dev_extension(dev_va);
        if (!is_kva(ext_va)) return 0;
        std::vector<std::uint8_t> ext(0x800);
        if (!kread(ext_va, ext.data(), ext.size())) return 0;

        for (std::uint32_t off = 0; off + (std::uint32_t)sizeof(std::uint32_t)*4 <= (std::uint32_t)ext.size(); off += 8) {
            std::uint32_t style  = *reinterpret_cast<const std::uint32_t*>(ext.data() + off);
            if (style != kPartStyleGPT) continue;
            if (off + 24 > (std::uint32_t)ext.size()) continue;
            std::int64_t length = *reinterpret_cast<const std::int64_t*>(ext.data() + off + 16);
            std::int64_t start  = *reinterpret_cast<const std::int64_t*>(ext.data() + off + 8);
            if (length <= 0 || length >= (std::int64_t)0x1000000000000000LL || start < 0) continue;

            if (off + 48 + 16 > (std::uint32_t)ext.size()) continue;
            spoof_guid_va(ext_va + off + 48);
            logging::print("disk: partmgr heuristic device 0x%llx patched at ext+0x%x", dev_va, off);
            return 1;
        }
        return 0;
    }

    inline void install() {
        const auto& off = g_disk_off();
        std::uint32_t patched = 0;
        std::uint32_t index = 0;
        enum_driver_devices(L"\\Driver\\partmgr", [&](std::uint64_t dev_va) {
            if (off.partmgr_partition_info_ex || off.partmgr_layout_cache) {
                patched += patch_device(dev_va, index++);
            } else {
                patched += patch_device_heuristic(dev_va);
                ++index;
            }
        });
        logging::print("disk: partmgr patched %u fields", patched);
    }

}
