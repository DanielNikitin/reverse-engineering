#pragma once
#include "shared.hxx"

namespace spoof::disk::volume_serial {
    using namespace helpers;

    static std::uint32_t patch_vpb(std::uint64_t dev_va) {
        std::uint64_t vpb_va = dev_vpb(dev_va);
        if (!is_kva(vpb_va)) return 0;
        std::uint32_t orig = kread_val<std::uint32_t>(vpb_va + VPB_OFF_SerialNumber);
        if (!orig) return 0;
        std::uint32_t new_sn = fnv1a(&orig, sizeof(orig), s_vol_seed);
        if (!new_sn) new_sn = 0x13572468;
        if (new_sn == orig) return 0;
        kwrite_val<std::uint32_t>(vpb_va + VPB_OFF_SerialNumber, new_sn);
        return 1;
    }

    static std::uint32_t patch_driver(const wchar_t* name) {
        std::uint32_t patched = 0;
        enum_driver_devices(name, [&](std::uint64_t dev_va) { patched += patch_vpb(dev_va); });
        return patched;
    }

    inline void install() {
        static const wchar_t* kDrivers[] = {
            L"\\Driver\\volmgr", L"\\Driver\\volsnap", L"\\Driver\\fvevol",
            L"\\Driver\\volume", L"\\FileSystem\\Ntfs", L"\\FileSystem\\Refs",
        };
        std::uint32_t total = 0;
        for (auto* d : kDrivers) total += patch_driver(d);
        logging::print("disk: volume_serial patched %u VPB serials", total);
    }

}
