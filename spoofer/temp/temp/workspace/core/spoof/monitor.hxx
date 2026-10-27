#pragma once
#include "helpers.hxx"
#include "../../../impl/pdb_offsets.hxx"
#include <vector>
#include <winreg.h>

namespace monitor {

    static void patch_edid_binary(HKEY hk) {
        DWORD sz = 0, type = 0;
        RegQueryValueExW(hk, L"EDID", nullptr, &type, nullptr, &sz);
        if (!sz || type != REG_BINARY || sz < 128) return;

        std::vector<std::uint8_t> edid(sz);
        if (RegQueryValueExW(hk, L"EDID", nullptr, &type,
                             edid.data(), &sz) != ERROR_SUCCESS) return;

        static constexpr std::uint8_t HDR[8] = {
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
        };
        if (memcmp(edid.data(), HDR, 8) != 0) return;

        using namespace spoof::helpers;

        edid[12] = static_cast<std::uint8_t>(rand_next());
        edid[13] = static_cast<std::uint8_t>(rand_next());
        edid[14] = static_cast<std::uint8_t>(rand_next());
        edid[15] = static_cast<std::uint8_t>(rand_next());

        for (int d = 0; d < 4; ++d) {
            const int base = 54 + d * 18;
            if (edid[base] != 0 || edid[base+1] != 0 || edid[base+2] != 0) continue;
            if (edid[base+3] != 0xFF) continue;
            for (int s = 0; s < 8; ++s) {
                const std::uint8_t r = static_cast<std::uint8_t>(rand_next() % 36);
                edid[base + 5 + s] = r < 10 ? static_cast<std::uint8_t>('0' + r)
                                             : static_cast<std::uint8_t>('A' + r - 10);
            }
            edid[base+13] = 0x0A;
            edid[base+14] = edid[base+15] = edid[base+16] = edid[base+17] = 0x20;
        }

        std::uint8_t sum = 0;
        for (int s = 0; s < 127; ++s) sum += edid[s];
        edid[127] = static_cast<std::uint8_t>(256u - sum);

        RegSetValueExW(hk, L"EDID", 0, REG_BINARY, edid.data(), sz);
    }

    static void patch_registry_edid() {
        HKEY hDisplay = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
                0, KEY_READ, &hDisplay) != ERROR_SUCCESS) return;

        std::uint32_t patched = 0;

        for (DWORD ci = 0; ; ++ci) {
            wchar_t cls[256] = {};
            DWORD cls_len = 256;
            if (RegEnumKeyExW(hDisplay, ci, cls, &cls_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            HKEY hCls = nullptr;
            if (RegOpenKeyExW(hDisplay, cls, 0, KEY_READ, &hCls) != ERROR_SUCCESS) continue;

            for (DWORD ii = 0; ; ++ii) {
                wchar_t inst[256] = {};
                DWORD inst_len = 256;
                if (RegEnumKeyExW(hCls, ii, inst, &inst_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                HKEY hInst = nullptr;
                if (RegOpenKeyExW(hCls, inst, 0, KEY_READ, &hInst) != ERROR_SUCCESS) continue;

                HKEY hDevParam = nullptr;
                if (RegOpenKeyExW(hInst, L"Device Parameters",
                                  0, KEY_READ | KEY_SET_VALUE, &hDevParam) == ERROR_SUCCESS) {
                    patch_edid_binary(hDevParam);
                    RegCloseKey(hDevParam);
                    ++patched;
                }
                RegCloseKey(hInst);
            }
            RegCloseKey(hCls);
        }
        RegCloseKey(hDisplay);

        HKEY hGfxCfg = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration",
                0, KEY_READ, &hGfxCfg) == ERROR_SUCCESS) {
            for (DWORD ci = 0; ; ++ci) {
                wchar_t sub[256] = {};
                DWORD sub_len = 256;
                if (RegEnumKeyExW(hGfxCfg, ci, sub, &sub_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                HKEY hSub = nullptr;
                if (RegOpenKeyExW(hGfxCfg, sub, 0, KEY_SET_VALUE, &hSub) != ERROR_SUCCESS) continue;
                const std::uint64_t zero = 0;
                RegSetValueExW(hSub, L"Timestamp", 0, REG_QWORD,
                    reinterpret_cast<const BYTE*>(&zero), sizeof(zero));
                RegCloseKey(hSub);
            }
            RegCloseKey(hGfxCfg);
        }

        logging::print("spoof: monitor — registry EDID patched (%u display(s))", patched);
    }

    inline void install() {
        using namespace spoof::helpers;

        loader_offsets::dxgkrnl_offsets off{};
        if (!pdb_offsets::resolve_dxgkrnl(&off)) {
            logging::print("spoof: monitor — dxgkrnl PDB resolution failed");
            return;
        }

        const std::uint64_t dxgkrnl_base = get_kernel_module_base(L"dxgkrnl.sys");
        if (!dxgkrnl_base) {
            logging::print("spoof: monitor — dxgkrnl.sys not found in module list");
            return;
        }

        const std::uint64_t cache_ptr_va = dxgkrnl_base + off.edid_cache_rva;
        const std::uint64_t cache_va     = kread_val<std::uint64_t>(cache_ptr_va);
        if (!is_kva(cache_va)) {
            logging::print("spoof: monitor — s_pEdidCache not valid (ptr=0x%llX)",
                (unsigned long long)cache_ptr_va);
            return;
        }

        static constexpr std::uint8_t EDID_HDR[8] = {
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
        };

        std::uint32_t count = 0;

        for (std::uint32_t i = 0; i < off.max_entries; ++i) {
            const std::uint64_t entry = cache_va + static_cast<std::uint64_t>(i) * off.entry_stride;

            const std::uint64_t ts = kread_val<std::uint64_t>(entry + off.entry_timestamp);
            if (!ts) continue;

            std::uint8_t edid[128] = {};
            if (!kread(entry + off.entry_edid_data, edid, 128)) continue;
            if (memcmp(edid, EDID_HDR, 8) != 0) continue;

            edid[12] = static_cast<std::uint8_t>(rand_next());
            edid[13] = static_cast<std::uint8_t>(rand_next());
            edid[14] = static_cast<std::uint8_t>(rand_next());
            edid[15] = static_cast<std::uint8_t>(rand_next());

            for (int d = 0; d < 4; ++d) {
                const int base = 54 + d * 18;
                if (edid[base] != 0 || edid[base + 1] != 0 || edid[base + 2] != 0) continue;
                if (edid[base + 3] != 0xFF) continue;
                for (int s = 0; s < 8; ++s) {
                    const std::uint8_t r = static_cast<std::uint8_t>(rand_next() % 36);
                    edid[base + 5 + s] = r < 10 ? static_cast<std::uint8_t>('0' + r)
                                                 : static_cast<std::uint8_t>('A' + r - 10);
                }
                edid[base + 13] = 0x0A;
                edid[base + 14] = 0x20;
                edid[base + 15] = 0x20;
                edid[base + 16] = 0x20;
                edid[base + 17] = 0x20;
            }

            std::uint8_t sum = 0;
            for (int s = 0; s < 127; ++s) sum += edid[s];
            edid[127] = static_cast<std::uint8_t>(static_cast<std::uint32_t>(256) - sum);

            kwrite(entry + off.entry_edid_data, edid, 128);
            ++count;

            logging::print("spoof: monitor — patched EDID entry %u (ts=0x%llX)",
                i, (unsigned long long)ts);
        }

        logging::print("spoof: monitor — %u EDID entr%s patched",
            count, count == 1 ? "y" : "ies");

        patch_registry_edid();
    }

}
