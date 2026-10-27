#pragma once
#include "helpers.hxx"
#include "disk/disk_offsets.hxx"
#include <vector>
#include <string>

namespace volume_guid {

    static DWORD make_rand_dword() {
        return (spoof::helpers::rand_next() << 15u) ^
               (spoof::helpers::rand_next() << 1u)  ^
                spoof::helpers::rand_next();
    }

    static void format_volume_name(wchar_t* buf, std::size_t buf_cch, const GUID& g) {
        swprintf_s(buf, buf_cch,
            L"\\DosDevices\\Volume{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1],
            g.Data4[2], g.Data4[3], g.Data4[4],
            g.Data4[5], g.Data4[6], g.Data4[7]);
    }

    static GUID make_rand_guid() {
        GUID g{};
        g.Data1 = make_rand_dword();
        g.Data2 = static_cast<WORD>(spoof::helpers::rand_next());
        g.Data3 = static_cast<WORD>((spoof::helpers::rand_next() & 0x0FFFu) | 0x4000u);
        const DWORD d4a = make_rand_dword();
        const DWORD d4b = make_rand_dword();
        memcpy(g.Data4,     &d4a, 4);
        memcpy(g.Data4 + 4, &d4b, 4);
        g.Data4[0] = static_cast<BYTE>((g.Data4[0] & 0x3Fu) | 0x80u);
        return g;
    }

    struct volume_entry {
        std::wstring old_name;
        DWORD        type;
        std::vector<BYTE> data;
    };



    static void patch_hardware_config_guid() {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\HardwareConfig",
                0, KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS) {
            logging::print("spoof: volume_guid — HardwareConfig not accessible");
            return;
        }

        wchar_t old_val[64] = {};
        DWORD   old_sz      = sizeof(old_val);
        DWORD   type        = 0;
        RegQueryValueExW(hk, L"LastConfig", nullptr, &type,
                         reinterpret_cast<LPBYTE>(old_val), &old_sz);

        const GUID new_g = make_rand_guid();
        wchar_t    new_val[48] = {};
        swprintf_s(new_val, 48,
            L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            new_g.Data1, new_g.Data2, new_g.Data3,
            new_g.Data4[0], new_g.Data4[1],
            new_g.Data4[2], new_g.Data4[3], new_g.Data4[4],
            new_g.Data4[5], new_g.Data4[6], new_g.Data4[7]);

        const DWORD new_sz = static_cast<DWORD>((wcslen(new_val) + 1) * sizeof(wchar_t));
        if (RegSetValueExW(hk, L"LastConfig", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(new_val), new_sz) == ERROR_SUCCESS)
            logging::print("spoof: volume_guid — HardwareConfig\\LastConfig patched");
        else
            logging::print("spoof: volume_guid — HardwareConfig\\LastConfig write failed");


        if (old_val[0] == L'{') {
            HKEY hOld = nullptr;
            if (RegOpenKeyExW(hk, old_val, 0, KEY_READ, &hOld) == ERROR_SUCCESS) {
                HKEY hNew = nullptr;
                if (RegCreateKeyExW(hk, new_val, 0, nullptr, 0,
                                    KEY_WRITE, nullptr, &hNew, nullptr) == ERROR_SUCCESS) {
                    for (DWORD vi = 0; ; ++vi) {
                        wchar_t vname[256] = {};
                        DWORD   vname_len  = 256;
                        DWORD   vtype      = 0;
                        DWORD   vdata_len  = 0;
                        LSTATUS vs = RegEnumValueW(hOld, vi, vname, &vname_len,
                                                   nullptr, &vtype, nullptr, &vdata_len);
                        if (vs == ERROR_NO_MORE_ITEMS) break;
                        if (vs != ERROR_SUCCESS && vs != ERROR_MORE_DATA) continue;
                        std::vector<BYTE> vdata(vdata_len);
                        vname_len = 256;
                        if (RegQueryValueExW(hOld, vname, nullptr, &vtype,
                                             vdata.data(), &vdata_len) == ERROR_SUCCESS)
                            RegSetValueExW(hNew, vname, 0, vtype, vdata.data(), vdata_len);
                    }
                    RegCloseKey(hNew);
                }
                RegCloseKey(hOld);
                RegDeleteKeyW(hk, old_val);
            }
        }

        RegCloseKey(hk);
    }

    static void patch_volmgr_unique_guid() {
        const ULONG guid_off = spoof::disk::g_disk_off().volmgr_volume_unique_guid;
        if (!guid_off) {
            logging::print("volume_guid: volmgr UniqueGuid offset not resolved, skipping kernel patch");
            return;
        }

        using spoof::helpers::enum_driver_devices;
        using spoof::helpers::kread;
        using spoof::helpers::kwrite;
        using spoof::helpers::kread_val;
        using spoof::helpers::is_kva;

        std::uint32_t patched = 0;
        enum_driver_devices(L"\\Driver\\volmgr", [&](std::uint64_t dev_va) {
            const std::uint64_t ext_va = kread_val<std::uint64_t>(dev_va + 0x40);
            if (!is_kva(ext_va)) return;

            GUID old_g{};
            if (!kread(ext_va + guid_off, &old_g, sizeof(old_g))) return;

            const auto* p = reinterpret_cast<const std::uint8_t*>(&old_g);
            bool all_zero = true;
            for (std::size_t i = 0; i < sizeof(old_g); ++i)
                if (p[i]) { all_zero = false; break; }
            if (all_zero) return;

            const GUID new_g = make_rand_guid();
            kwrite(ext_va + guid_off, &new_g, sizeof(new_g));
            ++patched;
        });

        logging::print("volume_guid: volmgr kernel UniqueGuid patched (%u volume(s))", patched);
    }

    inline void install() {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\MountedDevices",
                0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
            logging::print("spoof: volume_guid — failed to open MountedDevices (need admin)");
        } else {
            std::vector<volume_entry> entries;

            DWORD idx = 0;
            while (true) {
                wchar_t name[256]  = {};
                DWORD   name_len   = 256;
                DWORD   type       = 0;
                DWORD   data_len   = 0;
                LSTATUS s = RegEnumValueW(hKey, idx, name, &name_len,
                                          nullptr, &type, nullptr, &data_len);
                if (s == ERROR_NO_MORE_ITEMS) break;
                ++idx;
                if (s != ERROR_SUCCESS && s != ERROR_MORE_DATA) continue;
                if (_wcsnicmp(name, L"\\DosDevices\\Volume{", 19) != 0) continue;

                volume_entry e;
                e.old_name = name;
                e.type     = type;
                e.data.resize(data_len);
                name_len = 256;
                if (RegQueryValueExW(hKey, name, nullptr, &type,
                                     e.data.data(), &data_len) != ERROR_SUCCESS) continue;
                e.data.resize(data_len);
                entries.push_back(std::move(e));
            }

            if (entries.empty()) {
                logging::print("spoof: volume_guid — no Volume{GUID} entries found");
            } else {
                std::uint32_t count = 0;
                for (const auto& e : entries) {
                    const GUID new_g = make_rand_guid();
                    wchar_t    new_name[80] = {};
                    format_volume_name(new_name, 80, new_g);
                    if (RegSetValueExW(hKey, new_name, 0, e.type,
                                       e.data.data(),
                                       static_cast<DWORD>(e.data.size())) != ERROR_SUCCESS)
                        continue;
                    RegDeleteValueW(hKey, e.old_name.c_str());
                    ++count;
                }
                logging::print("spoof: volume_guid — renamed %u MountedDevices GUID(s)", count);
            }

            RegCloseKey(hKey);
        }

        patch_hardware_config_guid();
        patch_volmgr_unique_guid();
    }

}
