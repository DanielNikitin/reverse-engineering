#pragma once
#include "helpers.hxx"
#include <vector>
#include <string>
#include <winreg.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

namespace spoof::registry_ids {

    using namespace helpers;

    static GUID make_reg_guid() {
        GUID g{};
        auto rw = []() -> DWORD {
            return (rand_next() << 15u) ^ (rand_next() << 1u) ^ rand_next();
        };
        g.Data1 = rw();
        g.Data2 = static_cast<WORD>(rand_next());
        g.Data3 = static_cast<WORD>((rand_next() & 0x0FFFu) | 0x4000u);
        DWORD a = rw(), b = rw();
        memcpy(g.Data4,     &a, 4);
        memcpy(g.Data4 + 4, &b, 4);
        g.Data4[0] = static_cast<BYTE>((g.Data4[0] & 0x3Fu) | 0x80u);
        return g;
    }

    static void fmt_guid_str(wchar_t* buf, std::size_t cch, const GUID& g) {
        swprintf_s(buf, cch,
            L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1],
            g.Data4[2], g.Data4[3], g.Data4[4],
            g.Data4[5], g.Data4[6], g.Data4[7]);
    }

    static bool write_guid_sz(HKEY root, const wchar_t* subkey, const wchar_t* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return false;
        GUID g = make_reg_guid();
        wchar_t s[48] = {};
        fmt_guid_str(s, 48, g);
        const DWORD sz = static_cast<DWORD>((wcslen(s) + 1) * sizeof(wchar_t));
        const bool ok = RegSetValueExW(hk, value, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(s), sz) == ERROR_SUCCESS;
        RegCloseKey(hk);
        return ok;
    }


    static bool write_sz(HKEY root, const wchar_t* subkey, const wchar_t* value,
                         const wchar_t* data) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return false;
        const DWORD sz = static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t));
        const bool ok = RegSetValueExW(hk, value, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(data), sz) == ERROR_SUCCESS;
        RegCloseKey(hk);
        return ok;
    }


    static bool randomise_binary(HKEY root, const wchar_t* subkey, const wchar_t* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return false;
        DWORD sz = 0, type = 0;
        RegQueryValueExW(hk, value, nullptr, &type, nullptr, &sz);
        bool ok = false;
        if (sz && type == REG_BINARY) {
            std::vector<BYTE> buf(sz);
            if (RegQueryValueExW(hk, value, nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                for (DWORD i = 0; i < sz; ++i)
                    buf[i] = static_cast<BYTE>(rand_next() & 0xFF);
                ok = RegSetValueExW(hk, value, 0, REG_BINARY, buf.data(), sz) == ERROR_SUCCESS;
            }
        }
        RegCloseKey(hk);
        return ok;
    }

    static void del_value(HKEY root, const wchar_t* subkey, const wchar_t* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;
        RegDeleteValueW(hk, value);
        RegCloseKey(hk);
    }

    static bool write_qword(HKEY root, const wchar_t* subkey,
                            const wchar_t* value, std::uint64_t data) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return false;
        const bool ok = RegSetValueExW(hk, value, 0, REG_QWORD,
            reinterpret_cast<const BYTE*>(&data), sizeof(data)) == ERROR_SUCCESS;
        RegCloseKey(hk);
        return ok;
    }

    static void spoof_hardware_ids(HKEY root, const wchar_t* subkey, const wchar_t* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;


        DWORD sz = 0, type = 0;
        RegQueryValueExW(hk, value, nullptr, &type, nullptr, &sz);
        if (!sz) sz = 256;


        std::vector<wchar_t> buf(sz / sizeof(wchar_t) + 8, 0);
        std::size_t pos = 0;
        while (pos + 40 < buf.size() - 2) {
            GUID g = make_reg_guid();
            wchar_t gs[48] = {};
            fmt_guid_str(gs, 48, g);
            std::size_t glen = wcslen(gs) + 1;
            if (pos + glen + 2 > buf.size()) break;
            memcpy(&buf[pos], gs, glen * sizeof(wchar_t));
            pos += glen;

            buf[pos] = 0;
            break;
        }
        buf[pos] = 0;

        RegSetValueExW(hk, value, 0, REG_MULTI_SZ,
            reinterpret_cast<const BYTE*>(buf.data()),
            static_cast<DWORD>((pos + 2) * sizeof(wchar_t)));
        RegCloseKey(hk);
    }

    static void spoof_nic_timestamps() {
        static const wchar_t k_class[] =
            L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
            L"{4D36E972-E325-11CE-BFC1-08002BE10318}";
        HKEY hClass = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_class, 0, KEY_READ, &hClass) != ERROR_SUCCESS)
            return;

        for (DWORD i = 0; ; ++i) {
            wchar_t sub[16] = {};
            DWORD sub_len = 16;
            if (RegEnumKeyExW(hClass, i, sub, &sub_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hClass, sub, 0, KEY_SET_VALUE, &hSub) != ERROR_SUCCESS) continue;


            const std::uint64_t fake_ts = 0;
            RegSetValueExW(hSub, L"NetworkInterfaceInstallTimestamp", 0, REG_QWORD,
                reinterpret_cast<const BYTE*>(&fake_ts), sizeof(fake_ts));
            RegCloseKey(hSub);
        }
        RegCloseKey(hClass);
    }

    static void del_tree(HKEY root, const wchar_t* subkey) {
        SHDeleteKeyW(root, subkey);
    }

    static void spoof_scsi_devicemap() {
        HKEY hRoot = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DEVICEMAP\\Scsi",
                0, KEY_READ, &hRoot) != ERROR_SUCCESS) return;


        for (DWORD pi = 0; ; ++pi) {
            wchar_t port[32] = {};
            DWORD port_len = 32;
            if (RegEnumKeyExW(hRoot, pi, port, &port_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            HKEY hPort = nullptr;
            if (RegOpenKeyExW(hRoot, port, 0, KEY_READ, &hPort) != ERROR_SUCCESS) continue;

            for (DWORD bi = 0; ; ++bi) {
                wchar_t bus[32] = {};
                DWORD bus_len = 32;
                if (RegEnumKeyExW(hPort, bi, bus, &bus_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                HKEY hBus = nullptr;
                if (RegOpenKeyExW(hPort, bus, 0, KEY_READ, &hBus) != ERROR_SUCCESS) continue;

                for (DWORD ti = 0; ; ++ti) {
                    wchar_t target[32] = {};
                    DWORD target_len = 32;
                    if (RegEnumKeyExW(hBus, ti, target, &target_len,
                                      nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                    HKEY hTarget = nullptr;
                    if (RegOpenKeyExW(hBus, target, 0, KEY_READ, &hTarget) != ERROR_SUCCESS) continue;

                    for (DWORD li = 0; ; ++li) {
                        wchar_t lun[32] = {};
                        DWORD lun_len = 32;
                        if (RegEnumKeyExW(hTarget, li, lun, &lun_len,
                                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                        HKEY hLun = nullptr;
                        if (RegOpenKeyExW(hTarget, lun, 0,
                                          KEY_READ | KEY_SET_VALUE, &hLun) != ERROR_SUCCESS) continue;


                        wchar_t serial[128] = {};
                        DWORD slen = sizeof(serial);
                        DWORD stype = 0;
                        if (RegQueryValueExW(hLun, L"SerialNumber", nullptr, &stype,
                                             reinterpret_cast<LPBYTE>(serial), &slen) == ERROR_SUCCESS
                            && stype == REG_SZ) {
                            const DWORD chars = slen / sizeof(wchar_t);

                            const DWORD start = chars > 8 ? chars - 8 : 1;
                            for (DWORD c = start; c < chars; ++c) {
                                if (serial[c] == 0) break;
                                const DWORD r = rand_next() % 36;
                                serial[c] = r < 10 ? static_cast<wchar_t>(L'0' + r)
                                                   : static_cast<wchar_t>(L'A' + r - 10);
                            }
                            RegSetValueExW(hLun, L"SerialNumber", 0, REG_SZ,
                                reinterpret_cast<const BYTE*>(serial), slen);
                        }


                        RegDeleteValueW(hLun, L"DeviceIdentifierPage");

                        RegCloseKey(hLun);
                    }
                    RegCloseKey(hTarget);
                }
                RegCloseKey(hBus);
            }
            RegCloseKey(hPort);
        }
        RegCloseKey(hRoot);
        logging::print("registry_ids: HARDWARE\\DEVICEMAP\\Scsi serials patched");
    }

    static void patch_disk_peripheral_identifiers() {
        HKEY hMfa = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter",
                0, KEY_READ, &hMfa) != ERROR_SUCCESS) return;

        for (DWORD ai = 0; ; ++ai) {
            wchar_t adap[32] = {};
            DWORD adap_len = 32;
            if (RegEnumKeyExW(hMfa, ai, adap, &adap_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

            wchar_t dc_path[128] = {};
            swprintf_s(dc_path, L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\"
                                 L"%s\\DiskController", adap);
            HKEY hDc = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, dc_path, 0, KEY_READ, &hDc) != ERROR_SUCCESS)
                continue;

            for (DWORD ci = 0; ; ++ci) {
                wchar_t ctrl[32] = {};
                DWORD ctrl_len = 32;
                if (RegEnumKeyExW(hDc, ci, ctrl, &ctrl_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

                wchar_t dp_path[256] = {};
                swprintf_s(dp_path, L"%s\\%s\\DiskPeripheral", dc_path, ctrl);
                HKEY hDp = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, dp_path, 0, KEY_READ, &hDp) != ERROR_SUCCESS)
                    continue;

                for (DWORD di = 0; ; ++di) {
                    wchar_t disk[32] = {};
                    DWORD disk_len = 32;
                    if (RegEnumKeyExW(hDp, di, disk, &disk_len,
                                      nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

                    wchar_t full[320] = {};
                    swprintf_s(full, L"%s\\%s", dp_path, disk);
                    HKEY hDisk = nullptr;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, full, 0,
                                      KEY_READ | KEY_SET_VALUE, &hDisk) != ERROR_SUCCESS) continue;

                    wchar_t ident[128] = {};
                    DWORD ident_sz = sizeof(ident), ident_type = 0;
                    if (RegQueryValueExW(hDisk, L"Identifier", nullptr, &ident_type,
                                         reinterpret_cast<LPBYTE>(ident), &ident_sz) == ERROR_SUCCESS
                        && ident_type == REG_SZ) {

                        for (DWORD c = 0; ident[c]; ++c) {
                            const wchar_t ch = ident[c];
                            if ((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f')
                                || (ch >= L'A' && ch <= L'F')) {
                                const DWORD r = rand_next() % 16;
                                ident[c] = r < 10 ? static_cast<wchar_t>(L'0' + r)
                                                  : static_cast<wchar_t>(L'A' + r - 10);
                            }
                        }
                        RegSetValueExW(hDisk, L"Identifier", 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(ident), ident_sz);
                    }
                    RegCloseKey(hDisk);
                }
                RegCloseKey(hDp);
            }
            RegCloseKey(hDc);
        }
        RegCloseKey(hMfa);
        logging::print("registry_ids: DiskPeripheral Identifier(s) patched");
    }

    static void patch_esrt_guids() {
        HKEY hEsrt = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\UEFI\\ESRT",
                0, KEY_READ | KEY_WRITE, &hEsrt) != ERROR_SUCCESS) return;


        std::vector<std::wstring> old_keys;
        for (DWORD i = 0; ; ++i) {
            wchar_t sub[128] = {};
            DWORD sub_len = 128;
            if (RegEnumKeyExW(hEsrt, i, sub, &sub_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            old_keys.emplace_back(sub);
        }

        for (const auto& old_name : old_keys) {
            HKEY hOld = nullptr;
            if (RegOpenKeyExW(hEsrt, old_name.c_str(), 0, KEY_READ, &hOld) != ERROR_SUCCESS)
                continue;

            GUID ng = make_reg_guid();
            wchar_t new_name[48] = {};
            fmt_guid_str(new_name, 48, ng);

            HKEY hNew = nullptr;
            if (RegCreateKeyExW(hEsrt, new_name, 0, nullptr, 0,
                                KEY_WRITE, nullptr, &hNew, nullptr) == ERROR_SUCCESS) {

                for (DWORD vi = 0; ; ++vi) {
                    wchar_t vname[256] = {};
                    DWORD vname_len = 256, vtype = 0, vdata_len = 0;
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
            SHDeleteKeyW(hEsrt, old_name.c_str());
        }
        RegCloseKey(hEsrt);
        logging::print("registry_ids: ESRT GUID subkeys renamed (%zu)", old_keys.size());
    }

    static void patch_nic_netcfg_instance_id() {
        static const wchar_t k_class[] =
            L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
            L"{4D36E972-E325-11CE-BFC1-08002BE10318}";
        HKEY hClass = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_class, 0, KEY_READ, &hClass) != ERROR_SUCCESS)
            return;

        std::uint32_t count = 0;
        for (DWORD i = 0; ; ++i) {
            wchar_t sub[16] = {};
            DWORD sub_len = 16;
            if (RegEnumKeyExW(hClass, i, sub, &sub_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hClass, sub, 0, KEY_READ | KEY_SET_VALUE, &hSub) != ERROR_SUCCESS)
                continue;


            DWORD existing_sz = 0;
            if (RegQueryValueExW(hSub, L"NetCfgInstanceId", nullptr, nullptr,
                                 nullptr, &existing_sz) == ERROR_SUCCESS && existing_sz > 0) {
                GUID ng = make_reg_guid();
                wchar_t gs[48] = {};
                fmt_guid_str(gs, 48, ng);
                const DWORD sz = static_cast<DWORD>((wcslen(gs) + 1) * sizeof(wchar_t));
                RegSetValueExW(hSub, L"NetCfgInstanceId", 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(gs), sz);
                ++count;
            }
            RegCloseKey(hSub);
        }
        RegCloseKey(hClass);
        logging::print("registry_ids: NetCfgInstanceId patched (%u NIC(s))", count);
    }

    static void patch_network_profiles() {
        static const wchar_t k_path[] =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";
        HKEY hProfiles = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path,
                0, KEY_READ | KEY_WRITE, &hProfiles) != ERROR_SUCCESS) return;

        std::vector<std::wstring> old_keys;
        for (DWORD i = 0; ; ++i) {
            wchar_t sub[128] = {};
            DWORD sub_len = 128;
            if (RegEnumKeyExW(hProfiles, i, sub, &sub_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

            if (sub[0] == L'{') old_keys.emplace_back(sub);
        }

        for (const auto& old_name : old_keys) {
            HKEY hOld = nullptr;
            if (RegOpenKeyExW(hProfiles, old_name.c_str(), 0, KEY_READ, &hOld) != ERROR_SUCCESS)
                continue;

            GUID ng = make_reg_guid();
            wchar_t new_name[48] = {};
            fmt_guid_str(new_name, 48, ng);

            HKEY hNew = nullptr;
            if (RegCreateKeyExW(hProfiles, new_name, 0, nullptr, 0,
                                KEY_WRITE, nullptr, &hNew, nullptr) == ERROR_SUCCESS) {
                for (DWORD vi = 0; ; ++vi) {
                    wchar_t vname[256] = {};
                    DWORD vname_len = 256, vtype = 0, vdata_len = 0;
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
            SHDeleteKeyW(hProfiles, old_name.c_str());
        }
        RegCloseKey(hProfiles);
        logging::print("registry_ids: NetworkList profile GUIDs renamed (%zu)", old_keys.size());
    }

    static void clear_shimcache() {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;


        static const BYTE k_empty_hdr[128] = {
            0xEF, 0xBE, 0xAD, 0xDE,
            0x00, 0x00, 0x00, 0x00,

        };
        RegSetValueExW(hk, L"AppCompatCache", 0, REG_BINARY, k_empty_hdr, sizeof(k_empty_hdr));
        RegCloseKey(hk);
        logging::print("registry_ids: Shimcache (AppCompatCache) cleared");
    }

    static void clear_userassist() {
        static const wchar_t k_ua[] =
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
        SHDeleteKeyW(HKEY_CURRENT_USER, k_ua);
        logging::print("registry_ids: UserAssist cleared");
    }

    static void patch_network_signatures() {
        static const wchar_t k_path[] =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures";
        HKEY hRoot = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path,
                0, KEY_READ | KEY_WRITE, &hRoot) != ERROR_SUCCESS) return;

        for (DWORD mi = 0; ; ++mi) {
            wchar_t managed[64] = {};
            DWORD managed_len = 64;
            if (RegEnumKeyExW(hRoot, mi, managed, &managed_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            HKEY hManaged = nullptr;
            if (RegOpenKeyExW(hRoot, managed, 0, KEY_READ | KEY_WRITE, &hManaged) != ERROR_SUCCESS)
                continue;

            std::vector<std::wstring> old_keys;
            for (DWORD i = 0; ; ++i) {
                wchar_t sub[128] = {};
                DWORD sub_len = 128;
                if (RegEnumKeyExW(hManaged, i, sub, &sub_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                if (sub[0] == L'{') old_keys.emplace_back(sub);
            }

            for (const auto& old_name : old_keys) {
                HKEY hOld = nullptr;
                if (RegOpenKeyExW(hManaged, old_name.c_str(), 0, KEY_READ, &hOld) != ERROR_SUCCESS)
                    continue;

                GUID ng = make_reg_guid();
                wchar_t new_name[48] = {};
                fmt_guid_str(new_name, 48, ng);

                HKEY hNew = nullptr;
                if (RegCreateKeyExW(hManaged, new_name, 0, nullptr, 0,
                                    KEY_WRITE, nullptr, &hNew, nullptr) == ERROR_SUCCESS) {
                    for (DWORD vi = 0; ; ++vi) {
                        wchar_t vname[256] = {};
                        DWORD vname_len = 256, vtype = 0, vdata_len = 0;
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
                SHDeleteKeyW(hManaged, old_name.c_str());
            }
            RegCloseKey(hManaged);
        }
        RegCloseKey(hRoot);
        logging::print("registry_ids: NetworkList Signature GUIDs renamed");
    }

    static void patch_usbprint_serials() {
        static const wchar_t k_path[] =
            L"SYSTEM\\CurrentControlSet\\Enum\\USBPRINT";
        HKEY hRoot = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ, &hRoot) != ERROR_SUCCESS) return;

        std::uint32_t count = 0;
        for (DWORD i = 0; ; ++i) {
            wchar_t dev[256] = {};
            DWORD dev_len = 256;
            if (RegEnumKeyExW(hRoot, i, dev, &dev_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            wchar_t dev_path[512] = {};
            swprintf_s(dev_path, L"%s\\%s", k_path, dev);
            HKEY hDev = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, dev_path, 0, KEY_READ, &hDev) != ERROR_SUCCESS) continue;

            for (DWORD j = 0; ; ++j) {
                wchar_t inst[256] = {};
                DWORD inst_len = 256;
                if (RegEnumKeyExW(hDev, j, inst, &inst_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                wchar_t inst_path[1024] = {};
                swprintf_s(inst_path, L"%s\\%s", dev_path, inst);
                HKEY hInst = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, inst_path, 0,
                                  KEY_READ | KEY_SET_VALUE, &hInst) != ERROR_SUCCESS) continue;

                wchar_t serial[128] = {};
                DWORD slen = sizeof(serial), stype = 0;
                if (RegQueryValueExW(hInst, L"ContainerId", nullptr, &stype,
                                     reinterpret_cast<LPBYTE>(serial), &slen) == ERROR_SUCCESS
                    && stype == REG_SZ) {
                    GUID ng = make_reg_guid();
                    wchar_t gs[48] = {};
                    fmt_guid_str(gs, 48, ng);
                    const DWORD sz = static_cast<DWORD>((wcslen(gs) + 1) * sizeof(wchar_t));
                    RegSetValueExW(hInst, L"ContainerId", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(gs), sz);
                    ++count;
                }
                RegCloseKey(hInst);
            }
            RegCloseKey(hDev);
        }
        RegCloseKey(hRoot);
        logging::print("registry_ids: USBPRINT ContainerIds randomized (%u)", count);
    }

    inline void install() {


        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");


        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
            L"HwProfileGuid");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            L"SusClientId");
        del_value(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            L"SusClientIdValidation");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            L"ComputerHardwareId");

        spoof_hardware_ids(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            L"ComputerHardwareIds");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId");
        {

            FILETIME ft{};
            GetSystemTimeAsFileTime(&ft);
            const std::uint64_t now = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32)
                                    | ft.dwLowDateTime;

            const std::uint64_t offset = static_cast<std::uint64_t>(rand_next() % 10000000) * 10000ULL;
            const std::uint64_t fake_t = now - offset;
            write_qword(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\SQMClient", L"WinSqmFirstSessionStartTime", fake_t);
        }


        {
            FILETIME ft{};
            GetSystemTimeAsFileTime(&ft);
            const std::uint64_t now = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32)
                                    | ft.dwLowDateTime;
            const std::uint64_t fake_ft = now - static_cast<std::uint64_t>(rand_next() % 1000000) * 10000ULL;
            write_qword(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                L"InstallTime", fake_ft);

            const DWORD fake_unix = static_cast<DWORD>(fake_ft / 10000000ULL - 11644473600ULL);
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                RegSetValueExW(hk, L"InstallDate", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&fake_unix), sizeof(fake_unix));
                RegCloseKey(hk);
            }
        }
        randomise_binary(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DigitalProductId");

        randomise_binary(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DigitalProductId4");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            L"Windows Activation Technologies\\AdminObject\\Store",
            L"MachineId");

        randomise_binary(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID", L"RandomSeed");

        randomise_binary(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", L"WindowsAIKHash");

        write_guid_sz(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Office\\Common\\ClientTelemetry",
            L"MotherboardUUID");

        write_guid_sz(HKEY_USERS,
            L".DEFAULT\\Software\\Microsoft\\Office\\Common\\ClientTelemetry",
            L"MotherboardUUID");

        write_guid_sz(HKEY_USERS,
            L"S-1-5-18\\Software\\Microsoft\\Office\\Common\\ClientTelemetry",
            L"MotherboardUUID");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\NVIDIA Corporation\\Global", L"ClientUUID");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\NVIDIA Corporation\\Global", L"PersistenceIdentifier");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager", L"ChipsetMatchID");

        spoof_nic_timestamps();

        randomise_binary(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Win32kWPP\\Parameters",
            L"WppRecorder_TraceGuid");

        del_value(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
            L"BackupProductKeyDefault");

        del_value(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
            L"actionlist");

        del_value(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
            L"ServiceSessionId");


        del_value(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\Activation",
            L"ProductActivationTime");

        del_tree(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests");

        del_tree(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume");

        del_value(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket",
            L"LastEnum");

        del_tree(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume");

        del_tree(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2");

        del_tree(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Dfrg\\Statistics");

        spoof_scsi_devicemap();

        patch_disk_peripheral_identifiers();

        patch_esrt_guids();

        patch_nic_netcfg_instance_id();

        patch_network_profiles();

        clear_shimcache();

        clear_userassist();

        randomise_binary(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\XboxLive", L"XblDeviceToken");

        randomise_binary(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\XboxLive", L"PhoneToken");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Terminal Server Client", L"LicenseId");

        write_guid_sz(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\License",
            L"LicenseId");

        patch_network_signatures();

        patch_usbprint_serials();


        logging::print("registry_ids: all registry IDs patched");
    }

}
