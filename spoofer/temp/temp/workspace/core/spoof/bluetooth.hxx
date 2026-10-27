#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

namespace spoof::bluetooth {

    using namespace helpers;

    static void spoof_bthport_keys() {
        static const wchar_t k_path[] =
            L"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys";
        HKEY hKeys = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ, &hKeys) != ERROR_SUCCESS) return;

        std::uint32_t count = 0;
        for (DWORD i = 0; ; ++i) {
            wchar_t adapter[64] = {};
            DWORD adapter_len = 64;
            if (RegEnumKeyExW(hKeys, i, adapter, &adapter_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

            wchar_t full[256] = {};
            swprintf_s(full, L"%s\\%s", k_path, adapter);
            HKEY hAdapter = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, full, 0, KEY_READ | KEY_SET_VALUE, &hAdapter) != ERROR_SUCCESS)
                continue;

            for (DWORD vi = 0; ; ++vi) {
                wchar_t vname[128] = {};
                DWORD vname_len = 128, vtype = 0, vdata_len = 0;
                LSTATUS vs = RegEnumValueW(hAdapter, vi, vname, &vname_len,
                                           nullptr, &vtype, nullptr, &vdata_len);
                if (vs == ERROR_NO_MORE_ITEMS) break;
                if (vs != ERROR_SUCCESS) continue;
                if (vtype == REG_BINARY && vdata_len >= 16) {
                    std::vector<BYTE> buf(vdata_len);
                    vname_len = 128;
                    if (RegQueryValueExW(hAdapter, vname, nullptr, &vtype,
                                         buf.data(), &vdata_len) == ERROR_SUCCESS) {
                        for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                        RegSetValueExW(hAdapter, vname, 0, REG_BINARY, buf.data(), vdata_len);
                        ++count;
                    }
                }
            }
            RegCloseKey(hAdapter);
        }
        RegCloseKey(hKeys);
        logging::print("bluetooth: BTHPORT link keys randomized (%u)", count);
    }

    static void spoof_radio_address() {
        static const wchar_t k_path[] = L"SOFTWARE\\Microsoft\\Bluetooth";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;

        DWORD sz = 0, type = 0;
        if (RegQueryValueExW(hk, L"RadioAddress", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
            && sz >= 6 && type == REG_BINARY) {
            std::vector<BYTE> buf(sz);
            if (RegQueryValueExW(hk, L"RadioAddress", nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                for (DWORD i = 3; i < sz && i < 6; ++i)
                    buf[i] = static_cast<BYTE>(rand_next() & 0xFF);
                RegSetValueExW(hk, L"RadioAddress", 0, REG_BINARY, buf.data(), sz);
            }
        }
        RegCloseKey(hk);
        logging::print("bluetooth: RadioAddress randomized");
    }

    static void spoof_bth_params() {
        static const wchar_t* k_paths[] = {
            L"SYSTEM\\CurrentControlSet\\Services\\BTHLEParameters",
            L"SYSTEM\\CurrentControlSet\\Services\\RFCOMM\\Parameters",
            L"SYSTEM\\CurrentControlSet\\Services\\OBEX\\Parameters",
        };
        for (const auto* path : k_paths) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
                continue;
            DWORD sz = 0, type = 0;
            if (RegQueryValueExW(hk, L"AuthValue", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
                && sz && type == REG_BINARY) {
                std::vector<BYTE> buf(sz);
                if (RegQueryValueExW(hk, L"AuthValue", nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                    for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                    RegSetValueExW(hk, L"AuthValue", 0, REG_BINARY, buf.data(), sz);
                }
            }
            RegCloseKey(hk);
        }
        logging::print("bluetooth: BTH service AuthValues randomized");
    }

    static void spoof_bthenum_containerids() {
        static const wchar_t k_path[] = L"SYSTEM\\CurrentControlSet\\Enum\\BTHENUM";
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

                DWORD sz = 0, type = 0;
                if (RegQueryValueExW(hInst, L"ContainerId", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
                    && type == REG_SZ) {
                    DWORD d1 = (rand_next() << 17u) ^ (rand_next() << 2u) ^ rand_next();
                    WORD  d2 = static_cast<WORD>(rand_next());
                    WORD  d3 = static_cast<WORD>((rand_next() & 0x0FFFu) | 0x4000u);
                    BYTE  d4[8]; for (auto& b : d4) b = static_cast<BYTE>(rand_next() & 0xFF);
                    d4[0] = static_cast<BYTE>((d4[0] & 0x3Fu) | 0x80u);
                    wchar_t guid[48] = {};
                    swprintf_s(guid, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                        d1, d2, d3,
                        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]);
                    const DWORD gsz = static_cast<DWORD>((wcslen(guid) + 1) * sizeof(wchar_t));
                    RegSetValueExW(hInst, L"ContainerId", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(guid), gsz);
                    ++count;
                }
                RegCloseKey(hInst);
            }
            RegCloseKey(hDev);
        }
        RegCloseKey(hRoot);
        logging::print("bluetooth: BTHENUM ContainerIds randomized (%u)", count);
    }

    inline void install() {
        spoof_bthport_keys();
        spoof_radio_address();
        spoof_bth_params();
        spoof_bthenum_containerids();
    }

}
