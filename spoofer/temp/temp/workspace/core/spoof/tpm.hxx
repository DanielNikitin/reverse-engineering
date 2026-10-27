#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>

namespace spoof::tpm {

    using namespace helpers;

    static void randomize_binary(HKEY root, const wchar_t* subkey, const wchar_t* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;
        DWORD sz = 0, type = 0;
        RegQueryValueExW(hk, value, nullptr, &type, nullptr, &sz);
        if (sz && type == REG_BINARY) {
            std::vector<BYTE> buf(sz);
            if (RegQueryValueExW(hk, value, nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                RegSetValueExW(hk, value, 0, REG_BINARY, buf.data(), sz);
            }
        }
        RegCloseKey(hk);
    }

    static void delete_value(HKEY root, const wchar_t* subkey, const wchar_t* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;
        RegDeleteValueW(hk, value);
        RegCloseKey(hk);
    }

    static void spoof_tpm_main() {
        static const wchar_t k_path[] = L"SOFTWARE\\Microsoft\\TPM";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;

        static const wchar_t* k_blobs[] = { L"EkCert", L"StorageKey", L"EkPub" };
        for (const auto* val : k_blobs) {
            DWORD sz = 0, type = 0;
            if (RegQueryValueExW(hk, val, nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
                && sz && type == REG_BINARY) {
                std::vector<BYTE> buf(sz);
                if (RegQueryValueExW(hk, val, nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                    for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                    RegSetValueExW(hk, val, 0, REG_BINARY, buf.data(), sz);
                }
            }
        }
        RegCloseKey(hk);
        logging::print("tpm: TPM main registry values randomized");
    }

    static void spoof_calipower() {
        static const wchar_t k_path[] =
            L"SOFTWARE\\Microsoft\\Cryptography\\Calipower";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;

        static const wchar_t* k_blobs[] = { L"EkCert", L"CardId", L"SessionId" };
        for (const auto* val : k_blobs) {
            DWORD sz = 0, type = 0;
            if (RegQueryValueExW(hk, val, nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
                && sz && type == REG_BINARY) {
                std::vector<BYTE> buf(sz);
                if (RegQueryValueExW(hk, val, nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                    for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                    RegSetValueExW(hk, val, 0, REG_BINARY, buf.data(), sz);
                }
            }
        }
        RegCloseKey(hk);
        logging::print("tpm: Calipower keys randomized");
    }

    static void spoof_tpm_service() {
        randomize_binary(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID", L"RandomSeed");
        randomize_binary(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", L"WindowsAIKHash");
        randomize_binary(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", L"PlatformModuleData");
        delete_value(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM", L"Policy");
        logging::print("tpm: TPM service data randomized");
    }

    inline void install() {
        spoof_tpm_main();
        spoof_calipower();
        spoof_tpm_service();
    }

}
