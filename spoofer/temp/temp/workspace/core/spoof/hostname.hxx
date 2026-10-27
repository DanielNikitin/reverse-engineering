#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>

namespace spoof::hostname {

    using namespace helpers;

    static wchar_t s_hostname[32] = {};

    static void set_sz(HKEY root, const wchar_t* subkey,
                       const wchar_t* value, const wchar_t* data) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;
        const DWORD sz = static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t));
        RegSetValueExW(hk, value, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(data), sz);
        RegCloseKey(hk);
    }

    static void gen_hostname(wchar_t* out, std::size_t cch) {
        const DWORD hex = (rand_next() << 15u) ^ rand_next();
        swprintf_s(out, cch, L"DESKTOP-%07X", hex & 0x0FFFFFFFu);
    }

    static void spoof_computer_name() {
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
            L"ComputerName", s_hostname);
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
            L"ComputerName", s_hostname);
        logging::print("hostname: ComputerName -> %ls", s_hostname);
    }

    static void spoof_tcpip_hostname() {
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            L"Hostname", s_hostname);
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            L"NV Hostname", s_hostname);
        logging::print("hostname: Tcpip Hostname -> %ls", s_hostname);
    }

    static void spoof_env_computername() {
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            L"COMPUTERNAME", s_hostname);
        logging::print("hostname: Environment COMPUTERNAME -> %ls", s_hostname);
    }

    static void spoof_pnp_dnsfqdn() {
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PnP",
            L"DnsFQDN", s_hostname);
        logging::print("hostname: PnP DnsFQDN -> %ls", s_hostname);
    }

    static void spoof_dhcpv6_duid() {
        static const wchar_t k_path[] =
            L"SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;

        DWORD sz = 0, type = 0;
        if (RegQueryValueExW(hk, L"Dhcpv6DUID", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
            && sz && type == REG_BINARY) {
            std::vector<BYTE> buf(sz);
            if (RegQueryValueExW(hk, L"Dhcpv6DUID", nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                for (DWORD i = 4; i < sz; ++i)
                    buf[i] = static_cast<BYTE>(rand_next() & 0xFF);
                RegSetValueExW(hk, L"Dhcpv6DUID", 0, REG_BINARY, buf.data(), sz);
            }
        }
        RegCloseKey(hk);
        logging::print("hostname: Dhcpv6DUID randomized");
    }

    inline void install() {
        gen_hostname(s_hostname, 32);

        spoof_computer_name();
        spoof_tcpip_hostname();
        spoof_dhcpv6_duid();
        spoof_env_computername();
        spoof_pnp_dnsfqdn();


    }

}
