#pragma once
#include "helpers.hxx"
#include "../../../impl/pdb_offsets.hxx"
#include <vector>
#include <array>

namespace arp {

    static constexpr std::uint32_t NB_STATE_UNREACHABLE = 0;
    static constexpr std::uint32_t NB_STATE_INCOMPLETE  = 1;

    static loader_offsets::tcpip_offsets s_off{};
    static bool s_resolved = false;

    struct arp_ip_addr_string {
        arp_ip_addr_string* Next;
        char IpAddress[16];
        char IpMask[16];
        DWORD Context;
    };
    struct arp_adapter_info {
        arp_adapter_info* Next;
        DWORD   ComboIndex;
        char    AdapterName[260];
        char    Description[132];
        UINT    AddressLength;
        BYTE    Address[8];
        DWORD   Index;
        UINT    Type;
        UINT    DhcpEnabled;
        arp_ip_addr_string* CurrentIpAddress;
        arp_ip_addr_string  IpAddressList;
        arp_ip_addr_string  GatewayList;
        arp_ip_addr_string  DhcpServer;
        BOOL    HaveWins;
        arp_ip_addr_string  PrimaryWinsServer;
        arp_ip_addr_string  SecondaryWinsServer;
        std::uint64_t LeaseObtained;
        std::uint64_t LeaseExpires;
    };

    using fn_get_adapters_info_t = DWORD(WINAPI*)(arp_adapter_info*, ULONG*);
    using fn_send_arp_t          = DWORD(WINAPI*)(DWORD, DWORD, void*, ULONG*);


    static DWORD parse_ipv4(const char* s) {
        DWORD result = 0;
        for (int shift = 0; shift < 32; shift += 8) {
            DWORD octet = 0;
            while (*s >= '0' && *s <= '9') octet = octet * 10 + (*s++ - '0');
            if (octet > 255) return 0;
            result |= (octet << shift);
            if (*s == '.') ++s;
        }
        return result;
    }

    static std::vector<std::array<std::uint8_t, 6>> get_protected_macs() {
        std::vector<std::array<std::uint8_t, 6>> result;

        const HMODULE iphlp = GetModuleHandleW(L"iphlpapi.dll")
                           ? GetModuleHandleW(L"iphlpapi.dll")
                           : LoadLibraryW(L"iphlpapi.dll");
        if (!iphlp) return result;

        const auto fn_gai = reinterpret_cast<fn_get_adapters_info_t>(
            GetProcAddress(iphlp, "GetAdaptersInfo"));
        const auto fn_arp = reinterpret_cast<fn_send_arp_t>(
            GetProcAddress(iphlp, "SendARP"));
        if (!fn_gai || !fn_arp) return result;

        ULONG sz = 0;
        fn_gai(nullptr, &sz);
        if (!sz) return result;
        std::vector<std::uint8_t> buf(sz);
        auto* info = reinterpret_cast<arp_adapter_info*>(buf.data());
        if (fn_gai(info, &sz) != ERROR_SUCCESS) return result;

        for (auto* a = info; a; a = a->Next) {
            for (auto* gw = &a->GatewayList; gw; gw = gw->Next) {
                const DWORD ip = parse_ipv4(gw->IpAddress);
                if (!ip) continue;

                std::array<std::uint8_t, 6> mac{};
                ULONG mac_len = 6;
                if (fn_arp(ip, 0, mac.data(), &mac_len) == 0 && mac_len == 6) {
                    bool all_zero = true;
                    for (auto b : mac) if (b) { all_zero = false; break; }
                    if (!all_zero) {
                        logging::print("spoof: arp — protecting gateway MAC %02X:%02X:%02X:%02X:%02X:%02X",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        result.push_back(mac);
                    }
                }
            }
        }
        return result;
    }

    inline bool resolve_offsets() {
        if (s_resolved) return true;
        if (!pdb_offsets::resolve_tcpip(&s_off)) {
            logging::print("spoof: arp — tcpip offset resolution failed");
            return false;
        }
        s_resolved = true;
        return true;
    }

    static std::uint32_t spoof_neighbor_table(
        std::uint64_t neighbor_table_va,
        const std::vector<std::array<std::uint8_t, 6>>& protected_macs)
    {
        using namespace spoof::helpers;
        std::uint32_t count = 0;

        const std::uint32_t table_size = kread_val<std::uint32_t>(
            neighbor_table_va + s_off.ht_size_off);
        const std::uint64_t directory  = kread_val<std::uint64_t>(
            neighbor_table_va + s_off.ht_directory_off);

        if (!table_size || table_size > 4096 || !is_kva(directory))
            return 0;

        for (std::uint32_t i = 0; i < table_size; ++i) {
            const std::uint64_t bucket = directory + static_cast<std::uint64_t>(i) * 16u;
            std::uint64_t cur = kread_val<std::uint64_t>(bucket);

            for (std::uint32_t depth = 0;
                 depth < 256 && is_kva(cur) && cur != bucket;
                 ++depth)
            {
                const std::uint64_t nb = cur - s_off.nb_entry_offset;
                const std::uint64_t iface = kread_val<std::uint64_t>(nb + s_off.nb_interface);
                const std::uint32_t state = kread_val<std::uint32_t>(nb + s_off.nb_state);
                const std::uint32_t refs  = kread_val<std::uint32_t>(nb + s_off.nb_refcount);

                if (iface && refs &&
                    state != NB_STATE_UNREACHABLE && state != NB_STATE_INCOMPLETE)
                {

                    std::uint8_t mac[6];
                    kread(nb + s_off.nb_dl_address, mac, 6);
                    if (mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5]) {

                        bool skip = false;
                        for (const auto& p : protected_macs) {
                            if (p[0]==mac[0] && p[1]==mac[1] && p[2]==mac[2] &&
                                p[3]==mac[3] && p[4]==mac[4] && p[5]==mac[5]) {
                                skip = true; break;
                            }
                        }
                        if (!skip) {
                            mac[3] = static_cast<std::uint8_t>(rand_next());
                            mac[4] = static_cast<std::uint8_t>(rand_next());
                            mac[5] = static_cast<std::uint8_t>(rand_next());
                            kwrite(nb + s_off.nb_dl_address, mac, 6);
                            ++count;
                        }
                    }
                }

                cur = kread_val<std::uint64_t>(cur);
            }
        }
        return count;
    }

    static std::uint32_t patch_local_interface_macs(std::uint64_t cs) {
        using namespace spoof::helpers;
        if (!s_off.compartment_if_list || !s_off.if_compartment_link || !s_off.if_dl_phys_addr)
            return 0;
        if (!spoof::nic::mac_is_set(spoof::nic::s_first_mac))
            return 0;

        const std::uint32_t count     = kread_val<std::uint32_t>(cs + s_off.cs_count);
        const std::uint64_t table_ptr = kread_val<std::uint64_t>(cs + s_off.cs_table);
        if (!count || count > 4096 || !is_kva(table_ptr)) return 0;

        std::uint32_t patched = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint64_t bucket = table_ptr + static_cast<std::uint64_t>(i) * 16u;
            std::uint64_t cur = kread_val<std::uint64_t>(bucket);

            for (std::uint32_t d = 0; d < 64 && is_kva(cur) && cur != bucket; ++d) {
                const std::uint64_t compartment  = cur - s_off.cs_entry_offset;
                const std::uint64_t if_list_va   = compartment + s_off.compartment_if_list;
                std::uint64_t if_flink = kread_val<std::uint64_t>(if_list_va);

                for (std::uint32_t j = 0; j < 64 && is_kva(if_flink) && if_flink != if_list_va; ++j) {
                    const std::uint64_t iface     = if_flink - s_off.if_compartment_link;
                    const std::uint64_t phys_va   = iface + s_off.if_dl_phys_addr;
                    const std::uint16_t len = kread_val<std::uint16_t>(phys_va);
                    if (len == 6) {
                        std::uint8_t old_mac[6]{};
                        kread(phys_va + 2, old_mac, 6);
                        if (old_mac[0] || old_mac[1] || old_mac[2] ||
                            old_mac[3] || old_mac[4] || old_mac[5]) {
                            kwrite(phys_va + 2, spoof::nic::s_first_mac, 6);
                            ++patched;
                        }
                    }
                    if_flink = kread_val<std::uint64_t>(if_flink);
                }
                cur = kread_val<std::uint64_t>(cur);
            }
        }
        return patched;
    }

    inline void install() {
        using namespace spoof::helpers;

        if (!resolve_offsets()) return;


        const auto protected_macs = get_protected_macs();

        const std::uint64_t tcpip_base = get_kernel_module_base(L"tcpip.sys");
        if (!tcpip_base) {
            logging::print("spoof: arp — tcpip.sys not found in PsLoadedModuleList");
            return;
        }

        const std::uint64_t cs_ptr_va = tcpip_base + s_off.compartment_set_rva;

        auto try_resolve_cs = [&](std::uint64_t candidate) -> bool {
            const std::uint32_t c = kread_val<std::uint32_t>(candidate + s_off.cs_count);
            const std::uint64_t t = kread_val<std::uint64_t>(candidate + s_off.cs_table);
            return c > 0 && c <= 4096 && is_kva(t);
        };

        std::uint64_t cs = 0;

        const std::uint64_t cs_deref = kread_val<std::uint64_t>(cs_ptr_va);
        if (is_kva(cs_deref) && try_resolve_cs(cs_deref)) {
            cs = cs_deref;
            logging::print("spoof: arp — TcpCompartmentSet resolved via pointer");
        }

        else if (try_resolve_cs(cs_ptr_va)) {
            cs = cs_ptr_va;
            logging::print("spoof: arp — TcpCompartmentSet resolved as embedded struct");
        }
        else {
            logging::print("spoof: arp — TcpCompartmentSet not valid (ptr=0x%llX deref=0x%llX count_A=%u count_B=%u)",
                (unsigned long long)cs_ptr_va,
                (unsigned long long)cs_deref,
                kread_val<std::uint32_t>(cs_deref + s_off.cs_count),
                kread_val<std::uint32_t>(cs_ptr_va + s_off.cs_count));
            return;
        }

        const std::uint32_t count     = kread_val<std::uint32_t>(cs + s_off.cs_count);
        const std::uint64_t table_ptr = kread_val<std::uint64_t>(cs + s_off.cs_table);

        std::uint32_t total_spoofed = 0;

        for (std::uint32_t i = 0; i < count; ++i) {

            const std::uint64_t bucket = table_ptr + static_cast<std::uint64_t>(i) * 16u;
            std::uint64_t cur = kread_val<std::uint64_t>(bucket);

            for (std::uint32_t depth = 0;
                 depth < 64 && is_kva(cur) && cur != bucket;
                 ++depth)
            {
                const std::uint64_t compartment = cur - s_off.cs_entry_offset;
                const std::uint64_t nb_table_va = compartment + s_off.compartment_nb_table;
                total_spoofed += spoof_neighbor_table(nb_table_va, protected_macs);
                cur = kread_val<std::uint64_t>(cur);
            }
        }

        logging::print("spoof: ARP — spoofed %u neighbor entries", total_spoofed);

        const std::uint32_t if_patched = patch_local_interface_macs(cs);
        if (if_patched)
            logging::print("spoof: ARP — patched %u FL_INTERFACE local MAC(s) in tcpip.sys", if_patched);
        else if (!s_off.compartment_if_list || !s_off.if_compartment_link || !s_off.if_dl_phys_addr)
            logging::print("spoof: ARP — FL_INTERFACE SendARP patch skipped (PDB field offsets unavailable)");
    }

}
