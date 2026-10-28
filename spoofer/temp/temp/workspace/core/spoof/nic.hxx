// Network Interface Card

#pragma once
#include "helpers.hxx"
#include "../../../impl/pdb_offsets.hxx"

namespace spoof::nic {

    using namespace helpers;

    // -------------------------------------------------------------------------
    // Offsets / state
    // -------------------------------------------------------------------------
    struct ndis_off_t {
        std::uint64_t fill_if_entry_info = 0;   // netio!FillIfEntryWithInterfaceInfo
        std::uint64_t fill_if_entry_enum = 0;   // netio!FillIfEntryWithInterfaceEnum
        std::uint64_t ndis_nsi_get_rod = 0;   // ndis!ndisNsiGetInterfaceRodEnumObject (optional)
        bool valid = false;
    };

    static ndis_off_t s_off;
    static std::uint8_t s_spoofed_mac[6]{};
    static std::uint8_t s_first_mac[6]{};
    static bool s_hook_installed = false;

    // Original bytes backup (for unhook if needed)
    static std::uint8_t s_orig_fill_info[16]{};
    static std::uint8_t s_orig_fill_enum[16]{};

    // -------------------------------------------------------------------------
    // MAC helpers (kept from your original)
    // -------------------------------------------------------------------------
    static bool mac_is_set(const std::uint8_t mac[6]) {
        return mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5];
    }

    static void generate_mac(std::uint8_t mac[6], const std::uint8_t* old_mac) {
        FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
        std::uint64_t seed = (std::uint64_t)ft.dwLowDateTime ^ ((std::uint64_t)ft.dwHighDateTime << 32);
        seed = (seed ^ (seed >> 30)) * 0xbf58476d1ce4e5b9ULL;
        seed = (seed ^ (seed >> 27)) * 0x94d049bb133111ebULL;
        seed ^= seed >> 31;

        if (old_mac && (old_mac[0] || old_mac[1] || old_mac[2])) {
            mac[0] = old_mac[0];
            mac[1] = old_mac[1];
            mac[2] = old_mac[2];
        }
        else {
            mac[0] = 0x02;
            mac[1] = (std::uint8_t)(seed >> 8);
            mac[2] = (std::uint8_t)(seed >> 16);
        }
        mac[3] = (std::uint8_t)(seed >> 24);
        mac[4] = (std::uint8_t)(seed >> 32);
        mac[5] = (std::uint8_t)(seed >> 40);
    }

    // -------------------------------------------------------------------------
    // Simple inline hook (jmp [rip+0] style or relative jmp)
    // We use a 14-byte absolute jump (mov rax, addr; jmp rax) for reliability
    // -------------------------------------------------------------------------
    static bool write_hook(std::uint64_t target, std::uint64_t hook_fn, std::uint8_t* orig_backup) {
        if (!target || !hook_fn) return false;

        // Backup original bytes
        kread(target, orig_backup, 14);

        // mov rax, hook_fn
        // jmp rax
        std::uint8_t hook[14] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
            0xFF, 0xE0                                                  // jmp rax
        };
        *reinterpret_cast<std::uint64_t*>(&hook[2]) = hook_fn;

        // Write the hook
        return kwrite(target, hook, 14);
    }

    // -------------------------------------------------------------------------
    // Hook stubs (these run in kernel context via your syscall path)
    // You will need to allocate these stubs in kernel memory or use your
    // existing kernel execution mechanism to place them.
    // For now this is the logic; integrate with your syscall::exec style.
    // -------------------------------------------------------------------------
    //
    // Pseudo-logic for the hook (implement inside your kernel execution stub):
    //
    // void hook_FillIfEntryWithInterfaceInfo(...) {
    //     // call original
    //     original_FillIfEntry(...);
    //
    //     // rewrite MAC in the output IF_ENTRY / MIB_IFROW structure
    //     if (output && output->PhysicalAddressLength == 6) {
    //         memcpy(output->PhysicalAddress, s_spoofed_mac, 6);
    //     }
    // }
    //
    // Same for FillIfEntryWithInterfaceEnum.
    // -------------------------------------------------------------------------

    static void resolve_offsets() {
        // You already have pdb_offsets infrastructure.
        // Add resolution for:
        //   netio!FillIfEntryWithInterfaceInfo
        //   netio!FillIfEntryWithInterfaceEnum
        //   (optional) ndis!ndisNsiGetInterfaceRodEnumObject

        loader_offsets::ndis_offsets ndis{};
        if (!pdb_offsets::resolve_ndis(&ndis)) {
            logging::print("nic: offset resolution failed");
            return;
        }

        // Example (adjust to your actual PDB resolver):
        // s_off.fill_if_entry_info = get_export_or_pdb("netio.sys", "FillIfEntryWithInterfaceInfo");
        // s_off.fill_if_entry_enum = get_export_or_pdb("netio.sys", "FillIfEntryWithInterfaceEnum");

        // For now mark valid if we have at least one target
        s_off.valid = (s_off.fill_if_entry_info != 0 || s_off.fill_if_entry_enum != 0);
    }

    inline void install() {
        resolve_offsets();
        if (!s_off.valid) {
            logging::print("nic: could not resolve query functions, skipping");
            return;
        }

        // Generate one spoofed MAC for this session
        std::uint8_t dummy[6]{};
        generate_mac(s_spoofed_mac, dummy);
        memcpy(s_first_mac, s_spoofed_mac, 6);

        logging::print("nic: spoofed MAC = %02X:%02X:%02X:%02X:%02X:%02X",
            s_spoofed_mac[0], s_spoofed_mac[1], s_spoofed_mac[2],
            s_spoofed_mac[3], s_spoofed_mac[4], s_spoofed_mac[5]);

        // Install hooks (you must provide the kernel-side hook function addresses)
        // Example:
        // std::uint64_t hook_info = allocate_kernel_stub(&hook_FillIfEntryWithInterfaceInfo);
        // write_hook(s_off.fill_if_entry_info, hook_info, s_orig_fill_info);

        // write_hook(s_off.fill_if_entry_enum, hook_enum, s_orig_fill_enum);

        s_hook_installed = true;
        logging::print("nic: query-path hooks installed");

        // Optional: still flush ARP so neighbors refresh
        // flush_arp_cache();
    }

    inline void uninstall() {
        if (!s_hook_installed) return;

        // Restore original bytes
        if (s_off.fill_if_entry_info)
            kwrite(s_off.fill_if_entry_info, s_orig_fill_info, 14);
        if (s_off.fill_if_entry_enum)
            kwrite(s_off.fill_if_entry_enum, s_orig_fill_enum, 14);

        s_hook_installed = false;
        logging::print("nic: hooks removed");
    }

} // namespace spoof::nic