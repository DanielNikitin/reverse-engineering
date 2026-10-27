// C++20 / offsets.hpp / Windows Kernel / x64
#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <stdint.h>

namespace dxk_sync {

// Forward declarations for kernel-level caller compatibility
inline uintptr_t GetProcessSectionBaseAddress(PEPROCESS proc);
inline uint64_t GetProcessDirectoryTableBase(PEPROCESS proc);
inline uint64_t GetProcessUserDirectoryTableBase(PEPROCESS proc);
inline PEPROCESS FindProcessByPid(uint32_t pid);

// Dynamic structure offsets resolved at runtime from PsInitialSystemProcess.
// ponytail: dynamic discovery avoids brittle hardcoded offsets across Win10/Win11 builds.
struct ProcessOffsets {
    uint32_t unique_pid_offset;         // EPROCESS::UniqueProcessId
    uint32_t active_links_offset;       // EPROCESS::ActiveProcessLinks
    uint32_t cr3_offset;                // KPROCESS::DirectoryTableBase (always 0x28 on x64)
    uint32_t user_cr3_offset;           // KPROCESS::UserDirectoryTableBase (KVA shadow: 0x388 / 0x390)
    uint32_t section_base_offset;       // EPROCESS::SectionBaseAddress
    uint32_t image_name_offset;         // EPROCESS::ImageFileName
    bool initialized;
};

inline ProcessOffsets g_offsets = { 0, 0, 0x28, 0, 0x520, 0x5a8, false };

// Scans PsInitialSystemProcess (PID 4) to dynamically locate critical structure offsets.
inline bool InitializeOffsets() {
    PEPROCESS system_proc = PsInitialSystemProcess;
    if (!system_proc) {
        return false;
    }

    uint8_t* base = reinterpret_cast<uint8_t*>(system_proc);

    // 1. Scan for UniqueProcessId == (HANDLE)4 within first 0x800 bytes
    for (uint32_t off = 0x300; off < 0x600; off += sizeof(void*)) {
        if (*reinterpret_cast<uint64_t*>(base + off) == 4) {
            g_offsets.unique_pid_offset = off;
            g_offsets.active_links_offset = off + sizeof(void*);
            break;
        }
    }

    // 2. Scan for "System" string within ImageFileName range
    for (uint32_t off = 0x400; off < 0x700; ++off) {
        if (base[off] == 'S' && base[off + 1] == 'y' && base[off + 2] == 's' &&
            base[off + 3] == 't' && base[off + 4] == 'e' && base[off + 5] == 'm' &&
            base[off + 6] == '\0') {
            g_offsets.image_name_offset = off;
            break;
        }
    }

    // 3. Determine SectionBaseAddress offset based on OS build version
    RTL_OSVERSIONINFOW os_ver = { 0 };
    os_ver.dwOSVersionInfoSize = sizeof(os_ver);
    if (NT_SUCCESS(RtlGetVersion(&os_ver))) {
        if (os_ver.dwBuildNumber >= 26100) {
            // Windows 11 24H2
            g_offsets.section_base_offset = 0x528;
            g_offsets.user_cr3_offset = 0x390;
        } else if (os_ver.dwBuildNumber >= 22000) {
            // Windows 11 21H2 - 23H2
            g_offsets.section_base_offset = 0x520;
            g_offsets.user_cr3_offset = 0x390;
        } else {
            // Windows 10
            g_offsets.section_base_offset = 0x520;
            g_offsets.user_cr3_offset = 0x388;
        }
    }

    g_offsets.cr3_offset = 0x28; // Architectural hardware requirement on x86-64
    g_offsets.initialized = (g_offsets.unique_pid_offset != 0 && g_offsets.image_name_offset != 0);

    return g_offsets.initialized;
}

// Passively walks ActiveProcessLinks to find EPROCESS by PID without handles or API traces.
inline PEPROCESS FindProcessByPid(uint32_t pid) {
    if (!g_offsets.initialized && !InitializeOffsets()) {
        return nullptr;
    }

    PEPROCESS system_proc = PsInitialSystemProcess;
    if (!system_proc) return nullptr;

    PLIST_ENTRY start_link = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uint8_t*>(system_proc) + g_offsets.active_links_offset
    );
    PLIST_ENTRY current_link = start_link;

    do {
        uint8_t* eproc_addr = reinterpret_cast<uint8_t*>(current_link) - g_offsets.active_links_offset;
        uint64_t current_pid = *reinterpret_cast<uint64_t*>(eproc_addr + g_offsets.unique_pid_offset);

        if (current_pid == static_cast<uint64_t>(pid)) {
            return reinterpret_cast<PEPROCESS>(eproc_addr);
        }

        current_link = current_link->Flink;
        if (!current_link || current_link == current_link->Flink) {
            break;
        }
    } while (current_link != start_link);

    return nullptr;
}

// Retrieves the process DirectoryTableBase (CR3) for physical address translation.
inline uint64_t GetProcessDirectoryTableBase(PEPROCESS process) {
    if (!process) return 0;
    uint8_t* eproc = reinterpret_cast<uint8_t*>(process);
    return *reinterpret_cast<uint64_t*>(eproc + g_offsets.cr3_offset);
}

// Retrieves the UserDirectoryTableBase (for KVA-shadowed kernels).
inline uint64_t GetProcessUserDirectoryTableBase(PEPROCESS process) {
    if (!process || !g_offsets.user_cr3_offset) return 0;
    uint8_t* eproc = reinterpret_cast<uint8_t*>(process);
    return *reinterpret_cast<uint64_t*>(eproc + g_offsets.user_cr3_offset);
}

// Safely extracts SectionBaseAddress directly from EPROCESS without open handles or Zw queries.
inline uintptr_t GetProcessSectionBaseAddress(PEPROCESS process) {
    if (!process) return 0;
    if (!g_offsets.initialized && !InitializeOffsets()) return 0;

    uint8_t* eproc = reinterpret_cast<uint8_t*>(process);
    return *reinterpret_cast<uintptr_t*>(eproc + g_offsets.section_base_offset);
}

} // namespace dxk_sync
