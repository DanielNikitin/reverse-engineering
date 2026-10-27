// C++20 / pml4.hpp / Windows Kernel / x64
#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <stdint.h>

namespace dxk_sync {

// Hardware page table translation bitmasks (x86-64 architecture)
constexpr uint64_t PFN_MASK        = 0x000FFFFFFFFFF000ULL;
constexpr uint64_t PAGE_MASK_4KB   = 0x0000000000000FFFULL;
constexpr uint64_t PAGE_MASK_2MB   = 0x00000000001FFFFFULL;
constexpr uint64_t PAGE_MASK_1GB   = 0x000000003FFFFFFFULL;
constexpr uint64_t PAGE_SIZE_4KB   = 0x1000ULL;

constexpr uint64_t PML4_SHIFT      = 39;
constexpr uint64_t PDPT_SHIFT      = 30;
constexpr uint64_t PD_SHIFT        = 21;
constexpr uint64_t PT_SHIFT        = 12;
constexpr uint64_t INDEX_MASK      = 0x1FFULL;

// Maximum valid physical memory address detected in the system to prevent machine checks/BSODs
inline uint64_t g_max_physical_address = 0;

// Initializes physical memory bounds using Windows physical memory descriptors
inline bool InitPhysicalMemoryLimits() {
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) {
        // Fallback default limit: 128 GB safe cap
        g_max_physical_address = 0x2000000000ULL;
        return false;
    }

    uint64_t max_limit = 0;
    for (ULONG i = 0; ranges[i].BaseAddress.QuadPart || ranges[i].NumberOfBytes.QuadPart; ++i) {
        uint64_t limit = static_cast<uint64_t>(ranges[i].BaseAddress.QuadPart + ranges[i].NumberOfBytes.QuadPart);
        if (limit > max_limit) {
            max_limit = limit;
        }
    }

    ExFreePool(ranges);
    g_max_physical_address = max_limit;
    return (g_max_physical_address > 0);
}

// Verifies whether a physical address range is entirely within installed physical RAM
inline bool IsPhysicalAddressValid(uint64_t phys_addr, size_t size = 1) {
    if (g_max_physical_address == 0) {
        InitPhysicalMemoryLimits();
    }
    return (phys_addr > 0 && (phys_addr + size) <= g_max_physical_address);
}

// Reads physical RAM directly without user-mode stack frame or system calls.
// ponytail: MmCopyMemory with MM_COPY_MEMORY_PHYSICAL handles page boundaries and faults safely.
inline bool ReadPhysicalMemory(uint64_t phys_addr, void* buffer, size_t size) {
    if (!buffer || size == 0 || !IsPhysicalAddressValid(phys_addr, size)) {
        return false;
    }

    MM_COPY_ADDRESS copy_addr;
    copy_addr.PhysicalAddress.QuadPart = static_cast<LONGLONG>(phys_addr);
    SIZE_T bytes_transferred = 0;

    NTSTATUS status = MmCopyMemory(buffer, copy_addr, size, MM_COPY_MEMORY_PHYSICAL, &bytes_transferred);
    if (NT_SUCCESS(status) && bytes_transferred == size) {
        return true;
    }

    // Fallback: MmMapIoSpace for environments where physical copy is restricted
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = static_cast<LONGLONG>(phys_addr);
    void* mapped = MmMapIoSpace(pa, size, MmNonCached);
    if (mapped) {
        memcpy(buffer, mapped, size);
        MmUnmapIoSpace(mapped, size);
        return true;
    }

    return false;
}

// Pure software PML4 translation (PML4 -> PDPT -> PD -> PT -> Physical).
// Supports standard 4KB, large 2MB, and huge 1GB pages.
inline uint64_t TranslateVirtualAddress(uint64_t cr3, uint64_t virtual_address) {
    if (!cr3 || !virtual_address) {
        return 0;
    }

    // 1. PML4 Level
    uint64_t pml4_phys = cr3 & PFN_MASK;
    uint64_t pml4_index = (virtual_address >> PML4_SHIFT) & INDEX_MASK;
    uint64_t pml4_entry = 0;

    if (!ReadPhysicalMemory(pml4_phys + (pml4_index * sizeof(uint64_t)), &pml4_entry, sizeof(pml4_entry))) {
        return 0;
    }
    if (!(pml4_entry & 1)) {
        return 0; // Page not present
    }

    // 2. PDPT Level
    uint64_t pdpt_phys = pml4_entry & PFN_MASK;
    uint64_t pdpt_index = (virtual_address >> PDPT_SHIFT) & INDEX_MASK;
    uint64_t pdpt_entry = 0;

    if (!ReadPhysicalMemory(pdpt_phys + (pdpt_index * sizeof(uint64_t)), &pdpt_entry, sizeof(pdpt_entry))) {
        return 0;
    }
    if (!(pdpt_entry & 1)) {
        return 0;
    }

    // Check for 1GB Huge Page (PS bit 7)
    if (pdpt_entry & 0x80) {
        return (pdpt_entry & 0xFFFFFC0000000ULL) + (virtual_address & PAGE_MASK_1GB);
    }

    // 3. Page Directory (PD) Level
    uint64_t pd_phys = pdpt_entry & PFN_MASK;
    uint64_t pd_index = (virtual_address >> PD_SHIFT) & INDEX_MASK;
    uint64_t pd_entry = 0;

    if (!ReadPhysicalMemory(pd_phys + (pd_index * sizeof(uint64_t)), &pd_entry, sizeof(pd_entry))) {
        return 0;
    }
    if (!(pd_entry & 1)) {
        return 0;
    }

    // Check for 2MB Large Page (PS bit 7)
    if (pd_entry & 0x80) {
        return (pd_entry & 0xFFFFFFFFFE00000ULL) + (virtual_address & PAGE_MASK_2MB);
    }

    // 4. Page Table (PT) Level (4KB Standard Page)
    uint64_t pt_phys = pd_entry & PFN_MASK;
    uint64_t pt_index = (virtual_address >> PT_SHIFT) & INDEX_MASK;
    uint64_t pt_entry = 0;

    if (!ReadPhysicalMemory(pt_phys + (pt_index * sizeof(uint64_t)), &pt_entry, sizeof(pt_entry))) {
        return 0;
    }
    if (!(pt_entry & 1)) {
        return 0;
    }

    return (pt_entry & PFN_MASK) + (virtual_address & PAGE_MASK_4KB);
}

// Reads arbitrary virtual memory of the target process, handling 4KB page boundary splits.
inline bool ReadProcessVirtualMemory(uint64_t cr3, uint64_t virtual_address, void* buffer, size_t size, size_t* out_bytes_read = nullptr) {
    if (!cr3 || !virtual_address || !buffer || size == 0) {
        if (out_bytes_read) *out_bytes_read = 0;
        return false;
    }

    uint8_t* out_ptr = reinterpret_cast<uint8_t*>(buffer);
    size_t remaining = size;
    uint64_t current_va = virtual_address;
    size_t total_read = 0;

    while (remaining > 0) {
        uint64_t phys_addr = TranslateVirtualAddress(cr3, current_va);
        if (!phys_addr) {
            break;
        }

        // Determine how many bytes we can read within this 4KB page
        size_t page_offset = current_va & PAGE_MASK_4KB;
        size_t bytes_this_page = PAGE_SIZE_4KB - page_offset;
        if (bytes_this_page > remaining) {
            bytes_this_page = remaining;
        }

        if (!ReadPhysicalMemory(phys_addr, out_ptr, bytes_this_page)) {
            break;
        }

        current_va += bytes_this_page;
        out_ptr += bytes_this_page;
        remaining -= bytes_this_page;
        total_read += bytes_this_page;
    }

    if (out_bytes_read) {
        *out_bytes_read = total_read;
    }

    return (total_read == size);
}

} // namespace dxk_sync
