#include "mapper.h"
#include <winternl.h>
#include <psapi.h>
#pragma comment(lib, "ntdll.lib")

namespace mapper {

// ============================================================================
// Kernel primitives - REPLACE THESE with your actual BYOVD (iqvw64e, etc.)
// ============================================================================
bool KernelRead(KERNEL_CONTEXT& ctx, uint64_t address, void* buffer, size_t size) {
    // TODO: Implement via vulnerable driver IOCTL
    // Example for iqvw64e.sys style: DeviceIoControl with copy memory
    std::cout << "[*] KernelRead stub called for 0x" << std::hex << address << std::endl;
    return false; // replace with real impl
}

bool KernelWrite(KERNEL_CONTEXT& ctx, uint64_t address, void* buffer, size_t size) {
    std::cout << "[*] KernelWrite stub called for 0x" << std::hex << address << std::endl;
    return false;
}

uint64_t KernelAlloc(KERNEL_CONTEXT& ctx, size_t size, uint32_t protect) {
    std::cout << "[*] KernelAlloc stub (" << size << " bytes)" << std::endl;
    return 0;
}

bool KernelFree(KERNEL_CONTEXT& ctx, uint64_t address) {
    return false;
}

// ============================================================================
// PE Mapping core
// ============================================================================
uint64_t MapDriver(KERNEL_CONTEXT& ctx, const std::vector<uint8_t>& raw_driver) {
    if (raw_driver.size() < sizeof(IMAGE_DOS_HEADER)) return 0;

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_driver.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw_driver.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    size_t image_size = nt->OptionalHeader.SizeOfImage;
    uint64_t mapped = KernelAlloc(ctx, image_size);
    if (!mapped) {
        std::cout << "[-] Kernel allocation failed\n";
        return 0;
    }

    std::cout << "[+] Allocated kernel memory at 0x" << std::hex << mapped << std::endl;

    // Copy headers
    KernelWrite(ctx, mapped, (void*)raw_driver.data(), nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData == 0) continue;
        uint64_t dest = mapped + section->VirtualAddress;
        const uint8_t* src = raw_driver.data() + section->PointerToRawData;
        KernelWrite(ctx, dest, (void*)src, section->SizeOfRawData);
    }

    // Relocations
    if (!FixRelocations(ctx, mapped, nt->OptionalHeader.ImageBase, raw_driver)) {
        std::cout << "[-] Relocation failed\n";
        KernelFree(ctx, mapped);
        return 0;
    }

    // Imports
    if (!ResolveImports(ctx, mapped, raw_driver)) {
        std::cout << "[-] Import resolution failed\n";
        KernelFree(ctx, mapped);
        return 0;
    }

    // Entry point
    uint64_t entry = mapped + nt->OptionalHeader.AddressOfEntryPoint;
    if (!CallDriverEntry(ctx, mapped, nt->OptionalHeader.AddressOfEntryPoint)) {
        std::cout << "[-] DriverEntry call failed\n";
        KernelFree(ctx, mapped);
        return 0;
    }

    std::cout << "[+] Driver mapped and entry called successfully at 0x" << std::hex << mapped << std::endl;
    return mapped;
}

bool FixRelocations(KERNEL_CONTEXT& ctx, uint64_t mapped_base, uint64_t preferred_base, const std::vector<uint8_t>& raw) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + dos->e_lfanew);

    auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.Size == 0) return true;

    int64_t delta = (int64_t)mapped_base - (int64_t)preferred_base;
    if (delta == 0) return true;

    // Read reloc directory from kernel (or use raw if still matching)
    std::vector<uint8_t> reloc_buf(reloc_dir.Size);
    if (!KernelRead(ctx, mapped_base + reloc_dir.VirtualAddress, reloc_buf.data(), reloc_dir.Size))
        return false;

    auto reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reloc_buf.data());
    while (reloc->VirtualAddress) {
        uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* list = reinterpret_cast<WORD*>(reloc + 1);

        for (uint32_t i = 0; i < count; i++) {
            if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                uint64_t patch_addr = mapped_base + reloc->VirtualAddress + (list[i] & 0xFFF);
                uint64_t value = 0;
                if (KernelRead(ctx, patch_addr, &value, sizeof(value))) {
                    value += delta;
                    KernelWrite(ctx, patch_addr, &value, sizeof(value));
                }
            }
        }
        reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
    }
    return true;
}

bool ResolveImports(KERNEL_CONTEXT& ctx, uint64_t mapped_base, const std::vector<uint8_t>& raw) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + dos->e_lfanew);

    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0) return true;

    // Simplified: assumes ntoskrnl imports only (extend for other modules)
    uint64_t ntos = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntos) return false;

    IMAGE_IMPORT_DESCRIPTOR desc{};
    uint64_t desc_addr = mapped_base + import_dir.VirtualAddress;

    while (true) {
        if (!KernelRead(ctx, desc_addr, &desc, sizeof(desc))) return false;
        if (desc.Name == 0) break;

        // Read DLL name
        char dll_name[64]{};
        KernelRead(ctx, mapped_base + desc.Name, dll_name, sizeof(dll_name) - 1);

        std::cout << "[*] Resolving imports from " << dll_name << std::endl;

        // Walk thunks (simplified - only name imports)
        uint64_t thunk_addr = mapped_base + desc.FirstThunk;
        uint64_t orig_thunk = desc.OriginalFirstThunk ? mapped_base + desc.OriginalFirstThunk : thunk_addr;

        while (true) {
            uint64_t thunk_data = 0;
            if (!KernelRead(ctx, orig_thunk, &thunk_data, sizeof(thunk_data))) break;
            if (thunk_data == 0) break;

            if (!(thunk_data & IMAGE_ORDINAL_FLAG64)) {
                // Named import
                uint64_t name_addr = mapped_base + (thunk_data & 0xFFFFFFFF) + 2; // skip hint
                char func_name[128]{};
                KernelRead(ctx, name_addr, func_name, sizeof(func_name) - 1);

                // TODO: Resolve actual address via ntoskrnl export table walk
                uint64_t resolved = 0; // GetProcAddress equivalent in kernel
                std::cout << "  -> " << func_name << " (stub)\n";

                KernelWrite(ctx, thunk_addr, &resolved, sizeof(resolved));
            }
            orig_thunk += sizeof(uint64_t);
            thunk_addr += sizeof(uint64_t);
        }
        desc_addr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return true;
}

bool CallDriverEntry(KERNEL_CONTEXT& ctx, uint64_t mapped_base, uint64_t entry_rva) {
    uint64_t entry = mapped_base + entry_rva;
    std::cout << "[*] Calling DriverEntry at 0x" << std::hex << entry << std::endl;

    // Typical call: DriverEntry(DriverObject=NULL or fake, RegistryPath=NULL)
    // Real implementation uses a kernel shellcode or APC/thread to invoke it
    // For PoC we just log
    return true;
}

// ============================================================================
// Helpers
// ============================================================================
std::vector<uint8_t> ReadFileToVector(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(size);
    f.read(reinterpret_cast<char*>(buf.data()), size);
    return buf;
}

uint64_t GetKernelModuleBase(const char* module_name) {
    // Use NtQuerySystemInformation or EnumDeviceDrivers
    LPVOID drivers[1024];
    DWORD needed = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        for (DWORD i = 0; i < needed / sizeof(LPVOID); i++) {
            char name[256]{};
            if (GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name))) {
                if (_stricmp(name, module_name) == 0)
                    return reinterpret_cast<uint64_t>(drivers[i]);
            }
        }
    }
    return 0;
}

} // namespace mapper
