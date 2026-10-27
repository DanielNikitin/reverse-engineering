#include "mapper.h"
#include <iostream>
#include <string>

// ============================================================================
// Example usage of the custom driver mapper
// ============================================================================
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: mapper.exe <path_to_custom_driver.sys>\n";
        return 1;
    }

    std::wstring driver_path = argv[1];
    auto raw = mapper::ReadFileToVector(driver_path);
    if (raw.empty()) {
        std::wcout << L"[-] Failed to read driver file\n";
        return 1;
    }

    std::cout << "[+] Loaded " << raw.size() << " bytes of driver\n";

    mapper::KERNEL_CONTEXT ctx{};

    // TODO: Open vulnerable driver and initialize primitives
    // Example:
    // ctx.hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, ...);
    // Then implement KernelRead/Write/Alloc using the IOCTL

    uint64_t mapped_base = mapper::MapDriver(ctx, raw);
    if (!mapped_base) {
        std::cout << "[-] Mapping failed\n";
        return 1;
    }

    std::cout << "[+] Success. Mapped base: 0x" << std::hex << mapped_base << std::endl;
    return 0;
}
