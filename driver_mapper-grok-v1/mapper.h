#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

// Simple PE structures and mapper interfaces
namespace mapper {

struct KERNEL_CONTEXT {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    uint64_t ntoskrnl_base = 0;
    uint64_t system_cr3 = 0;
};

// Kernel read/write primitives (to be filled by your BYOVD)
bool KernelRead(KERNEL_CONTEXT& ctx, uint64_t address, void* buffer, size_t size);
bool KernelWrite(KERNEL_CONTEXT& ctx, uint64_t address, void* buffer, size_t size);
uint64_t KernelAlloc(KERNEL_CONTEXT& ctx, size_t size, uint32_t protect = PAGE_EXECUTE_READWRITE);
bool KernelFree(KERNEL_CONTEXT& ctx, uint64_t address);

// PE mapping
uint64_t MapDriver(KERNEL_CONTEXT& ctx, const std::vector<uint8_t>& raw_driver);
bool ResolveImports(KERNEL_CONTEXT& ctx, uint64_t mapped_base, const std::vector<uint8_t>& raw);
bool FixRelocations(KERNEL_CONTEXT& ctx, uint64_t mapped_base, uint64_t preferred_base, const std::vector<uint8_t>& raw);
bool CallDriverEntry(KERNEL_CONTEXT& ctx, uint64_t mapped_base, uint64_t entry_rva);

// Helpers
std::vector<uint8_t> ReadFileToVector(const std::wstring& path);
uint64_t GetKernelModuleBase(const char* module_name);

} // namespace mapper
