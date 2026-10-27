#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

uintptr_t module_base = 0;

class MemoryManager {
private:
    DWORD processId = 0;
    HANDLE hProcess = nullptr;

public:
    // Constructor / Destructor
    MemoryManager() = default;
    ~MemoryManager() {
        CleanUp();
    }

    // Prevents accidental copying of process handles
    MemoryManager(const MemoryManager&) = delete;
    MemoryManager& operator=(const MemoryManager&) = delete;

    // Returns if the manager has an active handle to a target process
    bool IsAttached() const {
        return hProcess != nullptr;
    }

    // Automatically finds the process ID by name and opens a high-access handle
    bool Attach(const std::wstring& processName) {
        CleanUp();

        // 1. Take a snapshot of all active processes
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        // 2. Enumerate through processes until finding a match
        if (Process32FirstW(hSnapshot, &processEntry)) {
            do {
                if (processName == processEntry.szExeFile) {
                    this->processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);

        if (this->processId == 0) return false;

        // 3. Open a process handle with virtual memory read/write permissions
        this->hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, this->processId);
        return (this->hProcess != nullptr);
    }

    // Obtains the base memory address of a module (e.g., "client.dll" or the main executable)
    uintptr_t GetModuleBaseAddress(const std::wstring& moduleName) {
        if (this->processId == 0) return 0;

        // We use TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32 to capture both 32-bit and 64-bit target applications
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->processId);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

        MODULEENTRY32W moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32W);
        uintptr_t baseAddress = 0;

        if (Module32FirstW(hSnapshot, &moduleEntry)) {
            do {
                if (moduleName == moduleEntry.szModule) {
                    baseAddress = reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
                    break;
                }
            } while (Module32NextW(hSnapshot, &moduleEntry));
        }

        CloseHandle(hSnapshot);
        return baseAddress;
    }

    // Template function to read any primitive variable type or primitive struct safely
    template <typename T>
    T Read(uintptr_t address) {
        T buffer{};
        if (hProcess == nullptr || address == 0) return buffer;

        ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), &buffer, sizeof(T), nullptr);
        return buffer;
    }

    // Template function to write any primitive value or raw data type to memory
    template <typename T>
    bool Write(uintptr_t address, const T& value) {
        if (hProcess == nullptr || address == 0) return false;

        SIZE_T bytesWritten;
        BOOL result = WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), &value, sizeof(T), &bytesWritten);
        return (result && bytesWritten == sizeof(T));
    }

    // Specialized function for resolving pointer multi-level offset paths (e.g., Base -> Offset1 -> Offset2)
    uintptr_t ResolvePointerChain(uintptr_t baseAddress, const std::vector<unsigned int>& offsets) {
        uintptr_t currentAddress = baseAddress;
        for (size_t i = 0; i < offsets.size(); ++i) {
            currentAddress = Read<uintptr_t>(currentAddress);
            currentAddress += offsets[i];
        }
        return currentAddress;
    }

    // Safely closes any lingering OS handles
    void CleanUp() {
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = nullptr;
        }
        processId = 0;
    }
};

MemoryManager mem;