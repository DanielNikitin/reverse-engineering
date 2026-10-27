// C++20 / memory_bridge.hpp / Windows User-Mode / x64
#pragma once

#include <windows.h>
#include <stdint.h>
#include <vector>
#include <type_traits>

#include "shared_mem.hpp"

namespace dxk_sync {

// Scatter-read descriptor for high-performance batch memory operations
struct ScatterRequest {
    uintptr_t address;         // Virtual address in the target process
    void* target_buffer;       // Destination buffer in client process
    size_t size;               // Byte count to copy
};

class MemoryBridge {
public:
    MemoryBridge();
    ~MemoryBridge();

    // Deleted copy semantics (unique bridge instance)
    MemoryBridge(const MemoryBridge&) = delete;
    MemoryBridge& operator=(const MemoryBridge&) = delete;

    // Connects to the kernel driver via safe pointer-swap gateway (\\.\NUL)
    bool Initialize();

    // Sets default target process ID for subsequent read calls
    void Attach(uint32_t pid);
    uint32_t GetAttachedPid() const { return m_attached_pid; }

    // Obtains executable section base address of the target process without open handles
    uintptr_t GetProcessBase(uint32_t pid = 0);

    // Reads raw block of virtual memory from target process
    bool ReadRaw(uintptr_t address, void* buffer, size_t size, uint32_t pid = 0);

    // Strongly-typed single-value memory read
    template<typename T>
    requires std::is_trivially_copyable_v<T>
    T Read(uintptr_t address, uint32_t pid = 0) {
        T value{};
        ReadRaw(address, &value, sizeof(T), pid);
        return value;
    }

    // Strongly-typed reference-based memory read
    template<typename T>
    requires std::is_trivially_copyable_v<T>
    bool Read(uintptr_t address, T& out, uint32_t pid = 0) {
        return ReadRaw(address, &out, sizeof(T), pid);
    }

    // High-performance batch/scatter read: fetches multiple structures in a single kernel roundtrip
    bool ReadScatter(const ScatterRequest* requests, size_t count, uint32_t pid = 0);
    bool ReadScatter(const std::vector<ScatterRequest>& requests, uint32_t pid = 0);

    // Status query
    bool IsConnected() const { return (m_hDevice != INVALID_HANDLE_VALUE && m_ring != nullptr); }

private:
    // Triggers kernel driver dispatcher to flush and process the ring buffer
    bool TriggerDispatch();

    HANDLE m_hDevice;
    SharedRingBuffer* m_ring;
    uint32_t m_attached_pid;
};

} // namespace dxk_sync
