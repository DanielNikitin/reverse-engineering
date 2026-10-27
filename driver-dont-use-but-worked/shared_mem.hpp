// C++20 / shared_mem.hpp / Windows Kernel & User-Mode / x64
#pragma once

#pragma warning(push)
#pragma warning(disable: 4324)

#include <stdint.h>

namespace dxk_sync {

constexpr uint64_t SHARED_MAGIC          = 0x53594E43484F5354ULL; // "SYNCHOST"
constexpr uint32_t RING_BUFFER_CAPACITY  = 512;
constexpr uint32_t SCATTER_MAX_ITEMS     = 1024;
constexpr uint32_t DATA_BUFFER_SIZE      = 512 * 1024;            // 512 KB

// IOCTL control codes for safe driver-dispatch communications (Data Section Pointer Swap)
constexpr uint32_t IOCTL_DXK_HANDSHAKE   = 0x80002444; // CTL_CODE(0x8000, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)
constexpr uint32_t IOCTL_DXK_DISPATCH    = 0x80002448; // CTL_CODE(0x8000, 0x912, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Protocol command IDs
enum CommandId : uint32_t {
    CMD_HANDSHAKE   = 0x1001,
    CMD_GET_BASE    = 0x1002,
    CMD_READ        = 0x1003,
    CMD_SCATTER     = 0x1004,
    CMD_DISPATCH    = 0x1005
};

// Item / Request execution status
enum ExecutionStatus : uint32_t {
    REQ_IDLE      = 0,
    REQ_PENDING   = 1,
    REQ_COMPLETED = 2,
    REQ_FAILED    = 3
};

// Individual scatter-read entry for batch memory operations
#pragma pack(push, 8)
struct ScatterItem {
    uint64_t target_address;   // Virtual address to read in target process
    uint32_t size;             // Number of bytes to read
    uint32_t buffer_offset;    // Destination offset within SharedRingBuffer::data_buffer
    uint32_t status;           // ExecutionStatus (REQ_PENDING -> REQ_COMPLETED / REQ_FAILED)
    uint32_t bytes_read;       // Number of bytes successfully transferred
};

// Command item inside the ring buffer
struct RingRequest {
    uint32_t cmd;              // CommandId
    uint32_t pid;              // Target process ID
    uint64_t address;          // Virtual address (for CMD_READ)
    uint32_t size;             // Size in bytes (for CMD_READ)
    uint32_t buffer_offset;    // Offset in data_buffer for output
    uint32_t scatter_count;    // Number of ScatterItems if cmd == CMD_SCATTER
    uint32_t status;           // ExecutionStatus
    uint64_t result_value;     // Output value (e.g., base address or total bytes read)
};

// Lockless shared memory ring buffer mapped between kernel and user process
struct alignas(64) SharedRingBuffer {
    uint64_t magic;
    volatile uint32_t head;
    volatile uint32_t tail;
    uint32_t capacity;
    uint32_t reserved;

    // Table of scatter read definitions
    ScatterItem scatter_items[SCATTER_MAX_ITEMS];

    // Command ring
    RingRequest requests[RING_BUFFER_CAPACITY];

    // Shared payload buffer for transferring memory blocks
    uint8_t data_buffer[DATA_BUFFER_SIZE];
};

// Packet passed to the trigger dispatcher (DeviceIoControl)
struct HandshakePacket {
    uint64_t magic;            // Must match SHARED_MAGIC
    uint32_t command;          // CMD_HANDSHAKE or CMD_DISPATCH
    uint32_t status;           // 0 on success, NTSTATUS on failure
    uint64_t user_buffer;      // Virtual address of SharedRingBuffer mapped into user-mode
    uint64_t param;            // Optional direct parameter
};
#pragma pack(pop)

} // namespace dxk_sync
