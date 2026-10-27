// C++20 / memory_bridge.cpp / Windows User-Mode / x64
#include "memory_bridge.hpp"
#include <cstring>
#include <chrono>
#include <cassert>

namespace dxk_sync {

MemoryBridge::MemoryBridge()
    : m_hDevice(INVALID_HANDLE_VALUE)
    , m_ring(nullptr)
    , m_attached_pid(0) {
}

MemoryBridge::~MemoryBridge() {
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
    m_ring = nullptr;
}

bool MemoryBridge::Initialize() {
    // Open standard system device object (PatchGuard-safe gateway, requires zero elevated privileges)
    m_hDevice = CreateFileW(
        L"\\\\.\\NUL",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Handshake: exchange magic header and obtain mapped shared memory buffer
    HandshakePacket packet = { 0 };
    packet.magic = SHARED_MAGIC;
    packet.command = CMD_HANDSHAKE;
    packet.status = 0;
    packet.user_buffer = 0;

    DWORD bytes_returned = 0;
    BOOL success = DeviceIoControl(
        m_hDevice,
        IOCTL_DXK_HANDSHAKE,
        &packet,
        sizeof(packet),
        &packet,
        sizeof(packet),
        &bytes_returned,
        nullptr
    );

    if (!success || packet.status != 0 || packet.user_buffer == 0) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
        return false;
    }

    m_ring = reinterpret_cast<SharedRingBuffer*>(packet.user_buffer);
    if (m_ring->magic != SHARED_MAGIC) {
        m_ring = nullptr;
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
        return false;
    }

    return true;
}

void MemoryBridge::Attach(uint32_t pid) {
    m_attached_pid = pid;
}

bool MemoryBridge::TriggerDispatch() {
    if (m_hDevice == INVALID_HANDLE_VALUE || !m_ring) {
        return false;
    }

    HandshakePacket packet = { 0 };
    packet.magic = SHARED_MAGIC;
    packet.command = CMD_DISPATCH;
    packet.status = 0;

    DWORD bytes_returned = 0;
    BOOL success = DeviceIoControl(
        m_hDevice,
        IOCTL_DXK_DISPATCH,
        &packet,
        sizeof(packet),
        &packet,
        sizeof(packet),
        &bytes_returned,
        nullptr
    );

    return (success && packet.status == 0);
}

uintptr_t MemoryBridge::GetProcessBase(uint32_t pid) {
    if (!m_ring) return 0;

    uint32_t target_pid = (pid != 0) ? pid : m_attached_pid;
    if (target_pid == 0) return 0;

    uint32_t slot = m_ring->head % RING_BUFFER_CAPACITY;
    RingRequest& req = m_ring->requests[slot];

    req.cmd = CMD_GET_BASE;
    req.pid = target_pid;
    req.status = REQ_PENDING;
    req.result_value = 0;

    m_ring->head = (slot + 1) % RING_BUFFER_CAPACITY;

    if (!TriggerDispatch()) {
        return 0;
    }

    return (req.status == REQ_COMPLETED) ? static_cast<uintptr_t>(req.result_value) : 0;
}

bool MemoryBridge::ReadRaw(uintptr_t address, void* buffer, size_t size, uint32_t pid) {
    if (!m_ring || !buffer || size == 0 || size > DATA_BUFFER_SIZE) {
        return false;
    }

    uint32_t target_pid = (pid != 0) ? pid : m_attached_pid;
    if (target_pid == 0) return false;

    uint32_t slot = m_ring->head % RING_BUFFER_CAPACITY;
    RingRequest& req = m_ring->requests[slot];

    req.cmd = CMD_READ;
    req.pid = target_pid;
    req.address = address;
    req.size = static_cast<uint32_t>(size);
    req.buffer_offset = 0;
    req.status = REQ_PENDING;
    req.result_value = 0;

    m_ring->head = (slot + 1) % RING_BUFFER_CAPACITY;

    if (!TriggerDispatch()) {
        return false;
    }

    if (req.status == REQ_COMPLETED && req.result_value == size) {
        std::memcpy(buffer, m_ring->data_buffer, size);
        return true;
    }

    return false;
}

bool MemoryBridge::ReadScatter(const ScatterRequest* requests, size_t count, uint32_t pid) {
    if (!m_ring || !requests || count == 0 || count > SCATTER_MAX_ITEMS) {
        return false;
    }

    uint32_t target_pid = (pid != 0) ? pid : m_attached_pid;
    if (target_pid == 0) return false;

    // Pack scatter descriptors into the shared ring buffer
    uint32_t current_data_offset = 0;
    for (size_t i = 0; i < count; ++i) {
        const auto& req = requests[i];
        if (current_data_offset + req.size > DATA_BUFFER_SIZE) {
            return false; // Total payload exceeds shared buffer capacity
        }

        ScatterItem& item = m_ring->scatter_items[i];
        item.target_address = req.address;
        item.size = static_cast<uint32_t>(req.size);
        item.buffer_offset = current_data_offset;
        item.status = REQ_PENDING;
        item.bytes_read = 0;

        current_data_offset += static_cast<uint32_t>(req.size);
    }

    uint32_t slot = m_ring->head % RING_BUFFER_CAPACITY;
    RingRequest& ring_req = m_ring->requests[slot];
    ring_req.cmd = CMD_SCATTER;
    ring_req.pid = target_pid;
    ring_req.scatter_count = static_cast<uint32_t>(count);
    ring_req.status = REQ_PENDING;

    m_ring->head = (slot + 1) % RING_BUFFER_CAPACITY;

    if (!TriggerDispatch()) {
        return false;
    }

    // Unpack responses back into caller destination buffers
    bool all_succeeded = true;
    for (size_t i = 0; i < count; ++i) {
        const ScatterItem& item = m_ring->scatter_items[i];
        if (item.status == REQ_COMPLETED && item.bytes_read == requests[i].size) {
            std::memcpy(requests[i].target_buffer, &m_ring->data_buffer[item.buffer_offset], item.bytes_read);
        } else {
            all_succeeded = false;
        }
    }

    return all_succeeded;
}

bool MemoryBridge::ReadScatter(const std::vector<ScatterRequest>& requests, uint32_t pid) {
    return ReadScatter(requests.data(), requests.size(), pid);
}

} // namespace dxk_sync

#ifdef DXK_SYNC_STANDALONE_TEST
// ponytail: self-check verification assert harness
int main() {
    dxk_sync::MemoryBridge bridge;
    if (!bridge.Initialize()) {
        return 1;
    }

    uint32_t current_pid = GetCurrentProcessId();
    uintptr_t base = bridge.GetProcessBase(current_pid);
    assert(base != 0 && "Process base must be non-zero");

    uint16_t dos_header = bridge.Read<uint16_t>(base);
    assert(dos_header == IMAGE_DOS_SIGNATURE && "Must read valid DOS signature");

    return 0;
}
#endif
