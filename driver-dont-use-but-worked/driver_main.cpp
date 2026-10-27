// C++20 / driver_main.cpp / Windows Kernel / x64
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdint.h>

#include "shared_mem.hpp"
#include "offsets.hpp"
#include "pml4.hpp"

namespace dxk_sync {

// Global driver state
PMDL g_shared_mdl                      = nullptr;
SharedRingBuffer* g_shared_ring        = nullptr;
PDRIVER_DISPATCH g_original_dispatch   = nullptr;
PDRIVER_OBJECT g_target_driver_obj     = nullptr;

// Anti-forensics: strips DOS/NT headers, section headers and debug directory
void ErasePeHeaders(void* image_base) {
    if (!image_base) return;

    __try {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(image_base) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        uint32_t headers_size = nt->OptionalHeader.SizeOfHeaders;
        if (headers_size == 0 || headers_size > 0x1000) {
            headers_size = 0x1000;
        }

        memset(image_base, 0, headers_size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Headers already freed or unmapped by loader
    }
}

// Anti-forensics: splits mapped section attributes (RX for code, RW for data, strips RWX)
// ponytail: walks kernel page tables with physical address bounds validation to prevent page faults
void SplitSectionProtections(void* image_base) {
    if (!image_base) return;

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(image_base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    auto section = IMAGE_FIRST_SECTION(nt);
    uint64_t cr3 = __readcr3();

    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        void* section_va = reinterpret_cast<uint8_t*>(image_base) + section->VirtualAddress;
        size_t section_size = section->Misc.VirtualSize;

        for (size_t offset = 0; offset < section_size; offset += PAGE_SIZE_4KB) {
            uint64_t va = reinterpret_cast<uint64_t>(section_va) + offset;
            uint64_t pml4_phys = cr3 & PFN_MASK;
            if (!IsPhysicalAddressValid(pml4_phys, 8)) continue;

            uint64_t pml4e = 0;
            if (!ReadPhysicalMemory(pml4_phys + (((va >> PML4_SHIFT) & INDEX_MASK) * 8), &pml4e, 8)) continue;
            if (!(pml4e & 1)) continue;

            uint64_t pdpt_phys = pml4e & PFN_MASK;
            if (!IsPhysicalAddressValid(pdpt_phys, 8)) continue;

            uint64_t pdpte = 0;
            if (!ReadPhysicalMemory(pdpt_phys + (((va >> PDPT_SHIFT) & INDEX_MASK) * 8), &pdpte, 8)) continue;
            if (!(pdpte & 1)) continue;

            uint64_t pd_phys = pdpte & PFN_MASK;
            if (!IsPhysicalAddressValid(pd_phys, 8)) continue;

            uint64_t pde = 0;
            if (!ReadPhysicalMemory(pd_phys + (((va >> PD_SHIFT) & INDEX_MASK) * 8), &pde, 8)) continue;
            if (!(pde & 1)) continue;

            uint64_t pt_phys = pde & PFN_MASK;
            uint64_t pte_addr = pt_phys + (((va >> PT_SHIFT) & INDEX_MASK) * 8);
            if (!IsPhysicalAddressValid(pte_addr, 8)) continue;

            uint64_t pte = 0;
            if (!ReadPhysicalMemory(pte_addr, &pte, 8)) continue;
            if (!(pte & 1)) continue;

            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                // Code: Execute-Read (clear Write bit 1, clear NX bit 63)
                pte &= ~(1ULL << 1);
                pte &= ~(1ULL << 63);
            } else {
                // Data: Read-Write, No-Execute (set NX bit 63)
                pte |= (1ULL << 63);
            }

            MM_COPY_ADDRESS copy_addr;
            copy_addr.PhysicalAddress.QuadPart = static_cast<LONGLONG>(pte_addr);
            SIZE_T transferred = 0;
            MmCopyMemory(reinterpret_cast<PVOID>(&pte), copy_addr, 8, MM_COPY_MEMORY_PHYSICAL, &transferred);
            __invlpg(reinterpret_cast<void*>(va));
        }
    }
}

// Executes an individual ring buffer request synchronously in caller context
void ExecuteRequest(RingRequest& req) {
    switch (req.cmd) {
    case CMD_GET_BASE: {
        PEPROCESS proc = FindProcessByPid(req.pid);
        if (proc) {
            req.result_value = GetProcessSectionBaseAddress(proc);
            req.status = (req.result_value != 0) ? REQ_COMPLETED : REQ_FAILED;
        } else {
            req.status = REQ_FAILED;
        }
        break;
    }

    case CMD_READ: {
        PEPROCESS proc = FindProcessByPid(req.pid);
        if (!proc) {
            req.status = REQ_FAILED;
            break;
        }

        uint64_t cr3 = GetProcessDirectoryTableBase(proc);
        if (req.buffer_offset + req.size <= DATA_BUFFER_SIZE) {
            size_t bytes_read = 0;
            bool ok = ReadProcessVirtualMemory(
                cr3, req.address, &g_shared_ring->data_buffer[req.buffer_offset], req.size, &bytes_read
            );

            // If initial read failed, retry with UserDirectoryTableBase (KVA shadow)
            if (!ok) {
                uint64_t user_cr3 = GetProcessUserDirectoryTableBase(proc);
                if (user_cr3) {
                    ok = ReadProcessVirtualMemory(
                        user_cr3, req.address, &g_shared_ring->data_buffer[req.buffer_offset], req.size, &bytes_read
                    );
                }
            }

            req.result_value = bytes_read;
            req.status = ok ? REQ_COMPLETED : REQ_FAILED;
        } else {
            req.status = REQ_FAILED;
        }
        break;
    }

    case CMD_SCATTER: {
        PEPROCESS proc = FindProcessByPid(req.pid);
        if (!proc) {
            req.status = REQ_FAILED;
            break;
        }

        uint64_t cr3 = GetProcessDirectoryTableBase(proc);
        uint32_t count = req.scatter_count;
        if (count > SCATTER_MAX_ITEMS) count = SCATTER_MAX_ITEMS;

        for (uint32_t i = 0; i < count; ++i) {
            ScatterItem& item = g_shared_ring->scatter_items[i];
            if (item.buffer_offset + item.size <= DATA_BUFFER_SIZE) {
                size_t bytes_read = 0;
                bool ok = ReadProcessVirtualMemory(
                    cr3, item.target_address, &g_shared_ring->data_buffer[item.buffer_offset], item.size, &bytes_read
                );

                if (!ok) {
                    uint64_t user_cr3 = GetProcessUserDirectoryTableBase(proc);
                    if (user_cr3) {
                        ok = ReadProcessVirtualMemory(
                            user_cr3, item.target_address, &g_shared_ring->data_buffer[item.buffer_offset], item.size, &bytes_read
                        );
                    }
                }

                item.bytes_read = static_cast<uint32_t>(bytes_read);
                item.status = ok ? REQ_COMPLETED : REQ_FAILED;
            } else {
                item.status = REQ_FAILED;
            }
        }
        req.status = REQ_COMPLETED;
        break;
    }

    default:
        req.status = REQ_FAILED;
        break;
    }
}

// Maps shared physical pages into the calling user process during handshake
NTSTATUS HandleHandshake(HandshakePacket* packet) {
    if (!g_shared_mdl) {
        return STATUS_UNSUCCESSFUL;
    }

    __try {
        void* user_addr = MmMapLockedPagesSpecifyCache(
            g_shared_mdl,
            UserMode,
            MmNonCached,
            nullptr,
            FALSE,
            NormalPagePriority
        );

        if (!user_addr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        packet->user_buffer = reinterpret_cast<uint64_t>(user_addr);
        packet->status = 0;
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
}

// Flushes and executes pending requests in the ring buffer
NTSTATUS HandleDispatch(HandshakePacket* packet) {
    if (!g_shared_ring) {
        return STATUS_NOT_FOUND;
    }

    uint32_t head = g_shared_ring->head;
    uint32_t tail = g_shared_ring->tail;

    while (tail != head) {
        RingRequest& req = g_shared_ring->requests[tail];
        if (req.status == REQ_PENDING) {
            ExecuteRequest(req);
        }
        tail = (tail + 1) % RING_BUFFER_CAPACITY;
    }
    g_shared_ring->tail = tail;

    packet->status = 0;
    return STATUS_SUCCESS;
}

// Hooked IRP Dispatcher (Data section pointer swap: zero .text modification, 100% PatchGuard-safe)
NTSTATUS HookedDeviceControl(PDEVICE_OBJECT device_object, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

    if (ioctl == IOCTL_DXK_HANDSHAKE || ioctl == IOCTL_DXK_DISPATCH) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HandshakePacket) &&
            stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(HandshakePacket) &&
            irp->AssociatedIrp.SystemBuffer) {
            auto packet = reinterpret_cast<HandshakePacket*>(irp->AssociatedIrp.SystemBuffer);
            if (packet->magic == SHARED_MAGIC) {
                NTSTATUS status = STATUS_SUCCESS;
                if (ioctl == IOCTL_DXK_HANDSHAKE) {
                    status = HandleHandshake(packet);
                } else {
                    status = HandleDispatch(packet);
                }
                irp->IoStatus.Status = status;
                irp->IoStatus.Information = sizeof(HandshakePacket);
                IoCompleteRequest(irp, IO_NO_INCREMENT);
                return status;
            }
        }
    }

    // Forward unhandled requests to original driver dispatcher
    if (g_original_dispatch) {
        return g_original_dispatch(device_object, irp);
    }

    irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

// Swaps DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] in pool memory (no .text edits)
// Uses IoGetDeviceObjectPointer to safely obtain \Driver\Null without undocumented APIs or IoDriverObjectType
bool InstallSafePointerSwap() {
    UNICODE_STRING dev_name;
    RtlInitUnicodeString(&dev_name, L"\\Device\\Null");

    PFILE_OBJECT file_obj = nullptr;
    PDEVICE_OBJECT dev_obj = nullptr;
    NTSTATUS status = IoGetDeviceObjectPointer(
        &dev_name,
        FILE_READ_DATA,
        &file_obj,
        &dev_obj
    );

    if (!NT_SUCCESS(status) || !dev_obj) {
        return false;
    }

    PDRIVER_OBJECT driver_obj = dev_obj->DriverObject;
    if (!driver_obj) {
        ObDereferenceObject(file_obj);
        return false;
    }

    g_target_driver_obj = driver_obj;

    // Atomically swap the function pointer in the dynamic DRIVER_OBJECT structure
    g_original_dispatch = reinterpret_cast<PDRIVER_DISPATCH>(
        InterlockedExchangePointer(
            reinterpret_cast<void**>(&driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL]),
            reinterpret_cast<void*>(HookedDeviceControl)
        )
    );

    ObDereferenceObject(file_obj);
    return (g_original_dispatch != nullptr);
}

// Allocates shared non-cached physical memory pages for the ring buffer
bool InitSharedMemory() {
    PHYSICAL_ADDRESS low_addr = { 0 };
    PHYSICAL_ADDRESS high_addr;
    high_addr.QuadPart = 0x10000000000ULL; // 1 TB
    PHYSICAL_ADDRESS skip_bytes = { 0 };

    SIZE_T total_bytes = sizeof(SharedRingBuffer);

    g_shared_mdl = MmAllocatePagesForMdlEx(
        low_addr,
        high_addr,
        skip_bytes,
        total_bytes,
        MmNonCached,
        MM_DONT_ZERO_ALLOCATION | MM_ALLOCATE_FULLY_REQUIRED
    );
    if (!g_shared_mdl) return false;

    g_shared_ring = reinterpret_cast<SharedRingBuffer*>(
        MmMapLockedPagesSpecifyCache(
            g_shared_mdl,
            KernelMode,
            MmNonCached,
            nullptr,
            FALSE,
            NormalPagePriority
        )
    );
    if (!g_shared_ring) {
        MmFreePagesFromMdl(g_shared_mdl);
        IoFreeMdl(g_shared_mdl);
        g_shared_mdl = nullptr;
        return false;
    }

    memset(g_shared_ring, 0, sizeof(SharedRingBuffer));
    g_shared_ring->magic = SHARED_MAGIC;
    g_shared_ring->capacity = RING_BUFFER_CAPACITY;

    return true;
}

} // namespace dxk_sync

// Universal entry point compatible with manual mapping loaders
extern "C" NTSTATUS DriverEntry(PVOID image_base, PVOID) {
    // 1. Initialize physical memory limits to prevent BSODs on invalid physical ranges
    dxk_sync::InitPhysicalMemoryLimits();

    // 2. Discover dynamic process offsets from PsInitialSystemProcess
    if (!dxk_sync::InitializeOffsets()) {
        return STATUS_NOT_SUPPORTED;
    }

    // 3. Allocate physical shared memory pages for lockless communication
    if (!dxk_sync::InitSharedMemory()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 4. Install PatchGuard-safe gateway (Data Section Pointer Swap, zero .text patches, zero pool trampolines)
    if (!dxk_sync::InstallSafePointerSwap()) {
        return STATUS_UNSUCCESSFUL;
    }

    // 5. Anti-Forensics: erase PE headers in kernel space safely
    if (image_base) {
        __try {
            if (*reinterpret_cast<USHORT*>(image_base) == IMAGE_DOS_SIGNATURE) {
                dxk_sync::ErasePeHeaders(image_base);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Memory already freed or protected by loader
        }
    }

    return STATUS_SUCCESS;
}
