#pragma once
#include <windows.h>
#include <winnt.h>
#include <intrin.h>
#include <stdint.h>

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#endif
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST    ((NTSTATUS)0xC0000010L)
#endif

typedef short CSHORT;
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _MEMORY_CACHING_TYPE {
    MmNonCached = 0,
    MmCached = 1,
    MmWriteCombined = 2,
    MmHardwareCoherentCached = 3,
    MmNonCachedUnordered = 4,
    MmUSWCCached = 5,
    MmMaximumCacheType = 6
} MEMORY_CACHING_TYPE;

typedef enum _MM_PAGE_PRIORITY {
    LowPagePriority,
    NormalPagePriority = 16,
    HighPagePriority = 32
} MM_PAGE_PRIORITY;

typedef struct _MDL {
    struct _MDL *Next;
    CSHORT Size;
    CSHORT MdlFlags;
    struct _EPROCESS *Process;
    PVOID MappedSystemVa;
    PVOID StartVa;
    ULONG ByteCount;
    ULONG ByteOffset;
} MDL, *PMDL;

typedef struct _PHYSICAL_MEMORY_RANGE {
    PHYSICAL_ADDRESS BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef union _MM_COPY_ADDRESS {
    PVOID            VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
} MM_COPY_ADDRESS, *PMM_COPY_ADDRESS;

#define MM_COPY_MEMORY_PHYSICAL 0x1
#define MM_COPY_MEMORY_VIRTUAL  0x2
#define MM_DONT_ZERO_ALLOCATION 0x00000001
#define MM_ALLOCATE_FULLY_REQUIRED 0x00000002

typedef PVOID PEPROCESS;
typedef PVOID PACCESS_STATE;
typedef PVOID POBJECT_TYPE;
typedef CCHAR KPROCESSOR_MODE;
#define KernelMode 0
#define UserMode 1
#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef struct _DEVICE_OBJECT DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct _DRIVER_OBJECT DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef struct _IRP IRP, *PIRP;
typedef struct _FILE_OBJECT *PFILE_OBJECT;

typedef NTSTATUS (*PDRIVER_DISPATCH)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

struct _DRIVER_OBJECT {
    CSHORT Type;
    CSHORT Size;
    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PVOID DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PVOID FastIoDispatch;
    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
};

struct _DEVICE_OBJECT {
    CSHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    PDRIVER_OBJECT DriverObject;
    struct _DEVICE_OBJECT *NextDevice;
    struct _DEVICE_OBJECT *AttachedDevice;
    PIRP CurrentIrp;
    PVOID Timer;
    ULONG Flags;
    ULONG Characteristics;
    PVOID DoNotUse1;
    PVOID DeviceExtension;
    ULONG DeviceType;
    CCHAR StackSize;
};

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;
    union {
        struct {
            ULONG OutputBufferLength;
            ULONG __padding1;
            ULONG InputBufferLength;
            ULONG __padding2;
            ULONG IoControlCode;
            ULONG __padding3;
            PVOID Type3InputBuffer;
        } DeviceIoControl;
        struct {
            ULONG Length;
            ULONG __padding1;
            ULONG Key;
            ULONG __padding2;
            LARGE_INTEGER ByteOffset;
        } Read;
        struct {
            ULONG Length;
            ULONG __padding1;
            ULONG Key;
            ULONG __padding2;
            LARGE_INTEGER ByteOffset;
        } Write;
        PVOID Parameters[4];
    } Parameters;
    PDEVICE_OBJECT DeviceObject;
    PVOID FileObject;
    PVOID CompletionRoutine;
    PVOID Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

struct _IRP {
    CSHORT Type;
    USHORT Size;
    PMDL MdlAddress;
    ULONG Flags;
    union {
        struct _IRP *MasterIrp;
        LONG IrpCount;
        PVOID SystemBuffer;
    } AssociatedIrp;
    LIST_ENTRY ThreadListEntry;
    IO_STATUS_BLOCK IoStatus;
    KPROCESSOR_MODE RequestorMode;
    BOOLEAN PendingReturned;
    CHAR StackCount;
    CHAR CurrentLocation;
    BOOLEAN Cancel;
    UCHAR CancelIrql;
    CCHAR ApcEnvironment;
    UCHAR AllocationFlags;
    PIO_STATUS_BLOCK UserIosb;
    PVOID UserEvent;
    union {
        struct {
            PVOID UserApcRoutine;
            PVOID UserApcContext;
        } AsynchronousParameters;
        LARGE_INTEGER AllocationSize;
    } Overlay;
    PVOID CancelRoutine;
    PVOID UserBuffer;
    union {
        struct {
            union {
                PVOID DriverContext[4];
            };
            PVOID Thread;
            PCHAR AuxiliaryBuffer;
            struct {
                LIST_ENTRY ListEntry;
                union {
                    struct _IO_STACK_LOCATION *CurrentStackLocation;
                    ULONG PacketType;
                };
            };
            PVOID OriginalFileObject;
        } Overlay;
    } Tail;
};

#define IO_NO_INCREMENT 0

extern "C" {
    extern __declspec(dllimport) PEPROCESS PsInitialSystemProcess;

    void* memcpy(void* dest, const void* src, size_t count);
    void* memset(void* dest, int c, size_t count);

    void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
    NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
    void ExFreePool(PVOID P);
    void ExFreePoolWithTag(PVOID P, ULONG Tag);
    PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRanges(void);
    NTSTATUS MmCopyMemory(PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred);
    PVOID MmMapIoSpace(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType);
    void MmUnmapIoSpace(PVOID BaseAddress, SIZE_T NumberOfBytes);
    PMDL MmAllocatePagesForMdlEx(PHYSICAL_ADDRESS LowAddress, PHYSICAL_ADDRESS HighAddress, PHYSICAL_ADDRESS SkipBytes, SIZE_T TotalBytes, MEMORY_CACHING_TYPE CacheType, ULONG Flags);
    PVOID MmMapLockedPagesSpecifyCache(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority);
    void MmFreePagesFromMdl(PMDL MemoryDescriptorList);
    void IoFreeMdl(PMDL Mdl);
    void IofCompleteRequest(PIRP Irp, CCHAR PriorityBoost);
    #define IoCompleteRequest(Irp, Boost) IofCompleteRequest(Irp, Boost)
    LONG_PTR ObfDereferenceObject(PVOID Object);
    #define ObDereferenceObject(a) ObfDereferenceObject(a)
    NTSTATUS IoGetDeviceObjectPointer(PUNICODE_STRING DeviceName, ACCESS_MASK DesiredAccess, PFILE_OBJECT *FileObject, PDEVICE_OBJECT *DeviceObject);
}

inline PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP Irp) {
    return Irp->Tail.Overlay.CurrentStackLocation;
}
