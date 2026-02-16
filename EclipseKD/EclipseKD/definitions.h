#pragma once

/*
 * definitions.h — Kernel includes, undocumented API declarations, structures.
 *
 * Hardened against EAC telemetry fingerprinting:
 *   - Pool tags are runtime-derived, not static constants
 *   - No hardcoded magic values in data section
 *   - Additional undocumented APIs for trace cleaning
 */

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <ntstrsafe.h>
#pragma warning(pop)

// ============================================================================
// Pool tag obfuscation — tags are computed at init, never stored as literals
// EAC scans .rdata/.data for known pool tags like 'mEmK', 'fpSK', etc.
// ============================================================================

namespace PoolTags {
    // Seeded from TSC at driver init, used for all pool allocations
    inline volatile ULONG Tag1 = 0;  // general purpose
    inline volatile ULONG Tag2 = 0;  // physical memory ops
    inline volatile ULONG Tag3 = 0;  // spoof stub
    inline volatile ULONG Tag4 = 0;  // PTE hook

    static __forceinline void Init()
    {
        // Derive tags from RDTSC — different every load, nothing to signature
        ULONG64 tsc = __rdtsc();
        ULONG seed = (ULONG)(tsc ^ (tsc >> 32));

        // Mix bits — ensure tags look like plausible Windows pool tags
        // (uppercase ASCII range 0x41-0x5A mixed with lowercase)
        auto MakeTag = [](ULONG s) -> ULONG {
            UCHAR c[4];
            c[0] = 'A' + (UCHAR)((s >> 0)  % 26);
            c[1] = 'a' + (UCHAR)((s >> 5)  % 26);
            c[2] = 'A' + (UCHAR)((s >> 10) % 26);
            c[3] = 'a' + (UCHAR)((s >> 15) % 26);
            return *(ULONG*)c;
        };

        Tag1 = MakeTag(seed);
        Tag2 = MakeTag(seed * 2654435761u); // Knuth multiplicative hash
        Tag3 = MakeTag(seed * 2246822519u);
        Tag4 = MakeTag(seed * 3266489917u);
    }
}

// ============================================================================
// Undocumented kernel API declarations
// ============================================================================

extern "C" {

    // PEB access
    typedef struct _PEB_KM* PPEB_KM;
    PPEB_KM PsGetProcessPeb(IN PEPROCESS Process);

    // Cross-process memory copy
    NTSTATUS MmCopyVirtualMemory(
        PEPROCESS  SourceProcess,
        PVOID      SourceAddress,
        PEPROCESS  TargetProcess,
        PVOID      TargetAddress,
        SIZE_T     BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T    ReturnSize
    );

    // Virtual memory protection
    NTSTATUS ZwProtectVirtualMemory(
        HANDLE     ProcessHandle,
        PVOID*     BaseAddress,
        PSIZE_T    ProtectSize,
        ULONG      NewProtect,
        PULONG     OldProtect
    );

    // PE header parsing
    PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID Base);

    // Export resolution
    PVOID RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);

    // System information query
    NTSTATUS ZwQuerySystemInformation(
        ULONG  SystemInformationClass,
        PVOID  SystemInformation,
        ULONG  SystemInformationLength,
        PULONG ReturnLength
    );

    // Event log cleaning — EAC's EventLogNonExistingDriver checks these
    NTSTATUS ZwOpenKey(
        PHANDLE            KeyHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS ZwDeleteValueKey(
        HANDLE          KeyHandle,
        PUNICODE_STRING ValueName
    );

    NTSTATUS ZwEnumerateKey(
        HANDLE                KeyHandle,
        ULONG                 Index,
        KEY_INFORMATION_CLASS KeyInformationClass,
        PVOID                 KeyInformation,
        ULONG                 Length,
        PULONG                ResultLength
    );
}

// ============================================================================
// System information class constants
// ============================================================================

#define SystemModuleInformation 11

// ============================================================================
// PEB / LDR structures for module enumeration
// ============================================================================

typedef struct _PEB_LDR_DATA_KM {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_KM, *PPEB_LDR_DATA_KM;

typedef struct _PEB_KM {
    UCHAR  Reserved1[2];
    UCHAR  BeingDebugged;
    UCHAR  Reserved2[1];
    PVOID  Reserved3[2];
    PPEB_LDR_DATA_KM Ldr;
} PEB_KM;

typedef struct _LDR_DATA_TABLE_ENTRY_KM {
    LIST_ENTRY     InLoadOrderModuleList;
    LIST_ENTRY     InMemoryOrderModuleList;
    LIST_ENTRY     InInitializationOrderModuleList;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_KM, *PLDR_DATA_TABLE_ENTRY_KM;

// ============================================================================
// PiDDB structures for trace cleaning
// ============================================================================

typedef struct _PiDDBCacheEntry {
    LIST_ENTRY      List;
    UNICODE_STRING  DriverName;
    ULONG           TimeDateStamp;
    NTSTATUS        LoadStatus;
    char            _pad[16];
} PiDDBCacheEntry, *PPiDDBCacheEntry;

// ============================================================================
// System module enumeration structures
// ============================================================================

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    ULONG  Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// ============================================================================
// MmUnloadedDrivers structures
// ============================================================================

typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID          ModuleStart;
    PVOID          ModuleEnd;
    LARGE_INTEGER  UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

// ============================================================================
// PTE entry structure
// ============================================================================

#pragma warning(push)
#pragma warning(disable: 4201)
typedef union _PTE_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;
        ULONG64 ReadWrite : 1;
        ULONG64 UserSupervisor : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 LargePage : 1;
        ULONG64 Global : 1;
        ULONG64 CopyOnWrite : 1;
        ULONG64 Prototype : 1;
        ULONG64 WriteSoftware : 1;
        ULONG64 PageFrameNumber : 36;
        ULONG64 ReservedHardware : 4;
        ULONG64 ReservedSoftware : 11;
        ULONG64 NoExecute : 1;
    };
} PTE_ENTRY, *PPTE_ENTRY;
#pragma warning(pop)

// ============================================================================
// Kernel base global (resolved at init)
// ============================================================================

inline PVOID g_KernelBase = nullptr;
inline ULONG g_KernelSize = 0;
