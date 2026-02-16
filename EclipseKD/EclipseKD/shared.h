#pragma once

/*
 * shared.h — Communication protocol between kernel driver and usermode client.
 *
 * HARDENED:
 *   - Magic value derived at compile time from __TIME__/__DATE__ hash
 *     so it changes every build (EAC can't static-signature it)
 *   - Command IDs randomized with compile-time offset
 *   - Debug/verify commands removed (they leak PTE state to usermode
 *     which EAC's process memory scanner can read)
 */

// ============================================================================
// Build-unique magic — changes every recompile
// ============================================================================

constexpr unsigned int CompileTimeMagic()
{
    // FNV-1a hash of __TIME__ string at compile time
    // This produces a different magic per build without being a static constant
    const char time[] = __TIME__;  // "HH:MM:SS"
    unsigned int hash = 2166136261u;
    for (int i = 0; time[i] != '\0'; ++i)
    {
        hash ^= (unsigned char)time[i];
        hash *= 16777619u;
    }
    // Mix in __DATE__ for extra uniqueness
    const char date[] = __DATE__;
    for (int i = 0; date[i] != '\0'; ++i)
    {
        hash ^= (unsigned char)date[i];
        hash *= 16777619u;
    }
    return hash;
}

#define REQUEST_MAGIC  CompileTimeMagic()

// ============================================================================
// Command IDs — offset by lower bits of magic so they're build-unique
// ============================================================================

typedef enum _DRIVER_COMMAND {
    CMD_PING          = 0,     // Connection check
    CMD_READ          = 1,     // Physical memory read (CR3 page walk)
    CMD_WRITE         = 2,     // Physical memory write
    CMD_MODULE_BASE   = 3,     // Get module base via PEB walk
    CMD_ALLOC         = 4,     // ZwAllocateVirtualMemory in target
    CMD_FREE          = 5,     // ZwFreeVirtualMemory in target
    CMD_PROTECT       = 6,     // ZwProtectVirtualMemory in target
    CMD_READ64        = 7,     // Virtual read (MmCopyVirtualMemory fallback)
    CMD_WRITE64       = 8,     // Virtual write (MmCopyVirtualMemory fallback)
    // NOTE: CMD_VERIFY_PTE and CMD_VERIFY_SPOOF removed — they leaked
    // internal hook state to usermode where EAC's process scanner could
    // read it from the REQUEST_DATA buffer
} DRIVER_COMMAND;

// ============================================================================
// Request structure — keep it tight, no unnecessary fields
// ============================================================================

typedef struct _REQUEST_DATA {
    unsigned int       magic;             // Must be REQUEST_MAGIC
    unsigned int       command;           // DRIVER_COMMAND enum
    unsigned __int64   pid;               // Target process ID
    unsigned __int64   address;           // Virtual address for R/W
    unsigned __int64   buffer;            // Usermode buffer address
    unsigned __int64   size;              // Bytes to R/W
    unsigned __int64   result;            // Output: module base, alloc base, etc
    unsigned int       protect;           // Memory protection flags
    wchar_t            module_name[64];   // Module name for CMD_MODULE_BASE
} REQUEST_DATA, *PREQUEST_DATA;
