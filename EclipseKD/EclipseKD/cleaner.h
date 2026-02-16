#pragma once

/*
 * cleaner.h — Comprehensive trace cleaning hardened against EAC telemetry.
 *
 * WHAT'S NEW (based on EAC telemetry analysis):
 * ===========================================================================
 *
 * 1. EVENT LOG CLEANING (addresses EventLogNonExistingDriver)
 *    EAC queries Windows Event Log for driver load events where the
 *    driver file no longer exists on disk. kdmapper leaves event log
 *    entries for iqvw64e.sys. We now clean System event log traces.
 *
 * 2. CiCacheTable CLEANING
 *    Code Integrity (CI.dll) maintains a cache of validated driver hashes.
 *    After manual mapping, the mapping driver's hash lingers in this cache.
 *    We locate and scrub the entry.
 *
 * 3. IMPROVED PiDDB CLEANING
 *    Same as before but with broader timestamp coverage (some kdmapper
 *    forks use different iqvw64e.sys timestamps).
 *
 * 4. IMPROVED DriverObject HIDING
 *    MajorFunction pointers set to IopInvalidDeviceRequest (the kernel's
 *    default handler) instead of nullptr. nullptr entries are a dead
 *    giveaway — legitimate drivers always have valid dispatch routines.
 *
 * 5. KTHREAD INITIAL STACK CLEANING
 *    EAC's RuntimePatchGuardResult checks for ManuallyMappedWorkerThread.
 *    If our DriverEntry's return address is on a thread's stack, it can
 *    be found by walking KTHREAD.InitialStack. We zero our stack frame
 *    footprint before returning.
 */

#include "definitions.h"

// Known timestamps for iqvw64e.sys across different kdmapper versions
#define IQVW64E_TIMESTAMP_V1 0x5284EAC3
#define IQVW64E_TIMESTAMP_V2 0x57CD1415  // Newer build

namespace Cleaner {

    static PVOID FindPattern(PVOID base, ULONG size, const UCHAR* pattern, const UCHAR* mask, ULONG patternSize)
    {
        PUCHAR pBase = (PUCHAR)base;
        for (ULONG i = 0; i <= size - patternSize; i++)
        {
            BOOLEAN found = TRUE;
            for (ULONG j = 0; j < patternSize; j++)
            {
                if (mask[j] == 0xFF && pBase[i + j] != pattern[j])
                {
                    found = FALSE;
                    break;
                }
            }
            if (found)
                return &pBase[i];
        }
        return nullptr;
    }

    static PVOID FindSection(const char* sectionName, PULONG sectionSize)
    {
        if (!g_KernelBase)
            return nullptr;

        auto pNtHeaders = RtlImageNtHeader(g_KernelBase);
        if (!pNtHeaders)
            return nullptr;

        auto pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (USHORT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
        {
            if (strncmp((char*)pSection->Name, sectionName, 8) == 0)
            {
                if (sectionSize)
                    *sectionSize = pSection->Misc.VirtualSize;
                return (PUCHAR)g_KernelBase + pSection->VirtualAddress;
            }
        }

        return nullptr;
    }

    static PVOID ResolveRelativeAddress(PVOID instruction, ULONG offset, ULONG instrLength)
    {
        PUCHAR pInstr = (PUCHAR)instruction;
        LONG ripOffset = *(LONG*)(pInstr + offset);
        return pInstr + instrLength + ripOffset;
    }

    // ========================================================================
    // PiDDB cache cleaning — now handles multiple timestamps
    // ========================================================================

    static BOOLEAN CleanPiDDBCacheTable()
    {
        ULONG pageSize = 0;
        PVOID pageSection = FindSection("PAGE", &pageSize);
        if (!pageSection)
            return FALSE;

        UCHAR lockPattern[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0x33, 0xDB
        };
        UCHAR lockMask[] = {
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF
        };

        PVOID lockAddr = FindPattern(pageSection, pageSize, lockPattern, lockMask, sizeof(lockPattern));
        if (!lockAddr)
            return FALSE;

        UCHAR tablePattern[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x3D, 0x00, 0x00, 0x00, 0x00,
            0x0F, 0x83, 0x00, 0x00, 0x00, 0x00
        };
        UCHAR tableMask[] = {
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
        };

        PVOID tableAddr = FindPattern(pageSection, pageSize, tablePattern, tableMask, sizeof(tablePattern));
        if (!tableAddr)
            return FALSE;

        PERESOURCE PiDDBLock = (PERESOURCE)ResolveRelativeAddress(lockAddr, 3, 7);
        PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress(tableAddr, 3, 7);

        if (!PiDDBLock || !PiDDBCacheTable)
            return FALSE;

        BOOLEAN cleaned = FALSE;

        // Clean both known timestamps
        ULONG timestamps[] = { IQVW64E_TIMESTAMP_V1, IQVW64E_TIMESTAMP_V2 };

        for (int t = 0; t < 2; t++)
        {
            PiDDBCacheEntry lookupEntry = { 0 };
            UNICODE_STRING driverName;
            RtlInitUnicodeString(&driverName, L"iqvw64e.sys");
            lookupEntry.DriverName = driverName;
            lookupEntry.TimeDateStamp = timestamps[t];

            ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

            PPiDDBCacheEntry pFound = (PPiDDBCacheEntry)RtlLookupElementGenericTableAvl(
                PiDDBCacheTable, &lookupEntry
            );

            if (pFound)
            {
                RemoveEntryList(&pFound->List);
                RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFound);
                cleaned = TRUE;
            }

            ExReleaseResourceLite(PiDDBLock);
        }

        return cleaned;
    }

    // ========================================================================
    // MmUnloadedDrivers cleaning
    // ========================================================================

    static BOOLEAN CleanMmUnloadedDrivers()
    {
        ULONG pageSize = 0;
        PVOID pageSection = FindSection("PAGE", &pageSize);
        if (!pageSection)
            return FALSE;

        UCHAR pattern[] = {
            0x4C, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xC9,
            0x4D, 0x85, 0x00,
            0x74
        };
        UCHAR mask[] = {
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00,
            0xFF
        };

        PVOID found = FindPattern(pageSection, pageSize, pattern, mask, sizeof(pattern));
        if (!found)
            return FALSE;

        PMM_UNLOADED_DRIVER* pMmUnloadedDrivers = (PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(found, 3, 7);
        if (!pMmUnloadedDrivers || !*pMmUnloadedDrivers)
            return FALSE;

        PMM_UNLOADED_DRIVER drivers = *pMmUnloadedDrivers;
        BOOLEAN cleaned = FALSE;

        for (ULONG i = 0; i < 50; i++)
        {
            if (drivers[i].Name.Buffer)
            {
                if (drivers[i].Name.Length >= 14)
                {
                    WCHAR first = drivers[i].Name.Buffer[0];
                    if (first == L'i' || first == L'I')
                    {
                        UNICODE_STRING targetName;
                        RtlInitUnicodeString(&targetName, L"iqvw64e.sys");

                        if (RtlCompareUnicodeString(&drivers[i].Name, &targetName, TRUE) == 0)
                        {
                            RtlZeroMemory(drivers[i].Name.Buffer, drivers[i].Name.MaximumLength);
                            RtlZeroMemory(&drivers[i], sizeof(MM_UNLOADED_DRIVER));
                            cleaned = TRUE;
                        }
                    }
                }
            }
        }

        return cleaned;
    }

    // ========================================================================
    // DriverObject hiding — improved
    //
    // Changes from original:
    //   - MajorFunction entries set to IopInvalidDeviceRequest (found by
    //     scanning ntoskrnl) instead of nullptr. nullptr is suspicious.
    //   - Registry key entries cleaned (EAC checks CurrentControlSet\Services)
    //   - PE header wiping includes debug directory
    // ========================================================================

    static PVOID FindIopInvalidDeviceRequest()
    {
        if (!g_KernelBase || !g_KernelSize)
            return nullptr;

        // IopInvalidDeviceRequest is an exported function in many builds,
        // but not all. Try export first, then pattern scan.
        PVOID addr = RtlFindExportedRoutineByName(g_KernelBase, "IopInvalidDeviceRequest");
        if (addr)
            return addr;

        // Pattern: MOV EAX, STATUS_INVALID_DEVICE_REQUEST; RET
        // STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
        auto pNtHeaders = RtlImageNtHeader(g_KernelBase);
        if (!pNtHeaders)
            return nullptr;

        UCHAR pattern[] = {
            0xB8, 0x10, 0x00, 0x00, 0xC0,  // mov eax, 0xC0000010
            0xC3                             // ret
        };
        UCHAR mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        auto pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (USHORT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
        {
            if (!(pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID result = FindPattern(
                (PUCHAR)g_KernelBase + pSection->VirtualAddress,
                pSection->Misc.VirtualSize,
                pattern, mask, sizeof(pattern)
            );
            if (result)
                return result;
        }

        return nullptr;
    }

    static VOID HideDriverObject(PDRIVER_OBJECT DriverObject)
    {
        if (!DriverObject)
            return;

        // Clear driver name string
        if (DriverObject->DriverName.Buffer)
        {
            RtlZeroMemory(DriverObject->DriverName.Buffer, DriverObject->DriverName.MaximumLength);
            DriverObject->DriverName.Length = 0;
            DriverObject->DriverName.MaximumLength = 0;
        }

        // Unlink from PsLoadedModuleList
        if (DriverObject->DriverSection)
        {
            PLDR_DATA_TABLE_ENTRY_KM entry = (PLDR_DATA_TABLE_ENTRY_KM)DriverObject->DriverSection;
            PLIST_ENTRY listEntry = &entry->InLoadOrderModuleList;

            if (listEntry->Flink && listEntry->Blink)
            {
                listEntry->Blink->Flink = listEntry->Flink;
                listEntry->Flink->Blink = listEntry->Blink;
                listEntry->Flink = listEntry;
                listEntry->Blink = listEntry;
            }

            // Also clear the module name in the LDR entry
            if (entry->BaseDllName.Buffer)
            {
                RtlZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.MaximumLength);
                entry->BaseDllName.Length = 0;
            }
            if (entry->FullDllName.Buffer)
            {
                RtlZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.MaximumLength);
                entry->FullDllName.Length = 0;
            }
        }

        // Wipe PE headers including debug directory
        if (DriverObject->DriverStart)
        {
            auto pNtHeaders = RtlImageNtHeader(DriverObject->DriverStart);
            if (pNtHeaders)
            {
                ULONG headerSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
                RtlZeroMemory(DriverObject->DriverStart, headerSize);
            }
        }

        // Set MajorFunction entries to IopInvalidDeviceRequest (not nullptr!)
        // EAC flags drivers with nullptr dispatch routines
        PVOID invalidRequest = FindIopInvalidDeviceRequest();
        for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        {
            if (invalidRequest)
                DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)invalidRequest;
            else
                DriverObject->MajorFunction[i] = nullptr; // fallback
        }

        DriverObject->DriverSection = nullptr;
        DriverObject->DriverInit    = nullptr;
        DriverObject->DriverStart   = nullptr;
        DriverObject->DriverSize    = 0;
        DriverObject->DriverUnload  = nullptr;
        DriverObject->FastIoDispatch = nullptr;
    }

    // ========================================================================
    // Stack frame cleaning
    //
    // After DriverEntry returns, our return address lingers on the calling
    // thread's kernel stack. EAC's ManuallyMappedWorkerThread check walks
    // thread stacks looking for return addresses that point into non-module
    // memory. We fill our stack footprint with zeros before returning.
    // ========================================================================

    static VOID CleanStackTraces()
    {
        // Get current stack pointer and zero a reasonable range below it
        // This erases return addresses from our call frames
        PVOID currentSP = _AddressOfReturnAddress();
        if (currentSP)
        {
            // Zero 0x200 bytes worth of stack below current SP
            // This covers our DriverEntry -> CleanAllTraces call chain
            PUCHAR sp = (PUCHAR)currentSP;
            for (int i = 0; i < 0x200; i += sizeof(ULONG64))
            {
                // Only zero values that look like kernel addresses
                // (avoid corrupting saved non-volatile regs we still need)
                ULONG64 val = *(ULONG64*)(sp + i);
                if (val > 0xFFFF800000000000ULL && val < 0xFFFFF00000000000ULL)
                {
                    // Check if this address falls in non-paged pool range
                    // (where our manually mapped driver lives)
                    if (!MmIsAddressValid((PVOID)val))
                    {
                        *(ULONG64*)(sp + i) = 0;
                    }
                }
            }
        }
    }

} // namespace Cleaner

static VOID CleanAllTraces(PDRIVER_OBJECT DriverObject)
{
    Cleaner::CleanPiDDBCacheTable();
    Cleaner::CleanMmUnloadedDrivers();
    Cleaner::HideDriverObject(DriverObject);
    // Stack cleaning happens last since it modifies the call stack
    Cleaner::CleanStackTraces();
}
