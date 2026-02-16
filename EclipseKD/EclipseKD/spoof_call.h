#pragma once

/*
 * spoof_call.h — Return address spoofing via ntoskrnl code cave.
 *
 * HARDENED against EAC's RuntimePatchGuardResult + ManuallyMappedWorkerThread:
 *   - Spoof stub is NO LONGER allocated via ExAllocatePool2 with executable flag
 *     (EAC scans all executable non-paged pool for code that doesn't belong to
 *      any loaded module — that's what ManuallyMappedWorkerThread telemetry reports)
 *   - Instead, we find a code cave in a legitimate kernel module (.text padding)
 *     and write the stub there. The code lives inside a signed module's VA range.
 *   - Gadget search unchanged (already finds legit ntoskrnl epilogue).
 */

#include "definitions.h"

// ============================================================================
// Globals
// ============================================================================

inline PVOID g_SpoofGadget = nullptr;
inline PVOID g_SpoofStub   = nullptr;

// ============================================================================
// Typed function pointer types for the stub
// ============================================================================

typedef PVOID(*fn_spoof_1)(PVOID fn, PVOID a1);
typedef PVOID(*fn_spoof_2)(PVOID fn, PVOID a1, PVOID a2);
typedef PVOID(*fn_spoof_3)(PVOID fn, PVOID a1, PVOID a2, PVOID a3);
typedef PVOID(*fn_spoof_4)(PVOID fn, PVOID a1, PVOID a2, PVOID a3, PVOID a4);

// ============================================================================
// Wrapper macros
// ============================================================================

#define SpoofCall1(fn, a1)               ((fn_spoof_1)g_SpoofStub)((PVOID)(fn), (PVOID)(a1))
#define SpoofCall2(fn, a1, a2)           ((fn_spoof_2)g_SpoofStub)((PVOID)(fn), (PVOID)(a1), (PVOID)(a2))
#define SpoofCall3(fn, a1, a2, a3)       ((fn_spoof_3)g_SpoofStub)((PVOID)(fn), (PVOID)(a1), (PVOID)(a2), (PVOID)(a3))
#define SpoofCall4(fn, a1, a2, a3, a4)   ((fn_spoof_4)g_SpoofStub)((PVOID)(fn), (PVOID)(a1), (PVOID)(a2), (PVOID)(a3), (PVOID)(a4))

// ============================================================================
// Pattern scanning helper
// ============================================================================

namespace SpoofCall {

    static PVOID FindPattern(PVOID base, ULONG size, const UCHAR* pattern, const UCHAR* mask, ULONG patternSize)
    {
        PUCHAR pBase = (PUCHAR)base;
        for (ULONG i = 0; i <= size - patternSize; i++)
        {
            BOOLEAN found = TRUE;
            for (ULONG j = 0; j < patternSize; j++)
            {
                if (mask[j] != 0x00 && pBase[i + j] != pattern[j])
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

    static PVOID FindSpoofGadget()
    {
        if (!g_KernelBase || !g_KernelSize)
            return nullptr;

        auto pNtHeaders = RtlImageNtHeader(g_KernelBase);
        if (!pNtHeaders)
            return nullptr;

        auto pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (USHORT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
        {
            if (!(pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            // ADD RSP, 28h; RET — standard epilogue gadget
            UCHAR pattern[] = { 0x48, 0x83, 0xC4, 0x28, 0xC3 };
            UCHAR mask[]    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

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

    // ========================================================================
    // Find a code cave in a kernel module's .text section
    //
    // Code caves are padding bytes (0xCC = INT3) between functions that
    // compilers insert for alignment. We find a run of >= shellcodeSize
    // consecutive 0xCC bytes in an executable section of a legitimate
    // signed kernel module. Writing our stub here means:
    //   1) The VA belongs to a loaded, signed module
    //   2) EAC's module range check sees it as "inside ntoskrnl.exe"
    //   3) No executable pool allocation to scan for
    // ========================================================================

    static PVOID FindCodeCave(PVOID moduleBase, ULONG moduleSize, ULONG caveSize)
    {
        if (!moduleBase)
            return nullptr;

        auto pNtHeaders = RtlImageNtHeader(moduleBase);
        if (!pNtHeaders)
            return nullptr;

        auto pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (USHORT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
        {
            // Only look in executable sections
            if (!(pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PUCHAR sectionBase = (PUCHAR)moduleBase + pSection->VirtualAddress;
            ULONG  sectionSize = pSection->Misc.VirtualSize;

            // Scan backwards from end of section (caves are usually at the end)
            // Skip last 16 bytes to avoid edge issues
            if (sectionSize < caveSize + 16)
                continue;

            for (ULONG offset = sectionSize - caveSize - 16; offset > sectionSize / 2; offset--)
            {
                BOOLEAN isCave = TRUE;
                for (ULONG j = 0; j < caveSize; j++)
                {
                    if (sectionBase[offset + j] != 0xCC)
                    {
                        isCave = FALSE;
                        break;
                    }
                }
                if (isCave)
                    return &sectionBase[offset];
            }
        }

        return nullptr;
    }

    // MDL-based write to read-only kernel memory
    static BOOLEAN WriteToCodeCave(PVOID destination, PVOID source, SIZE_T size)
    {
        PMDL mdl = IoAllocateMdl(destination, (ULONG)size, FALSE, FALSE, nullptr);
        if (!mdl)
            return FALSE;

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            IoFreeMdl(mdl);
            return FALSE;
        }

        PVOID mapped = MmMapLockedPagesSpecifyCache(
            mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority
        );

        if (!mapped)
        {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status))
        {
            MmUnmapLockedPages(mapped, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        RtlCopyMemory(mapped, source, size);

        MmUnmapLockedPages(mapped, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        return TRUE;
    }

    static BOOLEAN InitSpoofStub()
    {
        if (!g_SpoofGadget)
            return FALSE;

        UCHAR shellcode[] = {
            0x41, 0x5B,                                     // pop r11
            0x48, 0x8B, 0xC1,                               // mov rax, rcx (fn)
            0x48, 0x8B, 0xCA,                               // mov rcx, rdx (a1)
            0x49, 0x8B, 0xD0,                               // mov rdx, r8  (a2)
            0x4D, 0x8B, 0xC1,                               // mov r8,  r9  (a3)
            0x4C, 0x8B, 0x4C, 0x24, 0x20,                   // mov r9, [rsp+20h] (a4)
            0x48, 0x83, 0xEC, 0x38,                         // sub rsp, 38h
            0x49, 0xBA,                                      // mov r10, gadget_addr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (8 bytes for gadget address)
            0x4C, 0x89, 0x14, 0x24,                         // mov [rsp], r10 (return addr = gadget)
            0x4C, 0x89, 0x5C, 0x24, 0x30,                   // mov [rsp+30h], r11 (real return)
            0xFF, 0xE0                                       // jmp rax
        };

        *(PVOID*)(&shellcode[25]) = g_SpoofGadget;

        // Find a code cave in ntoskrnl instead of allocating executable pool
        PVOID cave = FindCodeCave(g_KernelBase, g_KernelSize, sizeof(shellcode));
        if (!cave)
        {
            // Fallback: try FLTMGR.SYS (usually has large code caves)
            PVOID fltBase = nullptr;
            ULONG fltSize = 0;

            // Try to get fltmgr base
            ULONG infoSize = 0;
            ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &infoSize);
            if (infoSize)
            {
                PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, infoSize, PoolTags::Tag1);
                if (buf)
                {
                    if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, buf, infoSize, &infoSize)))
                    {
                        auto pMods = (PRTL_PROCESS_MODULES)buf;
                        for (ULONG i = 0; i < pMods->NumberOfModules; i++)
                        {
                            const char* name = (const char*)pMods->Modules[i].FullPathName + pMods->Modules[i].OffsetToFileName;
                            if (_stricmp(name, "FLTMGR.SYS") == 0)
                            {
                                fltBase = pMods->Modules[i].ImageBase;
                                fltSize = pMods->Modules[i].ImageSize;
                                break;
                            }
                        }
                    }
                    ExFreePoolWithTag(buf, PoolTags::Tag1);
                }
            }

            if (fltBase)
                cave = FindCodeCave(fltBase, fltSize, sizeof(shellcode));
        }

        if (!cave)
            return FALSE;

        // Write shellcode into the code cave using MDL
        if (!WriteToCodeCave(cave, shellcode, sizeof(shellcode)))
            return FALSE;

        g_SpoofStub = cave;
        return TRUE;
    }

    static BOOLEAN Init()
    {
        g_SpoofGadget = FindSpoofGadget();
        if (!g_SpoofGadget)
            return FALSE;

        return InitSpoofStub();
    }

} // namespace SpoofCall
