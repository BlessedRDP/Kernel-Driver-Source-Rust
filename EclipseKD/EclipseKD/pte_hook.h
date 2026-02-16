#pragma once

/*
 * pte_hook.h — PTE-based hook engine, hardened against EAC CuteHook detection.
 *
 * KEY CHANGES from original:
 * ==========================================================================
 *
 * 1. NO MORE PTE SWAPPING IN CallOriginalFunction
 *    The old approach swapped PTE→original PFN, called, swapped back.
 *    Each swap generated a TLB flush (__invlpg) which causes page faults
 *    that EAC's CuteHook system monitors via:
 *      - Detection_CuteHookManuallyMappedPageFaulted
 *      - TelemetryEventType_GuardedRegionStats
 *      - EtwpTraceLastBranchRecord (LBR tracing on #PF)
 *
 *    NEW APPROACH: Build a trampoline that contains the original function's
 *    prologue bytes + a jump to the remainder. The PTE stays permanently
 *    pointed at the hooked page — no swaps, no TLB flushes, no page faults.
 *
 * 2. TRAMPOLINE LIVES IN CODE CAVE (not pool allocation)
 *    Same principle as the spoof stub — we find INT3 padding in a
 *    legitimate module and write the trampoline there. This avoids
 *    the ManuallyMappedWorkerThread detection.
 *
 * 3. PTE MODIFICATION DONE WITH IRQL RAISED
 *    Raising IRQL to DISPATCH_LEVEL during the initial PTE write prevents
 *    preemption-based detection (EAC can't catch mid-swap state).
 *
 * 4. TLB FLUSH IS BROADCAST TO ALL PROCESSORS
 *    Single-core __invlpg leaves other CPUs with stale TLB pointing to
 *    original page. EAC can read from another core and see unhoked code.
 *    We use KeIpiGenericCall to flush across all CPUs atomically.
 */

#include "definitions.h"

// ============================================================================
// PTE hook state
// ============================================================================

typedef struct _PTE_HOOK_STATE {
    PVOID             targetVA;        // Original virtual address of hooked function
    PPTE_ENTRY        pteAddress;      // PTE entry pointer
    ULONG64           originalPfn;     // Original page frame number (unhooked code)
    ULONG64           hookedPfn;       // New page frame number (hooked code with JMP)
    PVOID             newPageVA;       // VA of allocated hooked page
    PHYSICAL_ADDRESS  newPagePA;       // PA of allocated hooked page
    PVOID             trampolineVA;    // VA of trampoline (in code cave)
    BOOLEAN           active;
    UCHAR             originalBytes[32]; // Extended to hold full prologue for trampoline
    ULONG             prologueSize;     // Actual size of relocated prologue
} PTE_HOOK_STATE;

inline PTE_HOOK_STATE g_PteHookState = { 0 };
inline BOOLEAN g_UsePteHook = FALSE;

typedef PPTE_ENTRY(*fn_MiGetPteAddress)(PVOID VirtualAddress);
inline fn_MiGetPteAddress g_MiGetPteAddress = nullptr;

namespace PteHook {

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

    static fn_MiGetPteAddress FindMiGetPteAddress()
    {
        if (!g_KernelBase || !g_KernelSize)
            return nullptr;

        auto pNtHeaders = RtlImageNtHeader(g_KernelBase);
        if (!pNtHeaders)
            return nullptr;

        UCHAR pattern[] = {
            0x48, 0xC1, 0xE9, 0x09,
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x23, 0xC8,
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x03, 0xC1,
            0xC3
        };
        UCHAR mask[] = {
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF,
            0xFF
        };

        auto pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (USHORT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
        {
            PVOID result = FindPattern(
                (PUCHAR)g_KernelBase + pSection->VirtualAddress,
                pSection->Misc.VirtualSize,
                pattern, mask, sizeof(pattern)
            );

            if (result)
                return (fn_MiGetPteAddress)result;
        }

        return nullptr;
    }

    static BOOLEAN SplitLargePage(PVOID targetAddress)
    {
        if (!g_MiGetPteAddress)
            return FALSE;

        ULONG64 va = (ULONG64)targetAddress;
        ULONG64 pdeVA = va & ~0x1FFFFFULL;

        PPTE_ENTRY pde = (PPTE_ENTRY)g_MiGetPteAddress((PVOID)((ULONG64)g_MiGetPteAddress((PVOID)pdeVA)));
        if (!pde || !pde->Present)
            return FALSE;

        if (!pde->LargePage)
            return TRUE;

        PHYSICAL_ADDRESS lowAddr, highAddr, boundary;
        lowAddr.QuadPart  = 0;
        highAddr.QuadPart = 0xFFFFFFFFFFFFFFFF;
        boundary.QuadPart = 0;

        PVOID newPageTable = MmAllocateContiguousMemorySpecifyCache(
            PAGE_SIZE, lowAddr, highAddr, boundary, MmCached
        );

        if (!newPageTable)
            return FALSE;

        PPTE_ENTRY ptes = (PPTE_ENTRY)newPageTable;
        ULONG64 basePhys = pde->PageFrameNumber << 12;

        for (int i = 0; i < 512; i++)
        {
            ptes[i].Value = 0;
            ptes[i].Present      = 1;
            ptes[i].ReadWrite    = pde->ReadWrite;
            ptes[i].UserSupervisor = pde->UserSupervisor;
            ptes[i].Accessed     = 1;
            ptes[i].Dirty        = 1;
            ptes[i].Global       = pde->Global;
            ptes[i].PageFrameNumber = (basePhys >> 12) + i;
        }

        PHYSICAL_ADDRESS newPtPA = MmGetPhysicalAddress(newPageTable);

        PTE_ENTRY newPde;
        newPde.Value = 0;
        newPde.Present        = 1;
        newPde.ReadWrite      = pde->ReadWrite;
        newPde.UserSupervisor = pde->UserSupervisor;
        newPde.Accessed       = 1;
        newPde.LargePage      = 0;
        newPde.PageFrameNumber = newPtPA.QuadPart >> 12;

        InterlockedExchange64((LONG64*)&pde->Value, (LONG64)newPde.Value);

        for (int i = 0; i < 512; i++)
        {
            __invlpg((PVOID)(pdeVA + (ULONG64)i * PAGE_SIZE));
        }

        return TRUE;
    }

    static BOOLEAN WriteReadOnlyMemory(PVOID destination, PVOID source, SIZE_T size)
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

    // ========================================================================
    // Minimal x86-64 instruction length decoder
    //
    // We need to know how many bytes to copy for the trampoline prologue.
    // This handles the common instruction prefixes and encodings found at
    // function starts (push rbx, sub rsp, mov rcx, etc.)
    //
    // Returns the length of the instruction at 'code', or 0 if unknown.
    // ========================================================================

    static ULONG GetInstructionLength(PUCHAR code)
    {
        ULONG i = 0;
        BOOLEAN hasRex = FALSE;
        BOOLEAN has66 = FALSE;
        BOOLEAN hasF0 = FALSE;

        // Skip prefixes
        for (;;)
        {
            UCHAR b = code[i];
            if (b >= 0x40 && b <= 0x4F) { hasRex = TRUE; i++; continue; }
            if (b == 0x66) { has66 = TRUE; i++; continue; }
            if (b == 0xF0 || b == 0xF2 || b == 0xF3) { hasF0 = TRUE; i++; continue; }
            if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
                b == 0x64 || b == 0x65) { i++; continue; }
            break;
        }

        UCHAR op = code[i++];

        // Common single-byte opcodes
        if (op >= 0x50 && op <= 0x5F) return i;          // push/pop reg
        if (op == 0x90) return i;                          // nop
        if (op == 0xC3) return i;                          // ret
        if (op == 0xCC) return i;                          // int3
        if (op == 0xC9) return i;                          // leave

        // MOV reg, imm64 (REX.W + B8+r)
        if (hasRex && op >= 0xB8 && op <= 0xBF) return i + 8;

        // MOV reg, imm32 (no REX.W)
        if (!hasRex && op >= 0xB8 && op <= 0xBF) return i + 4;

        // SUB/ADD/CMP RSP, imm8 (83 /5, /0, /7)
        if (op == 0x83)
        {
            i++; // ModRM
            return i + 1; // imm8
        }

        // SUB/ADD/CMP RSP, imm32 (81 /5, /0, /7)
        if (op == 0x81)
        {
            i++; // ModRM
            return i + 4; // imm32
        }

        // MOV r/m, r or MOV r, r/m (89, 8B)
        if (op == 0x89 || op == 0x8B)
        {
            UCHAR modrm = code[i++];
            UCHAR mod = (modrm >> 6) & 3;
            UCHAR rm  = modrm & 7;

            if (mod == 3) return i; // reg-to-reg
            if (rm == 4) i++; // SIB
            if (mod == 0 && rm == 5) return i + 4; // RIP-relative
            if (mod == 1) return i + 1; // disp8
            if (mod == 2) return i + 4; // disp32
            return i;
        }

        // LEA r, [m] (8D)
        if (op == 0x8D)
        {
            UCHAR modrm = code[i++];
            UCHAR mod = (modrm >> 6) & 3;
            UCHAR rm  = modrm & 7;

            if (mod == 3) return i;
            if (rm == 4) i++;
            if (mod == 0 && rm == 5) return i + 4;
            if (mod == 1) return i + 1;
            if (mod == 2) return i + 4;
            return i;
        }

        // XOR/AND/OR/TEST reg, reg (31, 33, 21, 23, 09, 0B, 85)
        if (op == 0x31 || op == 0x33 || op == 0x21 || op == 0x23 ||
            op == 0x09 || op == 0x0B || op == 0x85)
        {
            UCHAR modrm = code[i++];
            UCHAR mod = (modrm >> 6) & 3;
            UCHAR rm  = modrm & 7;
            if (mod == 3) return i;
            if (rm == 4) i++;
            if (mod == 0 && rm == 5) return i + 4;
            if (mod == 1) return i + 1;
            if (mod == 2) return i + 4;
            return i;
        }

        // CALL/JMP rel32 (E8, E9)
        if (op == 0xE8 || op == 0xE9) return i + 4;

        // JMP rel8 (EB)
        if (op == 0xEB) return i + 1;

        // Short conditional jumps (70-7F)
        if (op >= 0x70 && op <= 0x7F) return i + 1;

        // Two-byte opcodes (0F xx)
        if (op == 0x0F)
        {
            UCHAR op2 = code[i++];
            // Long conditional jumps (0F 80-8F)
            if (op2 >= 0x80 && op2 <= 0x8F) return i + 4;
            // MOVZX, MOVSX (0F B6, B7, BE, BF)
            if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF)
            {
                UCHAR modrm = code[i++];
                UCHAR mod = (modrm >> 6) & 3;
                UCHAR rm  = modrm & 7;
                if (mod == 3) return i;
                if (rm == 4) i++;
                if (mod == 0 && rm == 5) return i + 4;
                if (mod == 1) return i + 1;
                if (mod == 2) return i + 4;
                return i;
            }
        }

        // If we can't decode, return 0 (caller should handle)
        return 0;
    }

    // ========================================================================
    // Build trampoline: original prologue bytes + JMP to (hookTarget + prologueSize)
    //
    // The trampoline is written into a code cave in ntoskrnl so it looks
    // like legitimate kernel code to VA range scanners.
    //
    // Layout:
    //   [original prologue bytes - no RIP-relative fixups needed for simple instrs]
    //   [MOV RAX, continuation_address]
    //   [JMP RAX]
    // ========================================================================

    static PVOID FindCodeCaveForTrampoline(ULONG requiredSize)
    {
        if (!g_KernelBase)
            return nullptr;

        auto pNtHeaders = RtlImageNtHeader(g_KernelBase);
        if (!pNtHeaders)
            return nullptr;

        auto pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (USHORT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
        {
            if (!(pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            // Skip .text, use other executable sections to avoid colliding
            // with the spoof stub's cave search
            if (strncmp((char*)pSection->Name, ".text", 5) == 0)
                continue;

            PUCHAR sectionBase = (PUCHAR)g_KernelBase + pSection->VirtualAddress;
            ULONG  sectionSize = pSection->Misc.VirtualSize;

            if (sectionSize < requiredSize + 16)
                continue;

            for (ULONG offset = sectionSize - requiredSize - 16; offset > sectionSize / 2; offset--)
            {
                BOOLEAN isCave = TRUE;
                for (ULONG j = 0; j < requiredSize; j++)
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

        // Fallback: try .text section too
        pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (USHORT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
        {
            if (!(pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PUCHAR sectionBase = (PUCHAR)g_KernelBase + pSection->VirtualAddress;
            ULONG  sectionSize = pSection->Misc.VirtualSize;

            if (sectionSize < requiredSize + 16)
                continue;

            // Search different region than spoof stub (use first half instead of second)
            for (ULONG offset = 64; offset < sectionSize / 4; offset++)
            {
                BOOLEAN isCave = TRUE;
                for (ULONG j = 0; j < requiredSize; j++)
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

    static BOOLEAN BuildTrampoline(PVOID hookTarget)
    {
        // Determine how many bytes of prologue we need to copy
        // (must be >= 12 bytes since our JMP patch is 12 bytes)
        PUCHAR code = (PUCHAR)hookTarget;
        ULONG totalLen = 0;

        while (totalLen < 12)
        {
            ULONG instrLen = GetInstructionLength(code + totalLen);
            if (instrLen == 0)
                return FALSE; // Unknown instruction, bail
            totalLen += instrLen;
            if (totalLen > 30)
                return FALSE; // Prologue too long, something's wrong
        }

        g_PteHookState.prologueSize = totalLen;
        RtlCopyMemory(g_PteHookState.originalBytes, code, totalLen);

        // Trampoline layout: prologue + MOV RAX, addr + JMP RAX = totalLen + 12
        ULONG trampolineSize = totalLen + 12;

        // Find code cave
        PVOID cave = FindCodeCaveForTrampoline(trampolineSize + 4); // +4 padding
        if (!cave)
            return FALSE;

        // Build trampoline buffer
        UCHAR trampBuf[64] = { 0 };
        RtlCopyMemory(trampBuf, code, totalLen);

        // Continuation address = hookTarget + prologueSize
        PVOID continuation = (PVOID)((ULONG_PTR)hookTarget + totalLen);

        // MOV RAX, continuation; JMP RAX
        trampBuf[totalLen]     = 0x48;
        trampBuf[totalLen + 1] = 0xB8;
        *(PVOID*)(&trampBuf[totalLen + 2]) = continuation;
        trampBuf[totalLen + 10] = 0xFF;
        trampBuf[totalLen + 11] = 0xE0;

        // Write to code cave
        if (!WriteReadOnlyMemory(cave, trampBuf, trampolineSize))
            return FALSE;

        g_PteHookState.trampolineVA = cave;
        return TRUE;
    }

    // ========================================================================
    // Call Original Function via Trampoline
    //
    // NO PTE SWAPPING. The trampoline contains the original prologue and
    // jumps into the middle of the original function (which is on the
    // original physical page, untouched). The hooked PTE stays pointed at
    // our page permanently — no page faults, no TLB flushes, nothing for
    // CuteHook to catch.
    // ========================================================================

    typedef NTSTATUS(*fn_OriginalFunc)(PVOID);

    static NTSTATUS CallOriginalFunction(PVOID argument)
    {
        if (!g_PteHookState.active || !g_PteHookState.trampolineVA)
            return STATUS_UNSUCCESSFUL;

        // Call through the trampoline — completely transparent
        fn_OriginalFunc trampoline = (fn_OriginalFunc)g_PteHookState.trampolineVA;
        return trampoline(argument);
    }

    // ========================================================================
    // IPI TLB flush callback — runs on ALL processors simultaneously
    // ========================================================================

    static ULONG_PTR IpiFlushTlbCallback(ULONG_PTR context)
    {
        __invlpg((PVOID)context);
        return 0;
    }

    static BOOLEAN InstallPteHook(PVOID hookTarget, PVOID handlerAddr)
    {
        g_MiGetPteAddress = FindMiGetPteAddress();
        if (!g_MiGetPteAddress)
            return FALSE;

        if (!SplitLargePage(hookTarget))
            return FALSE;

        PPTE_ENTRY pte = g_MiGetPteAddress(hookTarget);
        if (!pte || !pte->Present)
            return FALSE;

        ULONG64 originalPfn = pte->PageFrameNumber;

        PHYSICAL_ADDRESS lowAddr, highAddr, boundary;
        lowAddr.QuadPart  = 0;
        highAddr.QuadPart = 0xFFFFFFFFFFFFFFFF;
        boundary.QuadPart = 0;

        PVOID newPage = MmAllocateContiguousMemorySpecifyCache(
            PAGE_SIZE, lowAddr, highAddr, boundary, MmCached
        );

        if (!newPage)
            return FALSE;

        // Map original physical page temporarily to copy its contents
        PHYSICAL_ADDRESS origPA;
        origPA.QuadPart = (LONGLONG)(originalPfn << 12);
        PVOID origMapped = MmMapIoSpace(origPA, PAGE_SIZE, MmCached);
        if (!origMapped)
        {
            MmFreeContiguousMemory(newPage);
            return FALSE;
        }

        // Copy original page to the new page
        RtlCopyMemory(newPage, origMapped, PAGE_SIZE);
        MmUnmapIoSpace(origMapped, PAGE_SIZE);

        // Save state early so BuildTrampoline can use originalBytes
        g_PteHookState.targetVA    = hookTarget;
        g_PteHookState.pteAddress  = pte;
        g_PteHookState.originalPfn = originalPfn;

        // Build the trampoline BEFORE modifying the new page
        // (trampoline copies original bytes from hookTarget which is still intact)
        if (!BuildTrampoline(hookTarget))
        {
            MmFreeContiguousMemory(newPage);
            return FALSE;
        }

        // Write JMP handler to the new page at the hook offset
        ULONG hookOffset = (ULONG)((ULONG_PTR)hookTarget & 0xFFF);

        UCHAR trampoline[12] = { 0 };
        trampoline[0] = 0x48;
        trampoline[1] = 0xB8;
        *(PVOID*)(&trampoline[2]) = handlerAddr;
        trampoline[10] = 0xFF;
        trampoline[11] = 0xE0;

        RtlCopyMemory((PUCHAR)newPage + hookOffset, trampoline, sizeof(trampoline));

        PHYSICAL_ADDRESS newPA = MmGetPhysicalAddress(newPage);
        ULONG64 hookedPfn = newPA.QuadPart >> 12;

        // Complete state
        g_PteHookState.hookedPfn   = hookedPfn;
        g_PteHookState.newPageVA   = newPage;
        g_PteHookState.newPagePA   = newPA;

        // Atomically swap PTE to point to hooked page
        // Raise IRQL to prevent preemption during swap
        KIRQL oldIrql;
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

        PTE_ENTRY newPte;
        newPte.Value = pte->Value;
        newPte.PageFrameNumber = hookedPfn;

        InterlockedExchange64((LONG64*)&pte->Value, (LONG64)newPte.Value);

        // Flush TLB on ALL processors via IPI
        KeIpiGenericCall(IpiFlushTlbCallback, (ULONG_PTR)hookTarget);

        KeLowerIrql(oldIrql);

        g_PteHookState.active = TRUE;
        g_UsePteHook = TRUE;

        return TRUE;
    }

    static BOOLEAN RestorePteHook()
    {
        if (!g_PteHookState.active || !g_PteHookState.pteAddress)
            return FALSE;

        KIRQL oldIrql;
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

        PTE_ENTRY restorePte;
        restorePte.Value = g_PteHookState.pteAddress->Value;
        restorePte.PageFrameNumber = g_PteHookState.originalPfn;

        InterlockedExchange64((LONG64*)&g_PteHookState.pteAddress->Value, (LONG64)restorePte.Value);
        KeIpiGenericCall(IpiFlushTlbCallback, (ULONG_PTR)g_PteHookState.targetVA);

        KeLowerIrql(oldIrql);

        g_PteHookState.active = FALSE;
        g_UsePteHook = FALSE;

        if (g_PteHookState.newPageVA)
        {
            MmFreeContiguousMemory(g_PteHookState.newPageVA);
            g_PteHookState.newPageVA = nullptr;
        }

        return TRUE;
    }

    // Inline hook is NOT used for forwarding — only PTE hook supports it
    static BOOLEAN InstallInlineHook(PVOID hookTarget, PVOID handlerAddr)
    {
        UCHAR patch[12] = { 0 };
        patch[0]  = 0x48;
        patch[1]  = 0xB8;
        *(PVOID*)(&patch[2]) = handlerAddr;
        patch[10] = 0xFF;
        patch[11] = 0xE0;

        RtlCopyMemory(g_PteHookState.originalBytes, hookTarget, 12);
        g_PteHookState.targetVA = hookTarget;

        return WriteReadOnlyMemory(hookTarget, patch, sizeof(patch));
    }

} // namespace PteHook
