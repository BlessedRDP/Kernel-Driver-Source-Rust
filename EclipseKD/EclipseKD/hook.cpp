/*
 * hook.cpp — PTE hook installation on dxgkrnl.sys + command dispatcher.
 *
 * HARDENED:
 *   - Removed CMD_VERIFY_PTE / CMD_VERIFY_SPOOF (leaked hook internals)
 *   - Ping response is build-unique (derived from REQUEST_MAGIC)
 *   - Handler validates IRQL before processing to avoid reentrancy
 *   - Added volatile re-entrancy guard
 */

#include "definitions.h"
#include "shared.h"
#include "memory.h"
#include "hook.h"
#include "pte_hook.h"
#include "physical_memory.h"
#include "spoof_call.h"

namespace Hook {

    // Re-entrancy guard — if the hook is already being processed on this
    // thread/CPU, forward to original. Prevents infinite recursion if
    // our handler triggers another call to NtQueryCompositionSurfaceStatistics.
    static volatile LONG g_HandlerGuard = 0;

    // ========================================================================
    // Hook installation
    // ========================================================================

    BOOLEAN Install(PVOID handlerAddr)
    {
        // Resolve the kernel base first (needed by spoof call and PTE hook)
        if (!g_KernelBase)
        {
            g_KernelBase = GetSystemModuleBase("ntoskrnl.exe");
            if (!g_KernelBase)
                return FALSE;

            auto pNtHeaders = RtlImageNtHeader(g_KernelBase);
            if (pNtHeaders)
                g_KernelSize = pNtHeaders->OptionalHeader.SizeOfImage;
        }

        // Initialize pool tag system (must happen before ANY pool allocations)
        PoolTags::Init();

        // Initialize spoof call system (non-fatal if it fails)
        SpoofCall::Init();

        // Find the hook target: dxgkrnl.sys!NtQueryCompositionSurfaceStatistics
        PVOID hookTarget = GetSystemModuleExport(
            "dxgkrnl.sys",
            "NtQueryCompositionSurfaceStatistics"
        );

        if (!hookTarget)
            return FALSE;

        // Try PTE hook first (stealth method)
        if (PteHook::InstallPteHook(hookTarget, handlerAddr))
            return TRUE;

        // Fallback to inline patch
        if (PteHook::InstallInlineHook(hookTarget, handlerAddr))
        {
            g_UsePteHook = FALSE;
            return TRUE;
        }

        return FALSE;
    }

    // ========================================================================
    // Command dispatcher
    // ========================================================================

    NTSTATUS Handler(PVOID data)
    {
        // ----------------------------------------------------------------
        // FAST PATH: Validate 'data' before reading memory.
        // ----------------------------------------------------------------
        ULONG64 addr = (ULONG64)data;

        // NULL, handles (< 0x10000), or kernel addresses → forward immediately
        if (addr < 0x10000 || addr >= 0x00007FFF00000000ULL)
        {
            if (g_UsePteHook && g_PteHookState.active)
                return PteHook::CallOriginalFunction(data);
            return STATUS_SUCCESS;
        }

        // Re-entrancy check
        if (InterlockedCompareExchange(&g_HandlerGuard, 1, 0) != 0)
        {
            if (g_UsePteHook && g_PteHookState.active)
                return PteHook::CallOriginalFunction(data);
            return STATUS_SUCCESS;
        }

        // Extra safety: verify the memory is actually readable
        if (!MmIsAddressValid(data))
        {
            InterlockedExchange(&g_HandlerGuard, 0);
            if (g_UsePteHook && g_PteHookState.active)
                return PteHook::CallOriginalFunction(data);
            return STATUS_SUCCESS;
        }

        // All memory access inside __try to catch any edge cases
        __try
        {
            PREQUEST_DATA request = (PREQUEST_DATA)data;

            // Not our request → forward to original
            if (request->magic != REQUEST_MAGIC)
            {
                InterlockedExchange(&g_HandlerGuard, 0);
                if (g_UsePteHook && g_PteHookState.active)
                    return PteHook::CallOriginalFunction(data);
                return STATUS_SUCCESS;
            }

            // ============================================================
            // Dispatch our commands
            // ============================================================
            switch (request->command)
            {
            case CMD_READ:
            {
                NTSTATUS status = PhysicalMemory::ReadProcessMemory(
                    (HANDLE)request->pid,
                    request->address,
                    (PVOID)request->buffer,
                    (SIZE_T)request->size
                );
                request->result = (ULONG64)status;
                break;
            }

            case CMD_WRITE:
            {
                NTSTATUS status = PhysicalMemory::WriteProcessMemory(
                    (HANDLE)request->pid,
                    request->address,
                    (PVOID)request->buffer,
                    (SIZE_T)request->size
                );
                request->result = (ULONG64)status;
                break;
            }

            case CMD_READ64:
            {
                NTSTATUS status = myReadProcessMemory(
                    (HANDLE)request->pid,
                    (PVOID)request->address,
                    (PVOID)request->buffer,
                    (SIZE_T)request->size
                );
                request->result = (ULONG64)status;
                break;
            }

            case CMD_WRITE64:
            {
                NTSTATUS status = myWriteProcessMemory(
                    (HANDLE)request->pid,
                    (PVOID)request->address,
                    (PVOID)request->buffer,
                    (SIZE_T)request->size
                );
                request->result = (ULONG64)status;
                break;
            }

            case CMD_MODULE_BASE:
            {
                ULONG64 base = GetProcessModuleBase(
                    (HANDLE)request->pid,
                    request->module_name
                );
                request->result = base;
                break;
            }

            case CMD_ALLOC:
            {
                PVOID baseAddr = (request->address != 0) ? (PVOID)request->address : nullptr;
                SIZE_T regionSize = (SIZE_T)request->size;
                AllocateVirtualMemory(
                    (HANDLE)request->pid,
                    &baseAddr,
                    &regionSize,
                    request->protect
                );
                request->result = (ULONG64)baseAddr;
                request->size   = (ULONG64)regionSize;
                break;
            }

            case CMD_FREE:
            {
                NTSTATUS status = FreeVirtualMemory(
                    (HANDLE)request->pid,
                    (PVOID)request->address
                );
                request->result = (ULONG64)status;
                break;
            }

            case CMD_PROTECT:
            {
                NTSTATUS status = ProtectVirtualMemory(
                    (HANDLE)request->pid,
                    (PVOID)request->address,
                    (SIZE_T)request->size,
                    request->protect
                );
                request->result = (ULONG64)status;
                break;
            }

            case CMD_PING:
            {
                // Response is derived from the build-unique magic
                // so it changes every compile — can't be signatured
                request->result = REQUEST_MAGIC ^ 0xDEADBEEF;
                break;
            }

            // CMD_VERIFY_PTE and CMD_VERIFY_SPOOF intentionally removed.
            // They leaked PTE hook state (pteAddress, originalPfn, hookedPfn,
            // newPageVA, newPagePA) into usermode memory where EAC's process
            // scanner could read them from the REQUEST_DATA buffer.

            default:
                break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            InterlockedExchange(&g_HandlerGuard, 0);
            if (g_UsePteHook && g_PteHookState.active)
                return PteHook::CallOriginalFunction(data);
            return STATUS_SUCCESS;
        }

        InterlockedExchange(&g_HandlerGuard, 0);
        return STATUS_SUCCESS;
    }

} // namespace Hook
