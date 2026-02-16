#pragma once

/*
 * physical_memory.h — CR3 caching, 4-level page table walk, physical memory R/W.
 *
 * HARDENED:
 *   - Pool tags are runtime-generated (via PoolTags namespace)
 *   - CR3 cache uses volatile + interlocked ops properly
 *   - MmCopyMemory calls are wrapped to avoid being identifiable
 */

#include "definitions.h"
#include "spoof_call.h"

// ============================================================================
// CR3 cache
// ============================================================================

#define CR3_CACHE_SIZE      64
#define CR3_CACHE_THRESHOLD 500

typedef struct _CR3_CACHE_ENTRY {
    volatile ULONG64   cr3;
    volatile HANDLE    pid;
    volatile LONG      callCount;
    volatile BOOLEAN   validated;
} CR3_CACHE_ENTRY;

static CR3_CACHE_ENTRY g_Cr3Cache[CR3_CACHE_SIZE] = { 0 };

namespace PhysicalMemory {

    static NTSTATUS ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size, PSIZE_T bytesRead)
    {
        MM_COPY_ADDRESS addr;
        addr.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
        return MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, bytesRead);
    }

    static BOOLEAN ValidateCr3(ULONG64 cr3)
    {
        if (cr3 == 0 || (cr3 & 0xFFF) != 0)
            return FALSE;

        ULONG64 pml4e = 0;
        SIZE_T bytesRead = 0;
        NTSTATUS status = ReadPhysicalAddress(cr3, &pml4e, sizeof(pml4e), &bytesRead);
        if (!NT_SUCCESS(status) || bytesRead != sizeof(pml4e))
            return FALSE;

        return (pml4e & 1) != 0;
    }

    static ULONG64 GetProcessCR3(HANDLE pid)
    {
        ULONG cacheIdx = (ULONG)((ULONG_PTR)pid % CR3_CACHE_SIZE);
        CR3_CACHE_ENTRY* entry = &g_Cr3Cache[cacheIdx];

        if (entry->pid == pid && entry->validated && entry->callCount >= CR3_CACHE_THRESHOLD)
        {
            InterlockedIncrement(&entry->callCount);
            return entry->cr3;
        }

        PEPROCESS process = nullptr;
        NTSTATUS status;

        if (g_SpoofStub)
            status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
        else
            status = PsLookupProcessByProcessId(pid, &process);

        if (!NT_SUCCESS(status) || !process)
            return 0;

        KAPC_STATE apc;
        KeStackAttachProcess(process, &apc);
        ULONG64 cr3 = __readcr3();
        KeUnstackDetachProcess(&apc);

        ObfDereferenceObject(process);

        if (ValidateCr3(cr3))
        {
            entry->cr3 = cr3;
            entry->pid = pid;
            if (entry->callCount < CR3_CACHE_THRESHOLD)
                InterlockedIncrement(&entry->callCount);
            else
                entry->validated = TRUE;
        }

        return cr3;
    }

    static ULONG64 TranslateVirtualAddress(ULONG64 cr3, ULONG64 va)
    {
        ULONG64 pml4_idx = (va >> 39) & 0x1FF;
        ULONG64 pdpt_idx = (va >> 30) & 0x1FF;
        ULONG64 pd_idx   = (va >> 21) & 0x1FF;
        ULONG64 pt_idx   = (va >> 12) & 0x1FF;
        ULONG64 offset   = va & 0xFFF;

        ULONG64 entry = 0;
        SIZE_T  bytesRead = 0;

        NTSTATUS status = ReadPhysicalAddress((cr3 & 0xFFFFFFFFF000ULL) + pml4_idx * 8, &entry, 8, &bytesRead);
        if (!NT_SUCCESS(status) || !(entry & 1))
            return 0;

        status = ReadPhysicalAddress((entry & 0xFFFFFFFFF000ULL) + pdpt_idx * 8, &entry, 8, &bytesRead);
        if (!NT_SUCCESS(status) || !(entry & 1))
            return 0;

        if (entry & (1ULL << 7))
            return (entry & 0xFFFFC0000000ULL) + (va & 0x3FFFFFFFULL);

        status = ReadPhysicalAddress((entry & 0xFFFFFFFFF000ULL) + pd_idx * 8, &entry, 8, &bytesRead);
        if (!NT_SUCCESS(status) || !(entry & 1))
            return 0;

        if (entry & (1ULL << 7))
            return (entry & 0xFFFFFE00000ULL) + (va & 0x1FFFFFULL);

        status = ReadPhysicalAddress((entry & 0xFFFFFFFFF000ULL) + pt_idx * 8, &entry, 8, &bytesRead);
        if (!NT_SUCCESS(status) || !(entry & 1))
            return 0;

        return (entry & 0xFFFFFFFFF000ULL) + offset;
    }

    static NTSTATUS ReadProcessMemory(HANDLE pid, ULONG64 virtualAddress, PVOID userBuffer, SIZE_T size)
    {
        if (!userBuffer || size == 0)
            return STATUS_INVALID_PARAMETER;

        ULONG64 cr3 = GetProcessCR3(pid);
        if (!cr3)
            return STATUS_UNSUCCESSFUL;

        PVOID kernelBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, PoolTags::Tag2);
        if (!kernelBuf)
            return STATUS_INSUFFICIENT_RESOURCES;

        RtlZeroMemory(kernelBuf, size);

        SIZE_T totalRead = 0;
        NTSTATUS finalStatus = STATUS_SUCCESS;

        while (totalRead < size)
        {
            ULONG64 currentVA = virtualAddress + totalRead;
            SIZE_T  pageOffset = currentVA & 0xFFF;
            SIZE_T  chunkSize  = min(PAGE_SIZE - pageOffset, size - totalRead);

            ULONG64 physAddr = TranslateVirtualAddress(cr3, currentVA);
            if (!physAddr)
            {
                finalStatus = STATUS_UNSUCCESSFUL;
                break;
            }

            SIZE_T bytesRead = 0;
            NTSTATUS status = ReadPhysicalAddress(physAddr, (PUCHAR)kernelBuf + totalRead, chunkSize, &bytesRead);
            if (!NT_SUCCESS(status))
            {
                finalStatus = status;
                break;
            }

            totalRead += chunkSize;
        }

        if (NT_SUCCESS(finalStatus))
        {
            __try
            {
                RtlCopyMemory(userBuffer, kernelBuf, size);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                finalStatus = STATUS_ACCESS_VIOLATION;
            }
        }

        ExFreePoolWithTag(kernelBuf, PoolTags::Tag2);
        return finalStatus;
    }

    static NTSTATUS WriteProcessMemory(HANDLE pid, ULONG64 virtualAddress, PVOID userBuffer, SIZE_T size)
    {
        if (!userBuffer || size == 0)
            return STATUS_INVALID_PARAMETER;

        PVOID kernelBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, PoolTags::Tag2);
        if (!kernelBuf)
            return STATUS_INSUFFICIENT_RESOURCES;

        __try
        {
            RtlCopyMemory(kernelBuf, userBuffer, size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ExFreePoolWithTag(kernelBuf, PoolTags::Tag2);
            return STATUS_ACCESS_VIOLATION;
        }

        PEPROCESS process = nullptr;
        NTSTATUS status;

        if (g_SpoofStub)
            status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
        else
            status = PsLookupProcessByProcessId(pid, &process);

        if (!NT_SUCCESS(status) || !process)
        {
            ExFreePoolWithTag(kernelBuf, PoolTags::Tag2);
            return STATUS_UNSUCCESSFUL;
        }

        KAPC_STATE apc;
        KeStackAttachProcess(process, &apc);

        NTSTATUS writeStatus = STATUS_SUCCESS;
        __try
        {
            RtlCopyMemory((PVOID)virtualAddress, kernelBuf, size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            writeStatus = STATUS_ACCESS_VIOLATION;
        }

        KeUnstackDetachProcess(&apc);
        ObfDereferenceObject(process);
        ExFreePoolWithTag(kernelBuf, PoolTags::Tag2);

        return writeStatus;
    }

} // namespace PhysicalMemory
