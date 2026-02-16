/*
 * memory.cpp — Virtual memory operations.
 *
 * HARDENED:
 *   - All pool tags use runtime-generated PoolTags namespace
 *   - All ExAllocatePool2 calls use obfuscated tags
 */

#include "definitions.h"
#include "memory.h"
#include "spoof_call.h"

// ============================================================================
// System module helpers
// ============================================================================

PVOID GetSystemModuleBase(const char* moduleName)
{
    ULONG size = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &size);
    if (size == 0)
        return nullptr;

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, PoolTags::Tag1);
    if (!buffer)
        return nullptr;

    status = ZwQuerySystemInformation(SystemModuleInformation, buffer, size, &size);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(buffer, PoolTags::Tag1);
        return nullptr;
    }

    auto pModules = (PRTL_PROCESS_MODULES)buffer;
    PVOID moduleBase = nullptr;

    for (ULONG i = 0; i < pModules->NumberOfModules; i++)
    {
        const char* fullPath = (const char*)pModules->Modules[i].FullPathName;
        const char* fileName = fullPath + pModules->Modules[i].OffsetToFileName;

        if (_stricmp(fileName, moduleName) == 0)
        {
            moduleBase = pModules->Modules[i].ImageBase;

            if (!g_KernelBase && (_stricmp(moduleName, "ntoskrnl.exe") == 0))
            {
                g_KernelBase = moduleBase;
                g_KernelSize = pModules->Modules[i].ImageSize;
            }

            break;
        }
    }

    ExFreePoolWithTag(buffer, PoolTags::Tag1);
    return moduleBase;
}

PVOID GetSystemModuleExport(const char* moduleName, const char* routineName)
{
    PVOID moduleBase = GetSystemModuleBase(moduleName);
    if (!moduleBase)
        return nullptr;

    return RtlFindExportedRoutineByName(moduleBase, routineName);
}

// ============================================================================
// MmCopyVirtualMemory R/W (fallback)
// ============================================================================

NTSTATUS myReadProcessMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size)
{
    PEPROCESS process = nullptr;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status) || !process)
        return STATUS_UNSUCCESSFUL;

    SIZE_T bytes = 0;
    status = MmCopyVirtualMemory(
        process, address,
        PsGetCurrentProcess(), buffer,
        size, KernelMode, &bytes
    );

    ObfDereferenceObject(process);
    return status;
}

NTSTATUS myWriteProcessMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size)
{
    PEPROCESS process = nullptr;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status) || !process)
        return STATUS_UNSUCCESSFUL;

    SIZE_T bytes = 0;
    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(), buffer,
        process, address,
        size, KernelMode, &bytes
    );

    ObfDereferenceObject(process);
    return status;
}

// ============================================================================
// Module base via PEB walk
// ============================================================================

ULONG64 GetProcessModuleBase(HANDLE pid, LPCWSTR moduleName)
{
    PEPROCESS process = nullptr;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status) || !process)
        return 0;

    WCHAR safeModuleName[64] = { 0 };
    __try
    {
        SIZE_T len = wcslen(moduleName);
        if (len >= 64) len = 63;
        RtlCopyMemory(safeModuleName, moduleName, len * sizeof(WCHAR));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ObfDereferenceObject(process);
        return 0;
    }

    PPEB_KM peb = (PPEB_KM)PsGetProcessPeb(process);
    if (!peb)
    {
        ObfDereferenceObject(process);
        return 0;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    ULONG64 moduleBase = 0;

    __try
    {
        if (peb->Ldr && peb->Ldr->InLoadOrderModuleList.Flink)
        {
            PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
            PLIST_ENTRY listEntry = listHead->Flink;

            while (listEntry != listHead)
            {
                PLDR_DATA_TABLE_ENTRY_KM entry = CONTAINING_RECORD(
                    listEntry, LDR_DATA_TABLE_ENTRY_KM, InLoadOrderModuleList
                );

                if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
                {
                    if (_wcsicmp(entry->BaseDllName.Buffer, safeModuleName) == 0)
                    {
                        moduleBase = (ULONG64)entry->DllBase;
                        break;
                    }
                }

                listEntry = listEntry->Flink;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        moduleBase = 0;
    }

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return moduleBase;
}

// ============================================================================
// Virtual memory management
// ============================================================================

NTSTATUS AllocateVirtualMemory(HANDLE pid, PVOID* baseAddress, PSIZE_T regionSize, ULONG protect)
{
    PEPROCESS process = nullptr;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status) || !process)
        return STATUS_UNSUCCESSFUL;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), baseAddress, 0, regionSize,
        MEM_COMMIT | MEM_RESERVE, protect
    );

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return status;
}

NTSTATUS FreeVirtualMemory(HANDLE pid, PVOID baseAddress)
{
    PEPROCESS process = nullptr;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status) || !process)
        return STATUS_UNSUCCESSFUL;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    SIZE_T regionSize = 0;
    status = ZwFreeVirtualMemory(
        ZwCurrentProcess(), &baseAddress, &regionSize, MEM_RELEASE
    );

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return status;
}

NTSTATUS ProtectVirtualMemory(HANDLE pid, PVOID baseAddress, SIZE_T regionSize, ULONG newProtect)
{
    PEPROCESS process = nullptr;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status) || !process)
        return STATUS_UNSUCCESSFUL;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    ULONG oldProtect = 0;
    status = ZwProtectVirtualMemory(
        ZwCurrentProcess(), &baseAddress, &regionSize, newProtect, &oldProtect
    );

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return status;
}
