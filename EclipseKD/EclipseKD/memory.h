#pragma once

/*
 * memory.h — Prototypes for memory.cpp operations.
 */

#include "definitions.h"

// System module helpers
PVOID  GetSystemModuleBase(const char* moduleName);
PVOID  GetSystemModuleExport(const char* moduleName, const char* routineName);

// MmCopyVirtualMemory R/W (fallback methods)
NTSTATUS myReadProcessMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size);
NTSTATUS myWriteProcessMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size);

// Module base via PEB walk
ULONG64 GetProcessModuleBase(HANDLE pid, LPCWSTR moduleName);

// Virtual memory management
NTSTATUS AllocateVirtualMemory(HANDLE pid, PVOID* baseAddress, PSIZE_T regionSize, ULONG protect);
NTSTATUS FreeVirtualMemory(HANDLE pid, PVOID baseAddress);
NTSTATUS ProtectVirtualMemory(HANDLE pid, PVOID baseAddress, SIZE_T regionSize, ULONG newProtect);
