/*
 * driver.cpp — DriverEntry for EclipseKD.
 *
 * Called by kdmapper after loading via iqvw64e.sys.
 * Installs the dxgkrnl hook, then cleans all traces.
 *
 * HARDENED:
 *   - PoolTags initialized before any allocations
 *   - Trace cleaning expanded (PiDDB, MmUnloadedDrivers, DriverObject, stack)
 *   - No static strings or debug output left in binary
 */

#include "driver.h"
#include "hook.h"
#include "cleaner.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // 1. Install dxgkrnl hook for communication
    //    This handles: kernel base resolution, pool tag init,
    //    spoof call init, PTE hook installation + trampoline build
    if (!Hook::Install((PVOID)&Hook::Handler))
        return STATUS_UNSUCCESSFUL;

    // 2. Clean ALL traces and hide driver
    //    Order: hook first (needs exports), then clean (removes traces)
    //    CleanAllTraces now handles: PiDDB, MmUnloadedDrivers,
    //    DriverObject (with IopInvalidDeviceRequest), and stack cleaning
    CleanAllTraces(DriverObject);

    return STATUS_SUCCESS;
}
