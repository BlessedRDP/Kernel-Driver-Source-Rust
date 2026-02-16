<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows_x64-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Language-C++-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" />
  <img src="https://img.shields.io/badge/Type-Kernel_Driver-critical?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Build-MSVC_x64-6C33AF?style=for-the-badge&logo=visualstudio&logoColor=white" />
</p>

<h1 align="center">🌑 EclipseKD</h1>

<p align="center">
  <b>Hardened Windows x64 kernel-mode driver with stealth-first architecture.</b><br/>
  <sub>PTE hooking · Physical memory R/W · Return address spoofing · Full trace cleaning</sub>
</p>

---

## ⚠️ Important Notice — File Naming

> **Do not assume functionality based on file names alone.**
>
> File and header names in this project are **intentionally misleading** and do not accurately reflect what the code inside actually does. For example, `pte_hook.h` handles far more than just PTE hooking — it includes additional bypass logic and evasion techniques that go well beyond what the name suggests. This applies across the entire codebase. **Read the code itself** to understand the true scope of each module.

---

## 🧬 Overview

**EclipseKD** is a Windows x64 kernel-mode driver designed with a hardened, detection-resistant architecture. It communicates with usermode through a hooked `dxgkrnl.sys` export, supports both physical (CR3 page-walk) and virtual memory operations, and employs multiple layers of anti-detection techniques.

The driver is loaded via **kdmapper** and self-cleans all forensic traces on initialization.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        USERMODE CLIENT                           │
│           Communicates via NtQueryCompositionSurfaceStatistics    │
└──────────────────────────┬───────────────────────────────────────┘
                           │  REQUEST_DATA (build-unique magic)
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                         HOOK LAYER                               │
│    PTE-hooked dxgkrnl export  →  Command dispatcher (hook.cpp)   │
├──────────────────────────────────────────────────────────────────┤
│                       MEMORY ENGINE                              │
│    Physical R/W (CR3 walk)  ·  Virtual R/W (MmCopyVirtualMemory) │
│    Module base (PEB walk)   ·  Alloc / Free / Protect            │
├──────────────────────────────────────────────────────────────────┤
│                     STEALTH SUBSYSTEMS                           │
│    PTE Hook Engine  ·  Return Address Spoofing  ·  Trace Cleaner │
│    Pool Tag Obfuscation  ·  Stack Frame Cleaning                 │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

| File | Description |
|------|-------------|
| `driver.cpp` | Entry point — installs hook, triggers trace cleaning |
| `hook.cpp / hook.h` | PTE hook installation on `dxgkrnl.sys` + command dispatch |
| `memory.cpp / memory.h` | Virtual memory operations, module base resolution |
| `physical_memory.h` | CR3 caching, 4-level page table walk, physical R/W |
| `pte_hook.h` | PTE-based hook engine with hardened evasion techniques |
| `spoof_call.h` | Return address spoofing via ntoskrnl code caves |
| `cleaner.h` | Comprehensive trace cleaning (PiDDB, MmUnloadedDrivers, etc.) |
| `definitions.h` | Kernel structures, undocumented APIs, pool tag obfuscation |
| `shared.h` | Kernel ↔ usermode communication protocol |

---

## 🔑 Key Features

### Communication
- **Hooked dxgkrnl export** — communication channel through `NtQueryCompositionSurfaceStatistics`
- **Build-unique magic** — FNV-1a hash of `__TIME__` and `__DATE__` at compile time; changes every build
- **Randomized command IDs** — compile-time offset prevents static signatures

### Memory Operations
- **Physical memory R/W** — CR3 page table walk with 4-level translation (PML4 → PDPT → PD → PT)
- **CR3 caching** — per-PID cache with validation threshold to reduce kernel API calls
- **Virtual memory R/W** — `MmCopyVirtualMemory` fallback path with spoof call wrapping
- **Module base resolution** — PEB `InLoadOrderModuleList` walk
- **Virtual memory management** — Allocate, Free, and Protect via `Zw*` APIs

### Stealth & Evasion
- **PTE hooking** — page table entry manipulation with IPI-based TLB flush across all cores
- **Trampoline in code cave** — original function prologue relocated to ntoskrnl padding bytes
- **Return address spoofing** — spoof stub written into ntoskrnl code cave (no executable pool)
- **Pool tag obfuscation** — tags derived from `RDTSC` at runtime; never stored as literals
- **Stack frame cleaning** — zeroes DriverEntry return address from calling thread's kernel stack

### Trace Cleaning
- **PiDDB cache** — removes driver entries from the PiDDB cache table
- **MmUnloadedDrivers** — clears entries from the unloaded drivers list
- **DriverObject hiding** — overwrites MajorFunction dispatch with `IopInvalidDeviceRequest`
- **PE header wiping** — includes debug directory cleanup
- **Registry key cleaning** — removes `CurrentControlSet\Services` entries

---

## 🛠️ Building

### Requirements
- **Visual Studio 2022** with C++ Desktop Development workload
- **Windows Driver Kit (WDK)** for your target Windows version
- **Windows SDK** (matching WDK version)

### Build Steps
1. Open `EclipseKD.slnx` in Visual Studio
2. Set configuration to **Release | x64**
3. Build the solution (`Ctrl+Shift+B`)

> The output `.sys` driver binary will be located in `x64/Release/`.

---

## 🚀 Deployment

The driver is designed to be loaded via **[kdmapper](https://github.com/TheCruZ/kdmapper)** using the `iqvw64e.sys` vulnerable driver:

```
kdmapper.exe EclipseKD.sys
```

On load, the driver will:
1. Initialize obfuscated pool tags
2. Resolve kernel base and exports
3. Initialize the spoof call stub in a kernel code cave
4. Install the PTE hook on the target `dxgkrnl.sys` export
5. Build the trampoline for original function forwarding
6. Clean all forensic traces (PiDDB, MmUnloadedDrivers, DriverObject, stack)

---

## 📡 Supported Commands

| Command | ID | Description |
|---------|----|-------------|
| `CMD_PING` | `0` | Connection health check |
| `CMD_READ` | `1` | Physical memory read via CR3 page walk |
| `CMD_WRITE` | `2` | Physical memory write |
| `CMD_MODULE_BASE` | `3` | Get module base from target process PEB |
| `CMD_ALLOC` | `4` | Allocate virtual memory in target process |
| `CMD_FREE` | `5` | Free virtual memory in target process |
| `CMD_PROTECT` | `6` | Change memory protection in target process |
| `CMD_READ64` | `7` | Virtual read via `MmCopyVirtualMemory` |
| `CMD_WRITE64` | `8` | Virtual write via `MmCopyVirtualMemory` |

---

## 📋 Usermode Integration

To communicate with the driver from usermode, call `NtQueryCompositionSurfaceStatistics` with a `REQUEST_DATA` struct:

```cpp
REQUEST_DATA req = {};
req.magic   = REQUEST_MAGIC;   // Must match current build's magic
req.command = CMD_READ;
req.pid     = targetPid;
req.address = targetAddress;
req.buffer  = (ULONG64)localBuffer;
req.size    = readSize;

NtQueryCompositionSurfaceStatistics(&req);
```

> **Note:** The `REQUEST_MAGIC` value changes on every recompile. Both the driver and usermode client must be built from the same source at the same time.

---

## ⚠️ Disclaimer

This project is provided for **educational and research purposes only**. The author is not responsible for any misuse. Use at your own risk and in compliance with all applicable laws and terms of service.

---

<p align="center">
  <sub>EclipseKD — built different.</sub>
</p>
