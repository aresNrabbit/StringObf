# StringObf / # StringCleaner
### Windows Internals | Process Memory | String Analysis

## Overview

StringCleaner is a C++ Windows utility designed to inspect the virtual memory of running processes and identify strings matching user-provided keywords.

It explores Windows process architecture, virtual memory regions, memory protection, process access, and multithreaded memory analysis.

The application supports process identification through either a process name or PID and searches for matching strings in ANSI and UTF-16LE representations.

## How It Works

### 1. Process Identification
Uses the Windows Toolhelp32 API to locate a running process by executable name or PID.

### 2. Privilege Management
Attempts to enable available Windows privileges required for process access.

### 3. Process Access
Uses `OpenProcess` to obtain a handle to the selected process.

### 4. Memory Enumeration
Uses `VirtualQueryEx` to enumerate committed virtual memory regions.

### 5. Memory Inspection
Uses `ReadProcessMemory` to retrieve accessible memory regions for analysis.

### 6. String Detection
Searches memory contents for user-provided keywords using:
- ANSI string matching
- UTF-16LE string matching
- Case-insensitive comparisons
- Partial keyword matching

### 7. Memory Modification
The implementation attempts to overwrite matching string regions in the target process's virtual memory.

### 8. Result Reporting
Tracks detected matches and reports:
- Total strings found
- Successfully cleared strings
- Failed memory modifications

## Technical Components

| Component | Windows API / Technology |
|---|---|
| Process Enumeration | Toolhelp32 |
| Process Access | `OpenProcess` |
| Privilege Management | `AdjustTokenPrivileges` |
| Thread Management | `SuspendThread`, `ResumeThread` |
| Memory Enumeration | `VirtualQueryEx` |
| Memory Inspection | `ReadProcessMemory` |
| Memory Protection | `VirtualProtectEx` |
| Memory Modification | `WriteProcessMemory` |
| Instruction Cache | `FlushInstructionCache` |
| Parallel Processing | C++ `std::thread` |
| Synchronization | `std::mutex`, `std::atomic` |
| String Processing | ANSI / UTF-16LE |

## Search Capabilities

- Process identification by name or PID
- Multiple keyword input
- Case-insensitive matching
- Partial string matching
- ANSI and UTF-16LE string detection
- Memory-region-based scanning
- Multithreaded analysis

## Technologies

- C++
- Windows API
- Win32 Process Management
- Virtual Memory Architecture
- Windows Security and Privileges
- Multithreading
- Low-Level Memory Operations

## Disclaimer

StringCleaner is an experimental Windows internals research project intended for controlled laboratory environments and authorized testing.

Modifying memory belonging to another process can cause application instability, data corruption, or unexpected termination. Results depend on process permissions, memory protections, and system architecture.
