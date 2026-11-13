#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mutex>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <chrono>

//———————————————————— Utilities ————————————————————

std::string ptr_to_hex(uintptr_t ptr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << ptr;
    return oss.str();
}

bool SetPrivilege(HANDLE hToken, const char* name) {
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid))
        return false;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    return GetLastError() == ERROR_SUCCESS;
}

void EnableAllDebugPrivileges() {
    HANDLE ht;
    if (OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &ht))
    {
        const char* privs[5];
        privs[0] = "SeDebugPrivilege";
        privs[1] = "SeBackupPrivilege";
        privs[2] = "SeRestorePrivilege";
        privs[3] = "SeTakeOwnershipPrivilege";
        privs[4] = "SeSecurityPrivilege";

        for (int i = 0; i < 5; i++) {
            SetPrivilege(ht, privs[i]);
        }
        CloseHandle(ht);
    }
}

std::vector<HANDLE> SuspendAllThreads(DWORD pid) {
    std::vector<HANDLE> threads;
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hs == INVALID_HANDLE_VALUE) return threads;
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hs, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hT = OpenThread(THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (hT) {
                    SuspendThread(hT);
                    threads.push_back(hT);
                }
            }
        } while (Thread32Next(hs, &te));
    }
    CloseHandle(hs);
    return threads;
}

void ResumeAllThreads(const std::vector<HANDLE>& threads) {
    for (size_t i = 0; i < threads.size(); i++) {
        ResumeThread(threads[i]);
        CloseHandle(threads[i]);
    }
}

bool TryReadRegion(HANDLE hProc, LPCVOID base,
    std::vector<char>& buf, SIZE_T& outRead)
{
    if (ReadProcessMemory(hProc, base, buf.data(),
        buf.size(), &outRead))
        return true;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, base, &mbi, sizeof(mbi))
        != sizeof(mbi)) return false;
    DWORD oldProt;
    if (!VirtualProtectEx(hProc,
        mbi.BaseAddress,
        mbi.RegionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProt))
        return false;
    bool ok = ReadProcessMemory(hProc, base,
        buf.data(),
        buf.size(),
        &outRead);
    VirtualProtectEx(hProc,
        mbi.BaseAddress,
        mbi.RegionSize,
        oldProt,
        &oldProt);
    return ok;
}

bool TryZeroMemory(HANDLE hProc, uintptr_t addr, size_t len,
    std::ostringstream& log, bool& success)
{
    std::vector<char> zeros(len, 0);
    SIZE_T written = 0;
    if (WriteProcessMemory(hProc, (LPVOID)addr,
        zeros.data(), len, &written))
    {
        success = true;
        FlushInstructionCache(hProc,
            (LPCVOID)addr,
            len);
        return true;
    }
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc,
        (LPCVOID)addr,
        &mbi, sizeof(mbi))
        != sizeof(mbi))
    {
        success = false;
        return false;
    }
    DWORD oldProt;
    if (!VirtualProtectEx(hProc,
        mbi.BaseAddress,
        mbi.RegionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProt))
    {
        success = false;
        return false;
    }
    bool ok = WriteProcessMemory(hProc,
        (LPVOID)addr,
        zeros.data(),
        len,
        &written);
    FlushInstructionCache(hProc, (LPCVOID)addr, len);
    VirtualProtectEx(hProc,
        mbi.BaseAddress,
        mbi.RegionSize,
        oldProt,
        &oldProt);
    success = ok;
    return ok;
}

bool SafeZeroNoSuspend(HANDLE hProc,
    uintptr_t addr,
    size_t len,
    std::ostringstream& log,
    bool& success)
{
    std::vector<char> zeros(len, 0);
    SIZE_T written = 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc,
        (LPCVOID)addr,
        &mbi, sizeof(mbi))
        != sizeof(mbi))
    {
        success = false;
        return false;
    }
    DWORD oldProt;
    if (!VirtualProtectEx(hProc,
        mbi.BaseAddress,
        mbi.RegionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProt))
    {
        success = false;
        return false;
    }
    if (WriteProcessMemory(hProc,
        (LPVOID)addr,
        zeros.data(),
        len,
        &written))
    {
        success = true;
    }
    else {
        success = false;
    }
    FlushInstructionCache(hProc,
        (LPCVOID)addr,
        len);
    VirtualProtectEx(hProc,
        mbi.BaseAddress,
        mbi.RegionSize,
        oldProt,
        &oldProt);
    return success;
}

//———————————————————— Process Detection ————————————————————

DWORD GetProcessIdByName(const std::string& name) {
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hs == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hs, &pe)) {
        do {
            std::string procName(pe.szExeFile);
            std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
            std::string searchName = name;
            std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::tolower);

            if (procName == searchName || procName.find(searchName) != std::string::npos) {
                CloseHandle(hs);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hs, &pe));
    }
    CloseHandle(hs);
    return 0;
}

std::string GetProcessName(DWORD pid) {
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hs == INVALID_HANDLE_VALUE) return "";

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hs, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                std::string name(pe.szExeFile);
                CloseHandle(hs);
                return name;
            }
        } while (Process32Next(hs, &pe));
    }
    CloseHandle(hs);
    return "";
}

//———————————————————— Advanced deletion ————————————————————

std::string DeleteAdvanced(DWORD pid,
    const std::vector<std::string>& keywords,
    bool& matchesFound)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,
        FALSE, pid);
    if (!hProc)
        return "ERROR: Cannot open process. Try Admin.\r\n";

    EnableAllDebugPrivileges();
    std::vector<HANDLE> suspended = SuspendAllThreads(pid);

    std::vector<MEMORY_BASIC_INFORMATION> regions;
    SYSTEM_INFO sys; GetSystemInfo(&sys);
    uintptr_t addr = (uintptr_t)sys.lpMinimumApplicationAddress;
    uintptr_t max = (uintptr_t)sys.lpMaximumApplicationAddress;
    while (addr < max) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProc,
            (LPCVOID)addr,
            &mbi, sizeof(mbi))
            != sizeof(mbi))
            break;
        if (mbi.State == MEM_COMMIT)
            regions.push_back(mbi);
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    std::ostringstream log;
    std::mutex      mtx;
    std::atomic<size_t> idx(0);
    std::atomic<size_t> total(0);
    std::atomic<size_t> cleared(0);
    std::atomic<size_t> failed(0);
    size_t n = regions.size();
    unsigned workers = std::thread::hardware_concurrency();
    if (!workers) workers = 4;

    auto worker = [&]() {
        while (true) {
            size_t i = idx.fetch_add(1);
            if (i >= n) break;
            MEMORY_BASIC_INFORMATION& mbi = regions[i];

            std::vector<char> buf(mbi.RegionSize);
            SIZE_T rb = 0;
            if (!TryReadRegion(hProc,
                mbi.BaseAddress,
                buf, rb))
                continue;

            // Convert buffer to lowercase for case-insensitive search
            std::string bufLower(buf.begin(), buf.end());
            std::transform(bufLower.begin(), bufLower.end(), bufLower.begin(), ::tolower);

            // ANSI - Search for partial matches
            for (size_t off = 0; off + 1 < rb; ++off) {
                for (size_t kIdx = 0; kIdx < keywords.size(); kIdx++) {
                    const std::string& keyword = keywords[kIdx];
                    std::string keywordLower = keyword;
                    std::transform(keywordLower.begin(), keywordLower.end(), keywordLower.begin(), ::tolower);

                    size_t len = keywordLower.size();
                    if (!len || off + len > rb) continue;

                    // Check if keyword exists at this position (case-insensitive)
                    if (bufLower.compare(off, len, keywordLower) == 0) {
                        // Find the full string containing this keyword
                        size_t start = off;
                        size_t end = off + len;

                        // Expand backward to find start of the string
                        while (start > 0 && (isalnum(buf[start - 1]) || buf[start - 1] == '_' || buf[start - 1] == '-' || buf[start - 1] == '.')) {
                            start--;
                        }

                        // Expand forward to find end of the string
                        while (end < rb && (isalnum(buf[end]) || buf[end] == '_' || buf[end] == '-' || buf[end] == '.')) {
                            end++;
                        }

                        // Extract the full string
                        std::string fullString(buf.begin() + start, buf.begin() + end);
                        size_t fullLen = fullString.size();

                        if (fullLen > 0) {
                            uintptr_t f = (uintptr_t)mbi.BaseAddress + start;

                            bool success = false;
                            // Zero out the entire string
                            if (mbi.Type == MEM_PRIVATE)
                                SafeZeroNoSuspend(hProc, f, fullLen, log, success);
                            else
                                TryZeroMemory(hProc, f, fullLen, log, success);

                            if (success) {
                                cleared++;
                            }
                            else {
                                failed++;
                            }
                            total++;

                            // Update progress every 10 strings
                            size_t current = total.load();
                            if (current % 10 == 0) {
                                std::lock_guard<std::mutex> lk(mtx);
                                log << "\r[+] Found: " << current << " | Cleared: " << cleared.load() << " | Failed: " << failed.load() << "     ";
                            }

                            // Skip past this string to avoid duplicates
                            off = end - 1;
                            break;
                        }
                    }
                }
            }

            // UTF-16LE - Search for partial matches
            size_t wc = rb / sizeof(wchar_t);
            const wchar_t* wptr = (const wchar_t*)buf.data();

            // Convert wide string to lowercase for comparison
            std::wstring wbuf(wptr, wc);
            std::wstring wbufLower = wbuf;
            std::transform(wbufLower.begin(), wbufLower.end(), wbufLower.begin(), ::towlower);

            for (size_t off = 0; off + 1 < wc; ++off) {
                for (size_t kIdx = 0; kIdx < keywords.size(); kIdx++) {
                    const std::string& keyword = keywords[kIdx];
                    std::wstring wkeyword(keyword.begin(), keyword.end());
                    std::transform(wkeyword.begin(), wkeyword.end(), wkeyword.begin(), ::towlower);

                    size_t wlen = wkeyword.size();
                    if (!wlen || off + wlen > wc) continue;

                    // Check if keyword exists at this position (case-insensitive)
                    if (wbufLower.compare(off, wlen, wkeyword) == 0) {
                        // Find the full wide string containing this keyword
                        size_t start = off;
                        size_t end = off + wlen;

                        // Expand backward
                        while (start > 0 && (iswalnum(wptr[start - 1]) || wptr[start - 1] == L'_' || wptr[start - 1] == L'-' || wptr[start - 1] == L'.')) {
                            start--;
                        }

                        // Expand forward
                        while (end < wc && (iswalnum(wptr[end]) || wptr[end] == L'_' || wptr[end] == L'-' || wptr[end] == L'.')) {
                            end++;
                        }

                        // Extract full string
                        std::wstring fullWString(wptr + start, wptr + end);
                        size_t fullWLen = fullWString.size();

                        if (fullWLen > 0) {
                            uintptr_t f = (uintptr_t)mbi.BaseAddress + (start * sizeof(wchar_t));
                            std::string fullString(fullWString.begin(), fullWString.end());

                            bool success = false;
                            if (mbi.Type == MEM_PRIVATE)
                                SafeZeroNoSuspend(hProc, f, fullWLen * sizeof(wchar_t), log, success);
                            else
                                TryZeroMemory(hProc, f, fullWLen * sizeof(wchar_t), log, success);

                            if (success) {
                                cleared++;
                            }
                            else {
                                failed++;
                            }
                            total++;

                            // Update progress every 10 strings
                            size_t current = total.load();
                            if (current % 10 == 0) {
                                std::lock_guard<std::mutex> lk(mtx);
                                log << "\r[+] Found: " << current << " | Cleared: " << cleared.load() << " | Failed: " << failed.load() << "     ";
                            }

                            // Skip past this string
                            off = end - 1;
                            break;
                        }
                    }
                }
            }
        }
        };

    std::vector<std::thread> th;
    for (unsigned i = 0; i < workers; ++i)
        th.emplace_back(worker);
    for (size_t i = 0; i < th.size(); i++)
        th[i].join();

    ResumeAllThreads(suspended);
    CloseHandle(hProc);

    size_t cnt = total.load();
    size_t clr = cleared.load();
    size_t fail = failed.load();
    matchesFound = (cnt > 0);

    if (!cnt) return "No matches found.\r\n";

    std::ostringstream summary;
    summary << "\n\n========================================\n";
    summary << "  SCAN COMPLETE\n";
    summary << "========================================\n";
    summary << "  Total strings found: " << cnt << "\n";
    summary << "  Successfully cleared: " << clr << "\n";
    summary << "  Failed (protected): " << fail << "\n";
    summary << "========================================\n";
    summary << "\n[✓] CLEARED!\n";

    return summary.str();
}

//———————————————————— Console Main ————————————————————

int main() {
    EnableAllDebugPrivileges();

    SetConsoleTitle("Memory String Cleaner");

    std::cout << "========================================\n";
    std::cout << "    STRING CLEANER - Dev </> GhostX\n";
    std::cout << "========================================\n\n";

    while (true) {
        std::cout << "Enter Process Name or PID: ";
        std::string input;
        std::getline(std::cin, input);

        if (input.empty()) {
            std::cout << "Invalid input. Please try again.\n\n";
            continue;
        }

        bool isNumeric = !input.empty() && std::all_of(input.begin(), input.end(), ::isdigit);
        DWORD pid = 0;
        std::string procName;

        if (isNumeric) {
            pid = std::stoul(input);
            procName = GetProcessName(pid);
            if (procName.empty()) {
                std::cout << "ERROR: No process found with PID " << pid << "\n\n";
                continue;
            }
        }
        else {
            pid = GetProcessIdByName(input);
            if (pid == 0) {
                std::cout << "ERROR: No process found with name \"" << input << "\"\n\n";
                continue;
            }
            procName = input;
        }

        std::cout << "\n========================================\n";
        std::cout << "  PROCESS DETECTED\n";
        std::cout << "========================================\n";
        std::cout << "  Name : " << procName << "\n";
        std::cout << "  PID  : " << pid << "\n";
        std::cout << "========================================\n\n";

        // Ask for keywords
        std::cout << "ENTER KEYWORDS (comma separated): ";
        std::string keywordsLine;
        std::getline(std::cin, keywordsLine);

        // Parse keywords
        std::vector<std::string> keywords;
        std::string currentKeyword;
        for (size_t i = 0; i <= keywordsLine.length(); i++) {
            char c = (i < keywordsLine.length()) ? keywordsLine[i] : ',';
            if (c == ',' || c == ' ' || c == '\t') {
                if (!currentKeyword.empty()) {
                    keywords.push_back(currentKeyword);
                    currentKeyword.clear();
                }
                while (i < keywordsLine.length() && (keywordsLine[i] == ' ' || keywordsLine[i] == '\t')) {
                    i++;
                }
                if (i < keywordsLine.length()) {
                    i--;
                }
            }
            else {
                currentKeyword += c;
            }
        }
        if (!currentKeyword.empty()) {
            keywords.push_back(currentKeyword);
        }

        if (keywords.empty()) {
            std::cout << "ERROR: No keywords entered.\n\n";
            continue;
        }

        std::cout << "\n========================================\n";
        std::cout << "  KEYWORDS DETECTED\n";
        std::cout << "========================================\n";
        for (size_t i = 0; i < keywords.size(); i++) {
            std::cout << "  " << (i + 1) << ". \"" << keywords[i] << "\"\n";
        }
        std::cout << "========================================\n\n";

        std::cout << "DO YOU WANT TO CLEAR ALL STRINGS CONTAINING THESE KEYWORDS? [Y/N]: ";
        std::string choice;
        std::getline(std::cin, choice);

        if (choice.empty() || (choice[0] != 'Y' && choice[0] != 'y')) {
            std::cout << "\nOperation cancelled.\n\n";
            continue;
        }

        std::cout << "\n[+] Searching and clearing strings...\n\n";

        bool matchesFound = false;
        std::string result = DeleteAdvanced(pid, keywords, matchesFound);

        std::cout << result;
        std::cout << "\n========================================\n\n";

        std::cout << "Press ENTER to clear another process, or type 'exit' to quit: ";
        std::string exitChoice;
        std::getline(std::cin, exitChoice);
        if (exitChoice == "exit" || exitChoice == "EXIT" || exitChoice == "q") {
            break;
        }
        std::cout << "\n";
    }

    std::cout << "\nExiting...\n";
    return 0;
}
