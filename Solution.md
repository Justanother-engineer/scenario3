# Scenario 03 — Phishing: MITRE ATT&CK Coverage (Flow Order)

This document lists every MITRE ATT&CK technique exercised by the scenario, in the order they fire during a run. Each entry includes: the technique ID, name, what it does in this scenario, and the code reference (`file:line`) where it is implemented.

---

## Tactic: Initial Access

### T1566.001 — Phishing: Spearphishing Attachment
- **What:** User receives a phishing email with `Invoice_June2026.zip` containing `Invoice_Details.pdf.lnk`. User extracts and double-clicks.
- **Where:** `create-lnk.ps1:1-14` (LNK generation script)
- **Detection:** Sysmon EID 1 — `powershell.exe` with parent: `explorer.exe` (LNK execution)

---

## Tactic: Execution

### T1059.001 — Command and Scripting Interpreter: PowerShell
- **What:** The LNK runs PowerShell with a download cradle that fetches `loader.ps2` from GitHub and pipes to `iex`.
- **Where:** `create-lnk.ps1:8` (LNK target argument)
- **Detection:** Sysmon EID 1 — `powershell.exe` command-line contains `DownloadString` and `IEX`.

### T1218.005 — System Binary Proxy Execution: Mshta
- **What:** `loader.ps2` spawns `mshta.exe` (PPID-spoofed to `explorer.exe`) which executes `payload.hta`.
- **Where:** `loader.ps2:228-229` (PPID spoof → mshta)
- **Detection:** Sysmon EID 1 — `mshta.exe` parent = `explorer.exe`; EID 7 — `mshtml.dll` loaded.

### T1105 — Ingress Tool Transfer
- **What:** `certutil.exe -urlcache` downloads `loader.dll` from GitHub to `%TEMP%`.
- **Where:** `payload.hta:75-85` (certutil download)
- **Detection:** Sysmon EID 1 — `certutil.exe` with `-urlcache` and GitHub URL; EID 3 — outbound TLS.

### T1218.011 — System Binary Proxy Execution: Rundll32
- **What:** `payload.hta` launches `rundll32.exe` with `loader.dll,Hollow` to execute the process hollowing DLL.
- **Where:** `payload.hta:97-102` (rundll32 launch)
- **Detection:** Sysmon EID 1 — `rundll32.exe` loading unsigned `loader.dll` from `%TEMP%`.

---

## Tactic: Defense Evasion

### T1562.001 — Impair Defenses: AMSI Bypass
- **What:** A sacrificial child PowerShell patches `amsi.dll!AmsiScanBuffer` via `VirtualProtect` + `WriteProcessMemory`. Run in child process because the inline byte-patch can trigger TerminateProcess on hardened hosts; child dies, parent lives.
- **Where:** `loader.ps2:88-197` (Bypass C# class, sacrificial child)
- **Detection:** Sysmon EID 10 — `VirtualProtect` + `WriteProcessMemory` to `amsi.dll` code section from `powershell.exe`.

### T1562.006 — Impair Defenses: ETW Patching
- **What:** Same child process patches `ntdll!EtwEventWrite` → `ret` (0xC3) so subsequent process telemetry events are silently dropped.
- **Where:** `loader.ps2:148-153` (Bypass.Go() ETW patch via `Marshal.Copy`)
- **Detection:** Sysmon EID 10 — `VirtualProtect` + `WriteProcessMemory` to `ntdll.dll` code section.

### T1055.012 — Process Injection: Process Hollowing
- **What:** `loader.dll` creates `svchost.exe` suspended, unmaps its original image via `NtUnmapViewOfSection`, allocates memory, writes `stage2.dll` PE headers + sections, sets thread context to entry point, and resumes.
- **Where:** `loader.c:79-153` (Hollow function)
- **Detection:** Sysmon EID 1 — `svchost.exe` created suspended; EID 10 — `VirtualAllocEx` + `WriteProcessMemory` + `SetThreadContext`. No EID 8 (`CreateRemoteThread`).

### T1055.012 — Process Injection: PPID Spoofing
- **What:** `spoof.cs::SpawnWithParent` uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to make `mshta.exe` inherit `explorer.exe`'s handle as the parent. Process tree shows `explorer.exe → mshta.exe`.
- **Where:** `spoof.cs:117-170` (SpawnWithParent); `loader.ps2:226-233` (invocation)
- **Detection:** Sysmon EID 10 — `OpenProcess(PROC_CREATE_PROCESS)` on `explorer.exe`; EID 1 — mshta ParentImage = `explorer.exe`.

### T1036.005 — Masquerading: System Process Spoofing
- **What:** The payload runs inside a hollowed `svchost.exe` — a legitimate Windows system process.
- **Where:** `loader.c:79-153` (svchost hollowing)
- **Detection:** Sysmon EID 1 — `svchost.exe` with unusual parent (rundll32.exe instead of services.exe).

### T1070.006 — Indicator Removal: Timestomping
- **What:** `payload.hta` copies timestamps (DateCreated, DateLastModified, DateLastAccessed) from `kernel32.dll` to `loader.dll` to blend dropped file age with the OS.
- **Where:** `payload.hta:89-95` (timestomp)
- **Detection:** Sysmon EID 2 (FileCreateTime) — loader.dll timestamps match kernel32.dll.

### T1564.003 — Hide Artifacts: Hidden Window
- **What:** All child processes are spawned with `SW_HIDE` / `CREATE_NO_WINDOW` / `-WindowStyle Hidden`.
- **Where:** `loader.ps2:159` (`-WindowStyle Hidden`); `loader.c:88` (`CREATE_NO_WINDOW`); `payload.hta:81,98` (`WScript.Shell.Run` with window style 0)
- **Detection:** Sysmon EID 1 — child processes spawned with no window.

### T1027 — Obfuscated Files or Information
- **What:** `spoof.cs` (PPID spoof C#) is base64-embedded in `loader.ps2` and only decoded at runtime via `Add-TypeInMem`. No plain C# in any AMSI-scanned scriptblock.
- **Where:** `loader.ps2:185` (`$spoofBase64` blob); `loader.ps2:227` (`FromBase64String` + `Add-TypeInMem`)
- **Detection:** Static — C# source not visible without base64 decode.

### T1070.004 — Indicator Removal: File Deletion
- **What:** After the chain completes, `cleanup.ps1` removes all staging files, `.govinda` files, ransom note, and `%TEMP%\loader.dll`. Self-deletes at end.
- **Where:** `cleanup.ps1:44-80` (file deletion); `cleanup.ps1:97-100` (self-delete)
- **Detection:** Sysmon EID 23 (FileDelete) on each artifact path.

### T1116 — Code Signing (proxy via Microsoft binaries)
- **What:** Every process spawned in the chain is Microsoft-signed: `powershell.exe`, `mshta.exe`, `certutil.exe`, `rundll32.exe`, `svchost.exe`, `vssadmin.exe`. The payload DLLs (`loader.dll`, `stage2.dll`) are unsigned but run inside signed processes.
- **Where:** Implicit across all `CreateProcess` / `Start-Process` call sites.
- **Detection:** Authenticode audit — `loader.dll` and `stage2.dll` in `%TEMP%` and `cache\tray\` have no signature; parent chain is signed.

---

## Tactic: Privilege Escalation

### T1548.002 — Bypass User Account Control
- **What:** `loader.ps2` checks admin via `IsInRole(Administrator)`. If not admin, re-launches itself via `Start-Process -Verb RunAs` (standard UAC prompt — user must click Yes).
- **Where:** `loader.ps2:17-30` (admin gate); `cleanup.ps1:10-21` (same pattern)
- **Detection:** Winlogbeat 4672 (special privileges) on the re-spawned PowerShell.

---

## Tactic: Impact

### T1490 — Inhibit System Recovery: Volume Shadow Copy Deletion
- **What:** `stage2.dll` runs `vssadmin.exe delete shadows /all /quiet` to destroy system restore points.
- **Where:** `stage2.c:38-49` (DoVssadmin)
- **Detection:** Sysmon EID 1 — `vssadmin.exe` with `delete shadows` argument.

### T1486 — Data Encrypted for Impact
- **What:** Stage2 enumerates user profile folders (Desktop, Documents, Pictures, Downloads), copies matched files (`.docx`, `.xlsx`, `.pptx`, `.pdf`, `.txt`), and encrypts the copy via `CryptEncrypt` (AES-256) to `.govinda` extension. Originals are untouched. Ransom note dropped to Desktop.
- **Where:** `stage2.c:51-127` (DoEncryptFiles); `stage2.c:141-155` (DoRansomNote)
- **Detection:** Sysmon EID 11 — mass `.govinda` file creates; EID 4663 — mass file reads from `svchost.exe`; EID 11 — `README_GOVINDA.txt` on Desktop. Fallback: synthetic `.govinda` if no user documents found.

---

## Tactic: Collection

### T1074.001 — Data Staged: Local Data Staging
- **What:** All exfiltratable artifacts are written to `C:\ProgramData\Microsoft\cache\tray\`:
  - `cache.dat` — main log (recon, beacons, lifecycle)
  - `net.tmp` — lateral recon results (NetServerEnum, port scans, shares)
- **Where:** All stage2.c writers (`DoLateralRecon`, `LogMessage`, `AppendToFile`)
- **Detection:** Sysmon EID 11 — file creates in `cache\tray\`.

---

## Tactic: Command and Control

### T1041 — Exfiltration over Web Protocol
- **What:** `stage2.dll` sends 3 HTTP GET requests to `https://github.com` via `WinHttpOpen`/`WinHttpSendRequest` with 10s `Sleep` between. No data payload — pure connection pattern beacon.
- **Where:** `stage2.c:129-146` (DoBeacon)
- **Detection:** Sysmon EID 3 — `svchost.exe` outbound TLS to `github.com` (3x, 10s apart).

---

## Tactic: Discovery

### T1018 — Remote System Discovery
- **What:** `stage2.dll` calls `NetServerEnum(SV_TYPE_ALL)` to enumerate all domain-joined/workgroup machines.
- **Where:** `stage2.c:159-210` (DoLateralRecon)
- **Detection:** Winlogbeat 5156 — high-volume NetServerEnum from `svchost.exe`.

### T1046 — Network Service Discovery (port 445 scan)
- **What:** For each discovered host, `stage2.dll` opens a TCP socket to port 445 with a 3s timeout.
- **Where:** `stage2.c:175-183` (socket connect to 445)
- **Detection:** Sysmon EID 3 — `svchost.exe` connecting to port 445 on multiple IPs.

### T1135 — Network Share Discovery
- **What:** `NetShareEnum` on each reachable host to list available SMB shares.
- **Where:** `stage2.c:185-193` (NetShareEnum)
- **Detection:** Winlogbeat 5140/5145 (SMB share enumeration events).

---

## Tactic: Lateral Movement

### T1570 — Lateral Tool Transfer *(synthetic)*
- **What:** `stage2.dll` logs a synthetic entry: `CopyFile to \\DESKTOP-1\ADMIN$\govinda.exe (synthetic)` — no actual file copy attempted.
- **Where:** `stage2.c:215` (synthetic log)
- **Detection:** The `net.tmp` entry is the only artifact (no real network traffic).

### T1047 — Windows Remote Management (WMI) *(synthetic)*
- **What:** `stage2.dll` logs a synthetic entry: `WMI Win32_Process.Create on DESKTOP-1 (synthetic)`.
- **Where:** `stage2.c:216` (synthetic log)
- **Detection:** The `net.tmp` entry is the only artifact (no real WMI call).

---

## Summary — coverage at a glance

| Tactic | Techniques |
|--------|-----------|
| Initial Access | T1566.001 (phishing LNK) |
| Execution | T1059.001, T1218.005, T1218.011, T1105 |
| Defense Evasion | T1562.001, T1562.006, T1055.012 (x2), T1036.005, T1070.006, T1564.003, T1027, T1070.004, T1116 |
| Privilege Escalation | T1548.002 |
| Impact | T1486, T1490 |
| Collection | T1074.001 |
| Command and Control | T1041 |
| Discovery | T1018, T1046, T1135 |
| Lateral Movement | T1570 (synthetic), T1047 (synthetic) |

**~22 distinct techniques across 9 tactics.** Every technique maps to at least one Sysmon EID, Winlogbeat channel, or file artifact.

### Notable coverage choices

- **T1562.001 + T1562.006 + T1027** form the defense-evasion triad: base64-encoded C# source for PPID spoof, in-memory compile, AMSI/ETW patched in sacrificial child.
- **T1055.012 (process hollowing)** is the primary execution vector — the entire payload runs inside a hollowed `svchost.exe` with no dropped EXE.
- **T1486 (data encrypted)** does NOT destroy originals — it creates `.govinda` encrypted copies. Ransom note dropped for SOC visibility.
- **T1490 (volume shadow copy deletion)** is the most destructive step; vssadmin may not exist on all Windows SKUs, so a synthetic fallback is logged.
- **Fallback paths** (non-domain lateral recon, synthetic `.govinda` if no documents, synthetic beacon if no network) ensure artifacts land even on edge cases. See `idea.md` for the full fallback matrix.
