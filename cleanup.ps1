param(
    [switch]$WhatIf
)

# -- CONFIG --
$scriptBase = "https://raw.githubusercontent.com/Justanother-engineer/scenario3/main"

# -- Elevation Gate --
$isAdmin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Not admin. Requesting elevation..."
    $scriptUrl = "$scriptBase/cleanup.ps1"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
        "iex((New-Object Net.WebClient).DownloadString('$scriptUrl'))"
    ))
    Start-Process powershell -Verb RunAs -ArgumentList "-NoP -Exec Bypass -Enc $b64"
    exit
}

Write-Host "[*] Running with admin privileges."

$ErrorActionPreference = "SilentlyContinue"

$cleanupLog = "C:\ProgramData\Microsoft\cache\tray\cleanup.dat"
function Write-CleanupLog($msg) {
    $parent = Split-Path $cleanupLog -Parent
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    "$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') $msg" | Out-File $cleanupLog -Append
}

Write-Host "[*] Cleaning up scenario-03 artifacts..."
Write-CleanupLog "[*] cleanup.ps1 started - logFile=$cleanupLog"

# 1. Delete staging files
$stagingDir = "C:\ProgramData\Microsoft\cache\tray"
Write-CleanupLog "[*] Scanning $stagingDir"
if (Test-Path $stagingDir) {
    Get-ChildItem -Path $stagingDir -File -ErrorAction SilentlyContinue | ForEach-Object {
        if ($WhatIf) {
            Write-CleanupLog "[WHATIF] would delete $($_.FullName)"
        } else {
            Remove-Item -Path $_.FullName -Force
            Write-CleanupLog "[-] Deleted: $($_.FullName)"
        }
    }
}

# 2. Delete .govinda files from user profile
Write-CleanupLog "[*] Scanning for .govinda files"
$profileDirs = @("Desktop", "Documents", "Pictures", "Downloads")
foreach ($dir in $profileDirs) {
    $path = [Environment]::GetFolderPath($dir)
    if ($path -and (Test-Path $path)) {
        Get-ChildItem -Path $path -Filter "*.govinda" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($WhatIf) {
                Write-CleanupLog "[WHATIF] would delete $($_.FullName)"
            } else {
                Remove-Item -Path $_.FullName -Force
                Write-CleanupLog "[-] Deleted .govinda: $($_.FullName)"
            }
        }
    }
}

# 3. Delete README_GOVINDA.txt from Desktop
$desktop = [Environment]::GetFolderPath("Desktop")
$notePath = Join-Path $desktop "README_GOVINDA.txt"
if (Test-Path $notePath) {
    if ($WhatIf) {
        Write-CleanupLog "[WHATIF] would delete $notePath"
    } else {
        Remove-Item -Path $notePath -Force
        Write-CleanupLog "[-] Deleted ransom note: $notePath"
    }
}

# 4. Delete %TEMP%\loader.dll
$tempLoader = "$env:TEMP\loader.dll"
if (Test-Path $tempLoader) {
    if ($WhatIf) {
        Write-CleanupLog "[WHATIF] would delete $tempLoader"
    } else {
        Remove-Item -Path $tempLoader -Force
        Write-CleanupLog "[-] Deleted: $tempLoader"
    }
}

# 5. Residual verification
Write-CleanupLog ""
Write-CleanupLog "[*] Residual verification"
$residFiles = @()
$residualPaths = @(
    $stagingDir,
    $notePath,
    $tempLoader
)
foreach ($p in $residualPaths) {
    if (Test-Path -LiteralPath $p) { $residFiles += $p }
}
$residGovinda = Get-ChildItem -Path $profileDirs -Filter "*.govinda" -ErrorAction SilentlyContinue
$residCount = $residFiles.Count + $residGovinda.Count

if ($residCount -eq 0) {
    Write-CleanupLog "[+] Clean: no residuals detected"
    Write-Host "[+] Clean: no residuals detected"
} else {
    Write-CleanupLog "[-] $residCount residual(s) remain:"
    $residFiles | ForEach-Object { Write-CleanupLog "    file: $_" }
    $residGovinda | ForEach-Object { Write-CleanupLog "    .govinda: $($_.FullName)" }
}

# 6. Self-delete
$selfPath = $MyInvocation.MyCommand.Path
Write-CleanupLog "[*] Self-delete target: $selfPath"
if (-not $WhatIf -and $selfPath -and (Test-Path $selfPath)) {
    Remove-Item -Path $selfPath -Force
}

Write-CleanupLog "[+] Cleanup complete - log at $cleanupLog"
Write-Host "[+] Cleanup complete. Report at $cleanupLog"
