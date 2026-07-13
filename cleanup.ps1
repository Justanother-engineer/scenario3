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

# ponytail: artifacts are scattered across system dirs (see loader.ps2 CONFIG).
# cleanup sweeps each explicit file + the scatter dirs, then user-profile .govinda.
$cleanupLog = "C:\Windows\Temp\cleanup.dat"
function Write-CleanupLog($msg) {
    $parent = Split-Path $cleanupLog -Parent
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    "$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') $msg" | Out-File $cleanupLog -Append
}

Write-Host "[*] Cleaning up scenario-03 artifacts..."
Write-CleanupLog "[*] cleanup.ps1 started - logFile=$cleanupLog"

# 1. Delete scattered staging files
$scatterFiles = @(
    "C:\Windows\Temp\cache.dat",
    "C:\Windows\Temp\boot-ok.flag",
    "C:\Users\Public\Documents\payload.hta",
    "C:\Windows\System32\loader.dll",
    "C:\Windows\SysWOW64\stage2.dll",
    "C:\ProgramData\Microsoft\Diagnosis\net.tmp"
)
$scatterDirs = @(
    "C:\ProgramData\Microsoft\Diagnosis"
)
foreach ($f in $scatterFiles) {
    if (Test-Path -LiteralPath $f) {
        if ($WhatIf) {
            Write-CleanupLog "[WHATIF] would delete $f"
        } else {
            Remove-Item -LiteralPath $f -Force
            Write-CleanupLog "[-] Deleted: $f"
        }
    }
}
foreach ($d in $scatterDirs) {
    if (Test-Path -LiteralPath $d) {
        if ($WhatIf) {
            Write-CleanupLog "[WHATIF] would sweep $d"
        } else {
            Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -LiteralPath $_.FullName -Force
                Write-CleanupLog "[-] Deleted: $($_.FullName)"
            }
        }
    }
}

# 2. Delete .govinda files from user profile + system scatter dirs
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

# 2b. Sweep additional scatter dirs touched by stage2 synthetic-drop fallback
$govindaScatterDirs = @(
    [Environment]::GetFolderPath("CommonDocuments"),
    "C:\ProgramData\Microsoft\Diagnosis",
    "C:\Windows\Temp",
    $env:TEMP
)
foreach ($gdir in $govindaScatterDirs) {
    if ($gdir -and (Test-Path -LiteralPath $gdir)) {
        Get-ChildItem -LiteralPath $gdir -Filter "*.govinda" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($WhatIf) {
                Write-CleanupLog "[WHATIF] would delete $($_.FullName)"
            } else {
                Remove-Item -LiteralPath $_.FullName -Force
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
$residualPaths = @($scatterFiles) + @($notePath) + @($tempLoader)
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
