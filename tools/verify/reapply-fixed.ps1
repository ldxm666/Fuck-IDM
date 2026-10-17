$ErrorActionPreference='Continue'
$log='D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\reapply-fixed.log'
$py='C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe'
$exe='C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
function W($m){ $m | Out-File -FilePath $log -Append -Encoding utf8 }
"=== REAPPLY (fixed engine) $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File -FilePath $log -Encoding utf8
W ("elevated = {0}" -f ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
Start-Sleep -Seconds 2
W ("BROKEN installed sha256 = {0}" -f (Get-FileHash $exe -Algorithm SHA256).Hash)
Set-Location 'D:\pojie应用\jiesuo\work\idm-6.43b8'
W "--- 1) RESTORE ---"
W (& $py scripts\apply_patches_to_install.py --restore 2>&1 | Out-String)
W ("restored sha256 = {0}" -f (Get-FileHash $exe -Algorithm SHA256).Hash)
W "--- 2) APPLY (fixed P5 = nop x8) ---"
W (& $py scripts\apply_patches_to_install.py 2>&1 | Out-String)
W ("final sha256 = {0}" -f (Get-FileHash $exe -Algorithm SHA256).Hash)
W "=== done ==="
