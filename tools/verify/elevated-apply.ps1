$ErrorActionPreference = 'Continue'
$log = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\elevated-apply.log'
$py  = 'C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe'
$exe = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
function W($m){ $m | Out-File -FilePath $log -Append -Encoding utf8 }
"=== elevated apply $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File -FilePath $log -Encoding utf8
W ("elevated = {0}" -f ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
W ("BEFORE sha256 = {0}" -f (Get-FileHash $exe -Algorithm SHA256).Hash)
Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill(); W ("killed IDMan pid {0}" -f $_.Id) }
Start-Sleep -Milliseconds 800
Set-Location 'D:\pojie应用\jiesuo\work\idm-6.43b8'
W "--- apply_all ---"
$out = & $py scripts\apply_patches_to_install.py 2>&1 | Out-String
W $out
W ("AFTER sha256 = {0}" -f (Get-FileHash $exe -Algorithm SHA256).Hash)
W "--- scan ---"
W (& $py scripts\apply_patches_to_install.py --scan 2>&1 | Out-String)
W "=== done ==="
