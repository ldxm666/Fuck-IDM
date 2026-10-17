$ErrorActionPreference='Continue'
$log='D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\smoke.log'
function W($m){ $m | Out-File -FilePath $log -Append -Encoding utf8 }
"=== SMOKE $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File -FilePath $log -Encoding utf8
Set-Location 'D:\pojie应用\jiesuo\work\idm-6.43b8'
W "--- set with-serial ---"
W (& powershell -NoProfile -ExecutionPolicy Bypass -File scripts\idm-permanent-fix.ps1 -RegMode with-serial 2>&1 | Out-String)
W "--- registry after ---"
$c=Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue
W ("Serial='{0}' FName='{1}' LName='{2}' Email='{3}'" -f $c.Serial,$c.FName,$c.LName,$c.Email)
W "--- smoke soak 1x90s ---"
W (& powershell -NoProfile -ExecutionPolicy Bypass -File 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\verify-run.ps1' -Mode with-serial -Runs 1 -SoakSeconds 90 2>&1 | Out-String)
W "=== done ==="
