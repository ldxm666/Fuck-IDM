$ErrorActionPreference='Continue'
$log='D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\soak-with-serial-driver.log'
function W($m){ $m | Out-File -FilePath $log -Append -Encoding utf8 }
"=== driver with-serial $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File -FilePath $log -Encoding utf8
Set-Location 'D:\pojie应用\jiesuo\work\idm-6.43b8'
W "--- set with-serial ---"
W (& powershell -NoProfile -ExecutionPolicy Bypass -File scripts\idm-permanent-fix.ps1 -RegMode with-serial 2>&1 | Out-String)
$c=Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue
W ("Serial='{0}' FName='{1}' LName='{2}' Email='{3}'" -f $c.Serial,$c.FName,$c.LName,$c.Email)
W "--- soak 5x300s ---"
W (& powershell -NoProfile -ExecutionPolicy Bypass -File 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\verify-run2.ps1' -Mode with-serial -Runs 5 -SoakSeconds 300 2>&1 | Out-String)
W "=== driver done ==="
