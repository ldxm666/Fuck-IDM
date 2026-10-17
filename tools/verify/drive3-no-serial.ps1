$ErrorActionPreference='Continue'
$log='D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\drive3-no-serial.log'
function W($m){ $m | Out-File -FilePath $log -Append -Encoding utf8 }
"=== drive3 no-serial $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File -FilePath $log -Encoding utf8
Set-Location 'D:\pojie应用\jiesuo\work\idm-6.43b8'
W "--- flushdns ---"; W (& ipconfig /flushdns 2>&1 | Out-String)
W "--- set no-serial ---"
W (& powershell -NoProfile -ExecutionPolicy Bypass -File scripts\idm-permanent-fix.ps1 -RegMode no-serial 2>&1 | Out-String)
W "--- flushdns again ---"; W (& ipconfig /flushdns 2>&1 | Out-String)
$c=Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue
W ("Serial='{0}' FName='{1}' LName='{2}' Email='{3}'" -f $c.Serial,$c.FName,$c.LName,$c.Email)
if($c.Serial){ W "!! ABORT: Serial still present in no-serial mode"; exit 1 }
$bad=0
foreach($dn in 'internetdownloadmanager.com','www.internetdownloadmanager.com','secure.internetdownloadmanager.com','register.internetdownloadmanager.com','tonec.com','www.tonec.com'){
  $r=(ping -n 1 -w 1000 $dn 2>&1 | Out-String)
  $blocked=($r -notmatch 'Pinging|来自|Reply from')
  if(-not $blocked){ $bad++ }
  W ("  DNS {0,-38} blocked={1}" -f $dn,$blocked)
}
if($bad -gt 0){ W ("!! ABORT: {0} domain(s) reachable" -f $bad); exit 1 }
W "preconditions OK -> starting no-serial soak"
W (& powershell -NoProfile -ExecutionPolicy Bypass -File 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\verify-run3.ps1' -Mode no-serial -Runs 5 -SoakSeconds 300 2>&1 | Out-String)
W "=== drive3 no-serial done ==="
