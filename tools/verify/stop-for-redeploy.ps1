$ErrorActionPreference='Continue'
$log='D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\stop-for-redeploy.log'
function W($m){ $m | Out-File -FilePath $log -Append -Encoding utf8 }
"=== stop for redeploy $(Get-Date -Format 'HH:mm:ss') ===" | Out-File -FilePath $log -Encoding utf8
$mine = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'verify-run3|drive3-with-serial|watch_mdata' }
foreach($p in $mine){ W ("kill pid {0}" -f $p.ProcessId); try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }catch{ W ("  fail {0}" -f $_.Exception.Message) } }
Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { W ("kill IDMan pid {0}" -f $_.Id); try{$_.Kill()}catch{} }
Start-Sleep -Seconds 3
W ("remaining harness procs: {0}" -f @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'verify-run3|drive3-with-serial' }).Count)
W ("IDMan procs: {0}" -f @(Get-Process IDMan -ErrorAction SilentlyContinue).Count)
W "=== done ==="
