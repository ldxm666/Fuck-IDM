$ErrorActionPreference='Continue'
$log='D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\stop-soak.log'
function W($m){ $m | Out-File -FilePath $log -Append -Encoding utf8 }
"=== stop contaminated soak $(Get-Date -Format 'HH:mm:ss') ===" | Out-File -FilePath $log -Encoding utf8
$mine = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'verify-run2|drive-with-serial' }
foreach($p in $mine){ W ("kill pid {0} : {1}" -f $p.ProcessId, $p.CommandLine); try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }catch{ W ("  failed: {0}" -f $_.Exception.Message) } }
Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { W ("kill IDMan pid {0}" -f $_.Id); try{$_.Kill()}catch{} }
Start-Sleep -Seconds 2
W "--- remaining ---"
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'verify-run2|drive-with-serial' } | ForEach-Object { W ("STILL: {0}" -f $_.ProcessId) }
W ("IDMan procs: {0}" -f @(Get-Process IDMan -ErrorAction SilentlyContinue).Count)
W "=== done ==="
