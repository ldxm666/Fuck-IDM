$ErrorActionPreference='Continue'
$log='D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\guard-disable.log'
function W($m){ $m | Out-File -FilePath $log -Append -Encoding utf8 }
"=== guard task disable $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File -FilePath $log -Encoding utf8
W ("elevated = {0}" -f ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
foreach($n in 'IDM-Activator-Guard','IDM-Activator-Guard-Logon'){
  try{
    $t=Get-ScheduledTask -TaskName $n -ErrorAction Stop
    W ("BEFORE {0}: State={1} Enabled={2}" -f $n,$t.State,$t.Settings.Enabled)
    if($t.State -ne 'Disabled'){ Disable-ScheduledTask -TaskName $n -ErrorAction Stop | Out-Null }
    $t2=Get-ScheduledTask -TaskName $n
    W ("AFTER  {0}: State={1} Enabled={2}" -f $n,$t2.State,$t2.Settings.Enabled)
  } catch { W ("{0}: {1}" -f $n,$_.Exception.Message) }
}
W "--- any IDM-Activator.exe process ---"
$pr=@(Get-Process IDM-Activator -ErrorAction SilentlyContinue)
W ("count = {0}" -f $pr.Count)
$pr | ForEach-Object { W ("  pid {0} started {1}" -f $_.Id,$_.StartTime) }
W "=== done ==="
