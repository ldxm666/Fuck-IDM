<#
  watch_procs.ps1 - capture every newly-launched IDM-related process WITH its command line.

  WHY
    The counterfeit popup was observed to belong to pid 15856 = IDMGrHlp.exe, NOT IDMan.exe
    (see logs_and_dumps/idm/probe/idm930b_dialogs.log). IDMGrHlp.exe imports
    GetCommandLineA and MessageBoxA, yet the wording exists in NO binary on disk
    (verified: plain and XOR 0x0F, in both IDMan.exe and IDMGrHlp.exe). So the text is
    supplied at runtime. If IDMan.exe hands it over as a command-line argument, this
    watcher captures the wording verbatim - which would locate the source in one shot.

  READ-ONLY: enumerates processes and reads their command lines. Launches nothing.
#>
param(
  [int]$DurationSec = 600,
  [string]$LogPath = "$env:TEMP\idm_probe\proc_watch.log",
  [int]$IntervalMs = 1000,
  [string]$NamePattern = 'IDM|idm|IEMonitor|tonec'
)

$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $LogPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

$start = Get-Date
$deadline = $start.AddSeconds($DurationSec)
$seen = @{}

"=== watch_procs start $($start.ToString('yyyy-MM-dd HH:mm:ss.fff')) duration=${DurationSec}s pattern=$NamePattern ===" |
  Out-File -FilePath $LogPath -Append -Encoding UTF8

while ((Get-Date) -lt $deadline) {
  try {
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
      if (-not $p.Name) { continue }
      if ($p.Name -notmatch $NamePattern) { continue }
      if ($seen.ContainsKey([int]$p.ProcessId)) { continue }
      $seen[[int]$p.ProcessId] = $true
      $el = [int]((Get-Date) - $start).TotalSeconds
      "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'))] +${el}s NEW pid=$($p.ProcessId) ppid=$($p.ParentProcessId) name=$($p.Name)" |
        Out-File -FilePath $LogPath -Append -Encoding UTF8
      "    cmdline=[$($p.CommandLine)]" | Out-File -FilePath $LogPath -Append -Encoding UTF8
    }
  } catch {
    "[$((Get-Date).ToString('HH:mm:ss.fff'))] PROCWATCH-ERROR $_" | Out-File -FilePath $LogPath -Append -Encoding UTF8
  }
  Start-Sleep -Milliseconds $IntervalMs
}

"=== watch_procs end $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')) ===" |
  Out-File -FilePath $LogPath -Append -Encoding UTF8
