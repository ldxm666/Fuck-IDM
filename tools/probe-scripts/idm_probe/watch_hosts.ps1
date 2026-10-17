<#
  watch_hosts.ps1 - hosts tamper-watcher.

  Hypothesis under test: IDM itself comments out our hosts block lines at startup,
  which would make the license server reachable exactly while IDM runs - explaining
  the user's "popup fires at unpredictable times after activation".

  Evidence that motivated this: hosts LastWriteTime 03:02:02 vs a run that started
  03:02:00 (2 s apart), and an earlier same-shaped observation at 02:49:44 (3/6).

  Every IntervalMs it computes the hosts quad:
      sha256 | line count | effective IDM lines | LastWriteTime
  and writes a record ONLY when the sha256 changes (plus a periodic heartbeat).
  On a change it dumps the FULL IDM-related lines before/after, so the tamper is
  provable from the log alone.

  READ-ONLY with respect to hosts: this script never writes to it.
#>
param(
  [int]$DurationSec = 1000,
  [string]$LogPath = "$env:TEMP\idm_probe\hosts_watch.log",
  [int]$IntervalMs = 2000
)

$ErrorActionPreference = 'Continue'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$dir = Split-Path -Parent $LogPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

function Get-HostsQuad {
  $fi = Get-Item -LiteralPath $hosts
  $bytes = [System.IO.File]::ReadAllBytes($hosts)
  $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  $shaHex = ($sha | ForEach-Object { $_.ToString('x2') }) -join ''
  $lines = @(Get-Content -LiteralPath $hosts)
  $idmLines = @($lines | Where-Object { $_ -match 'internetdownloadmanager|tonec' })
  $effective = @($lines | Where-Object { $_ -match '^\s*[^#\s]' -and $_ -match 'internetdownloadmanager|tonec' }).Count
  return [pscustomobject]@{
    sha256    = $shaHex
    lineCount = $lines.Count
    effective = $effective
    lastWrite = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss.fff')
    idmLines  = $idmLines
  }
}

function Write-Quad([string]$tag, $q) {
  "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'))] $tag sha256=$($q.sha256.Substring(0,16)) lines=$($q.lineCount) effective=$($q.effective) lastWrite=$($q.lastWrite)" |
    Out-File -FilePath $LogPath -Append -Encoding UTF8
  foreach ($l in $q.idmLines) { "    | $l" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
}

$start = Get-Date
$deadline = $start.AddSeconds($DurationSec)
$prev = Get-HostsQuad
"=== watch_hosts start $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')) duration=${DurationSec}s ===" |
  Out-File -FilePath $LogPath -Append -Encoding UTF8
Write-Quad 'INITIAL' $prev
$lastBeat = Get-Date

while ((Get-Date) -lt $deadline) {
  try {
    $cur = Get-HostsQuad
    if ($cur.sha256 -ne $prev.sha256) {
      "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'))] *** HOSTS CHANGED ***" |
        Out-File -FilePath $LogPath -Append -Encoding UTF8
      "  BEFORE: effective=$($prev.effective) lastWrite=$($prev.lastWrite)" |
        Out-File -FilePath $LogPath -Append -Encoding UTF8
      foreach ($l in $prev.idmLines) { "    -| $l" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
      "  AFTER : effective=$($cur.effective) lastWrite=$($cur.lastWrite)" |
        Out-File -FilePath $LogPath -Append -Encoding UTF8
      foreach ($l in $cur.idmLines) { "    +| $l" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
      $prev = $cur
    }
  } catch {
    "[$((Get-Date).ToString('HH:mm:ss.fff'))] HOSTWATCH-ERROR $_" | Out-File -FilePath $LogPath -Append -Encoding UTF8
  }

  if (((Get-Date) - $lastBeat).TotalSeconds -ge 60) {
    $lastBeat = Get-Date
    $q = Get-HostsQuad
    "[$((Get-Date).ToString('HH:mm:ss.fff'))] heartbeat elapsed=$([int]((Get-Date) - $start).TotalSeconds)s effective=$($q.effective) IDManProcs=$(@(Get-Process IDMan -ErrorAction SilentlyContinue).Count)" |
      Out-File -FilePath $LogPath -Append -Encoding UTF8
  }
  Start-Sleep -Milliseconds $IntervalMs
}

Write-Quad 'FINAL' (Get-HostsQuad)
"=== watch_hosts end $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')) ===" |
  Out-File -FilePath $LogPath -Append -Encoding UTF8
