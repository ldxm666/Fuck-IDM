<#
  watch_dialogs.ps1 - independent (hook-free) Win32 window-enumeration witness.

  Every IntervalMs it enumerates top-level windows, and when the set of dialog-class
  (#32770) windows changes it logs full detail: class, title, body text (Static children),
  button labels, owner pid/process name, rect. This:
    * proves whether the popup really is a standard MessageBox (#32770 + Static/Button), or
      a custom dialog resource;
    * is the fallback evidence if Frida gets blocked by IDM's anti-debug.

  It also auto-dismisses the probe's own self-test window ("PROBE SELFTEST") so the
  liveness check cannot block the run.
#>
param(
  [int]$DurationSec = 340,
  [string]$LogPath = "$env:TEMP\idm_probe\dialogs.log",
  [int]$IntervalMs = 1000
)

$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $LogPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WinProbe {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
}
"@

function Get-WinClass([IntPtr]$h) {
  $sb = New-Object System.Text.StringBuilder 512
  [void][WinProbe]::GetClassName($h, $sb, $sb.Capacity)
  return $sb.ToString()
}
function Get-WinText([IntPtr]$h) {
  $len = [WinProbe]::GetWindowTextLength($h)
  if ($len -le 0) { return '' }
  $sb = New-Object System.Text.StringBuilder ($len + 2)
  [void][WinProbe]::GetWindowText($h, $sb, $sb.Capacity)
  return $sb.ToString()
}
function Get-ProcName([uint32]$p) {
  try { return (Get-Process -Id $p -ErrorAction Stop).ProcessName } catch { return '?' }
}

# NOTE: accumulators are .NET ArrayList objects, NOT PowerShell arrays.
# A child-scope `+=` inside a native-callback scriptblock would create a local copy and
# silently lose the data; calling .Add() mutates the shared object instead.
function Get-DialogSnapshot {
  $script:foundList = New-Object System.Collections.ArrayList
  $cb = [WinProbe+EnumProc]{
    param([IntPtr]$h, [IntPtr]$l)
    try {
      $cls = Get-WinClass $h
      if ($cls -eq '#32770') {
        [uint32]$wpid = 0
        [void][WinProbe]::GetWindowThreadProcessId($h, [ref]$wpid)
        $script:childList = New-Object System.Collections.ArrayList
        $ccb = [WinProbe+EnumProc]{
          param([IntPtr]$ch, [IntPtr]$cl)
          try {
            [void]$script:childList.Add(('{0}|{1}' -f (Get-WinClass $ch), (Get-WinText $ch)))
          } catch {}
          return $true
        }
        [void][WinProbe]::EnumChildWindows($h, $ccb, [IntPtr]::Zero)
        [void]$script:foundList.Add([pscustomobject]@{
          hwnd     = ('0x{0:X}' -f $h.ToInt64())
          class    = $cls
          title    = (Get-WinText $h)
          visible  = [WinProbe]::IsWindowVisible($h)
          pid      = $wpid
          process  = (Get-ProcName $wpid)
          children = $script:childList.ToArray()
        })
      }
    } catch {}
    return $true
  }
  [void][WinProbe]::EnumWindows($cb, [IntPtr]::Zero)
  return $script:foundList
}

$start = Get-Date
$deadline = $start.AddSeconds($DurationSec)
$prevKey = ''
$lastBeat = Get-Date
"=== watch_dialogs start $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') duration=${DurationSec}s interval=${IntervalMs}ms ===" |
  Out-File -FilePath $LogPath -Append -Encoding UTF8

while ((Get-Date) -lt $deadline) {
  try {
    $snap = Get-DialogSnapshot
    $key = ($snap | ForEach-Object { "$($_.hwnd)|$($_.title)|$($_.children -join ',')" }) -join ';;'
    if ($key -ne $prevKey) {
      $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
      if ($snap.Count -eq 0) {
        $head = "[$ts] DIALOGS=0 (none)  <-- changed"
      } else {
        $head = "[$ts] DIALOGS=$($snap.Count)  <-- changed"
      }
      $head | Out-File -FilePath $LogPath -Append -Encoding UTF8
      foreach ($d in $snap) {
        "  hwnd=$($d.hwnd) class=$($d.class) visible=$($d.visible) pid=$($d.pid) proc=$($d.process)" |
          Out-File -FilePath $LogPath -Append -Encoding UTF8
        "    title=[$($d.title)]" | Out-File -FilePath $LogPath -Append -Encoding UTF8
        foreach ($c in $d.children) {
          "    child=[$c]" | Out-File -FilePath $LogPath -Append -Encoding UTF8
        }
      }
      $prevKey = $key
    }

    # auto-dismiss our own self-test dialog so it cannot block the run
    foreach ($d in $snap) {
      if ($d.title -match 'PROBE SELFTEST') {
        $h = [IntPtr][Convert]::ToInt64($d.hwnd, 16)
        [void][WinProbe]::PostMessage($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)  # WM_CLOSE
        "[$(Get-Date -Format 'HH:mm:ss.fff')] closed self-test dialog $($d.hwnd)" |
          Out-File -FilePath $LogPath -Append -Encoding UTF8
      }
    }
  } catch {
    "[$(Get-Date -Format 'HH:mm:ss.fff')] WATCH-ERROR $_" | Out-File -FilePath $LogPath -Append -Encoding UTF8
  }

  if (((Get-Date) - $lastBeat).TotalSeconds -ge 30) {
    $lastBeat = Get-Date
    $alive = @(Get-Process IDMan -ErrorAction SilentlyContinue).Count
    "[$(Get-Date -Format 'HH:mm:ss.fff')] heartbeat elapsed=$([int]((Get-Date) - $start).TotalSeconds)s IDManProcs=$alive" |
      Out-File -FilePath $LogPath -Append -Encoding UTF8
  }
  Start-Sleep -Milliseconds $IntervalMs
}

"=== watch_dialogs end $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') ===" |
  Out-File -FilePath $LogPath -Append -Encoding UTF8
