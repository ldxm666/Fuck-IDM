# Watch IDMan's windows over time, log every change to detect delayed nag dialogs.
$ErrorActionPreference = "Continue"
$w = "D:\pojie应用\jiesuo\work\idm-6.43b8"
$log = Join-Path $w "logs\window-watch.log"

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class W32W {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public static string Txt(IntPtr h){ var sb=new StringBuilder(4096); GetWindowTextW(h,sb,4096); return sb.ToString(); }
  public static string Cls(IntPtr h){ var sb=new StringBuilder(512); GetClassNameW(h,sb,512); return sb.ToString(); }
}
"@

function Snapshot {
  $seen = @()
  $pids = @(Get-Process -Name IDMan -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
  if ($pids.Count -eq 0) { return @("<no IDMan process>") }
  $cb = [W32W+EnumProc]{
    param($h, $p)
    $pp = 0
    [void][W32W]::GetWindowThreadProcessId($h, [ref]$pp)
    if ($pids -contains [int]$pp) {
      $t = [W32W]::Txt($h); $c = [W32W]::Cls($h)
      if ($t -ne "" -or $c -eq "#32770") {
        $script:seen += ("{0}|{1}|vis={2}" -f $c, $t, [W32W]::IsWindowVisible($h))
      }
    }
    return $true
  }
  [void][W32W]::EnumWindows($cb, [IntPtr]::Zero)
  return $seen
}

$prev = ""
$deadline = (Get-Date).AddSeconds(240)
while ((Get-Date) -lt $deadline) {
  $snap = (Snapshot | Sort-Object) -join "`n"
  if ($snap -ne $prev) {
    $stamp = Get-Date -Format "HH:mm:ss"
    Add-Content -Path $log -Value "=== $stamp CHANGED ==="
    Add-Content -Path $log -Value $snap
    $prev = $snap
  }
  Start-Sleep -Seconds 3
}
Add-Content -Path $log -Value "=== watch ended $(Get-Date -Format HH:mm:ss) ==="
