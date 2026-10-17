param(
    [string]$Exe = "C:\Program Files (x86)\Internet Download Manager\IDMan.exe",
    [string]$Label = "run",
    [int]$Cmd = 0x8012,
    [string]$ShotDir = "D:\pojie应用\jiesuo\work\idm-6.43b8\shots"
)
# Launch IDMan, dismiss tip, open a menu command, then read the dialog's text via
# UI Automation (works for the IE-hosted HTML dialogs) and also grab a topmost screenshot.
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $ShotDir | Out-Null
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class C2 {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string T(IntPtr h){ var sb=new StringBuilder(8192); GetWindowTextW(h,sb,8192); return sb.ToString(); }
  public static string C(IntPtr h){ var sb=new StringBuilder(512); GetClassNameW(h,sb,512); return sb.ToString(); }
}
"@

function Get-Wins([int]$targetPid, [bool]$vis) {
    $res = New-Object System.Collections.ArrayList
    $cb = [C2+EnumProc]{
        param($h, $p)
        $pp = 0; [void][C2]::GetWindowThreadProcessId($h, [ref]$pp)
        if ($pp -eq $targetPid -and ((-not $vis) -or [C2]::IsWindowVisible($h))) {
            [void]$res.Add([pscustomobject]@{ H=[IntPtr]$h; Cls=[C2]::C($h); Txt=[C2]::T($h) })
        }
        return $true
    }
    [void][C2]::EnumWindows($cb, [IntPtr]::Zero)
    return $res
}

function Read-Uia([IntPtr]$hwnd, [int]$depth, [int]$max) {
    if ($depth -gt $max) { return }
    $el = $null
    try { $el = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd) } catch { }
    if ($el -eq $null) { Write-Output ("{0}(uia: no element)" -f ("  " * $depth)); return }
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    $child = $walker.GetFirstChild($el)
    $n = 0
    while ($child -ne $null -and $n -lt 200) {
        $name = ""
        try { $name = $child.Current.Name } catch { }
        $ctype = ""
        try { $ctype = $child.Current.ControlType.ProgrammaticName } catch { }
        $val = ""
        try {
            $vp = $child.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
            if ($vp) { $val = $vp.Current.Value }
        } catch { }
        if ($name -or $val) {
            Write-Output ("{0}{1} | name='{2}' value='{3}'" -f ("  " * $depth), $ctype, $name, $val)
        }
        Read-Uia $child.Current.NativeWindowHandle ($depth + 1) $max
        $child = $walker.GetNextSibling($child)
        $n++
    }
}

Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
Start-Sleep -Seconds 3
Write-Output "############ $Label  (cmd=0x$('{0:X}' -f $Cmd))"
$p = Start-Process -FilePath $Exe -PassThru
Start-Sleep -Seconds 6
$p.Refresh(); if ($p.HasExited) { Write-Output "EXITED code=$($p.ExitCode)"; return }

foreach ($wd in (Get-Wins $p.Id $true)) {
    if ($wd.Txt -match "每日提示|Tip") { [void][C2]::PostMessageW($wd.H, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero); Write-Output "closed tip" }
}
Start-Sleep -Seconds 3

$main = $null
for ($i = 0; $i -lt 15 -and -not $main; $i++) {
    $main = (Get-Wins $p.Id $true | Where-Object { $_.Cls -eq "#32770" -and $_.Txt -like "*Internet Download Manager*" } | Select-Object -First 1)
    if (-not $main) { Start-Sleep -Seconds 1 }
}
if (-not $main) { Write-Output "!! no main window"; return }

$before = @(Get-Wins $p.Id $true | ForEach-Object { $_.H.ToInt64() })
[void][C2]::PostMessageW($main.H, 0x0111, [IntPtr]$Cmd, [IntPtr]::Zero)

$dlgs = @()
for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Seconds 1
    $dlgs = @(Get-Wins $p.Id $true | Where-Object { $_.H -ne $main.H -and ($before -notcontains $_.H.ToInt64()) })
    if ($dlgs.Count -gt 0) { break }
}
if ($dlgs.Count -eq 0) { Write-Output "!! no dialog opened"; return }
$target = $dlgs | Select-Object -First 1
Write-Output "dialog: '$($target.Txt)'  hwnd=0x$('{0:X}' -f $target.H.ToInt64())"

Write-Output "`n=== UI Automation text ==="
Read-Uia $target.H 0 6

Write-Output "`n=== screenshot (topmost) ==="
[void][C2]::SetWindowPos($target.H, [IntPtr](-1), 0,0,0,0, 0x0043)  # HWND_TOPMOST|NOMOVE|NOSIZE|SHOWWINDOW
Start-Sleep -Seconds 2
$r = New-Object C2+RECT
[void][C2]::GetWindowRect($target.H, [ref]$r)
$wd = $r.R - $r.L; $ht = $r.B - $r.T
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$bmp = New-Object System.Drawing.Bitmap($wd, $ht)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size($wd, $ht)))
$g.Dispose()
$out = Join-Path $ShotDir ("uia-{0}-{1}.png" -f $Label, (Get-Date -Format "HHmmss"))
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
[void][C2]::SetWindowPos($target.H, [IntPtr](-2), 0,0,0,0, 0x0043)  # HWND_NOTOPMOST
Write-Output "screenshot: $out"
