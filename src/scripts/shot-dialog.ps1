param(
    [string]$Exe = "C:\Program Files (x86)\Internet Download Manager\IDMan.exe",
    [string]$Label = "run",
    [int]$Cmd = 0x8012,
    [string]$ShotDir = "D:\pojie应用\jiesuo\work\idm-6.43b8\shots"
)
# Launch IDMan, dismiss Tip-of-the-Day, send a menu command, foreground the resulting
# dialog and screenshot just that window.
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $ShotDir | Out-Null

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class B {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string T(IntPtr h){ var sb=new StringBuilder(8192); GetWindowTextW(h,sb,8192); return sb.ToString(); }
  public static string C(IntPtr h){ var sb=new StringBuilder(512); GetClassNameW(h,sb,512); return sb.ToString(); }
}
"@

function Get-Wins([int]$targetPid, [bool]$vis) {
    $res = New-Object System.Collections.ArrayList
    $cb = [B+EnumProc]{
        param($h, $p)
        $pp = 0; [void][B]::GetWindowThreadProcessId($h, [ref]$pp)
        if ($pp -eq $targetPid -and ((-not $vis) -or [B]::IsWindowVisible($h))) {
            [void]$res.Add([pscustomobject]@{ H=[IntPtr]$h; Cls=[B]::C($h); Txt=[B]::T($h) })
        }
        return $true
    }
    [void][B]::EnumWindows($cb, [IntPtr]::Zero)
    return $res
}

Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
Start-Sleep -Seconds 3
Write-Output "############ $Label"
$p = Start-Process -FilePath $Exe -PassThru
Start-Sleep -Seconds 6
$p.Refresh(); if ($p.HasExited) { Write-Output "EXITED code=$($p.ExitCode)"; return }

foreach ($wd in (Get-Wins $p.Id $true)) {
    if ($wd.Txt -match "每日提示|Tip") { [void][B]::PostMessageW($wd.H, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero); Write-Output "closed tip" }
}
Start-Sleep -Seconds 3

$main = $null
for ($i = 0; $i -lt 15 -and -not $main; $i++) {
    $main = (Get-Wins $p.Id $true | Where-Object { $_.Cls -eq "#32770" -and $_.Txt -like "*Internet Download Manager*" } | Select-Object -First 1)
    if (-not $main) { Start-Sleep -Seconds 1 }
}
if (-not $main) { Write-Output "!! no main window; windows seen:"; Get-Wins $p.Id $false | ForEach-Object { Write-Output ("   [{0}] '{1}'" -f $_.Cls, $_.Txt) }; return }
Write-Output "main hwnd=0x$('{0:X}' -f $main.H.ToInt64())"

$before = @(Get-Wins $p.Id $true | Where-Object { $_.H -ne $main.H } | ForEach-Object { $_.H.ToInt64() })
[void][B]::PostMessageW($main.H, 0x0111, [IntPtr]$Cmd, [IntPtr]::Zero)

$dlgs = @()
for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Seconds 1
    $dlgs = @(Get-Wins $p.Id $true | Where-Object { $_.H -ne $main.H -and ($before -notcontains $_.H.ToInt64()) })
    if ($dlgs.Count -gt 0) { break }
}
Write-Output "dialogs now open:"
foreach ($d in $dlgs) { Write-Output ("   [{0}] '{1}' hwnd=0x{2:X}" -f $d.Cls, $d.Txt, $d.H.ToInt64()) }
if ($dlgs.Count -eq 0) { Write-Output "!! no dialog opened (cmd 0x$('{0:X}' -f $Cmd))"; return }
$target = $dlgs | Select-Object -First 1

[void][B]::ShowWindow($target.H, 5)
[void][B]::BringWindowToTop($target.H)
[void][B]::SetForegroundWindow($target.H)
Start-Sleep -Seconds 2

$r = New-Object B+RECT
[void][B]::GetWindowRect($target.H, [ref]$r)
$wd = $r.R - $r.L; $ht = $r.B - $r.T
Write-Output "rect: $($r.L),$($r.T) ${wd}x${ht}"

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$out = Join-Path $ShotDir ("dialog-{0}-{1}.png" -f $Label, (Get-Date -Format "HHmmss"))

# PrintWindow grabs the window's own rendering regardless of z-order.
$bmp = New-Object System.Drawing.Bitmap($wd, $ht)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok = [B]::PrintWindow($target.H, $hdc, 2)   # PW_RENDERFULLCONTENT
$g.ReleaseHdc($hdc)
$g.Dispose()
if (-not $ok) {
    Write-Output "PrintWindow failed; falling back to screen grab"
    $bmp2 = New-Object System.Drawing.Bitmap($wd, $ht)
    $g2 = [System.Drawing.Graphics]::FromImage($bmp2)
    $g2.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size($wd, $ht)))
    $g2.Dispose(); $bmp.Dispose(); $bmp = $bmp2
}
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "screenshot: $out"
