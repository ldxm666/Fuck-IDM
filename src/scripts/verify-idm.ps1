param(
    [string]$Exe = "C:\Program Files (x86)\Internet Download Manager\IDMan.exe",
    [int]$WaitMs = 6000,
    [string]$ShotDir = "D:\pojie应用\jiesuo\work\idm-6.43b8\shots"
)
# Launch an IDMan build, dump its windows + menu, open About, read the state text, screenshot.
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $ShotDir | Out-Null

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class U {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetSubMenu(IntPtr m, int pos);
  [DllImport("user32.dll")] public static extern int GetMenuItemCount(IntPtr m);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetMenuStringW(IntPtr m, uint id, StringBuilder s, int n, uint flags);
  [DllImport("user32.dll")] public static extern uint GetMenuItemID(IntPtr m, int pos);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string T(IntPtr h){ var sb=new StringBuilder(4096); GetWindowTextW(h,sb,4096); return sb.ToString(); }
  public static string C(IntPtr h){ var sb=new StringBuilder(512); GetClassNameW(h,sb,512); return sb.ToString(); }
}
"@

function Get-Windows([int]$targetPid, [bool]$visibleOnly) {
    $res = New-Object System.Collections.ArrayList
    $cb = [U+EnumProc]{
        param($h, $p)
        $pp = 0; [void][U]::GetWindowThreadProcessId($h, [ref]$pp)
        if ($pp -eq $targetPid -and ((-not $visibleOnly) -or [U]::IsWindowVisible($h))) {
            [void]$res.Add([pscustomobject]@{ H=[IntPtr]$h; Cls=[U]::C($h); Txt=[U]::T($h) })
        }
        return $true
    }
    [void][U]::EnumWindows($cb, [IntPtr]::Zero)
    return $res
}

function Dump-Tree([int]$targetPid) {
    foreach ($wd in (Get-Windows $targetPid $true)) {
        Write-Output ("  [{0}] {1}   hwnd=0x{2:X}" -f $wd.Cls, $wd.Txt, $wd.H.ToInt64())
        $cb = [U+EnumProc]{
            param($h, $p)
            $t = [U]::T($h)
            if ($t -ne "") { Write-Output ("      child[{0}] {1}" -f [U]::C($h), $t) }
            return $true
        }
        [void][U]::EnumChildWindows($wd.H, $cb, [IntPtr]::Zero)
    }
}

function Dump-Menu([IntPtr]$hMenu, [int]$depth) {
    $n = [U]::GetMenuItemCount($hMenu)
    for ($i = 0; $i -lt $n; $i++) {
        $sb = New-Object System.Text.StringBuilder 256
        $id = [U]::GetMenuItemID($hMenu, $i)
        [void][U]::GetMenuStringW($hMenu, [uint32]$i, $sb, 256, 0x400)  # MF_BYPOSITION
        $pad = "  " * $depth
        Write-Output ("{0}[{1}] id=0x{2:X4} '{3}'" -f $pad, $i, $id, $sb.ToString())
        $sub = [U]::GetSubMenu($hMenu, $i)
        if ($sub -ne [IntPtr]::Zero) { Dump-Menu $sub ($depth + 1) }
    }
}

Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "killing pid=$($_.Id)"; $_.Kill() }
Start-Sleep -Milliseconds 1500

Write-Output "=== launching: $Exe ==="
$p = Start-Process -FilePath $Exe -PassThru
Start-Sleep -Milliseconds $WaitMs
$p.Refresh()
Write-Output "pid=$($p.Id) alive=$(-not $p.HasExited)"
if ($p.HasExited) { Write-Output "EXITED code=$($p.ExitCode)"; exit }

Write-Output "`n=== visible windows ==="
Dump-Tree $p.Id

$main = (Get-Windows $p.Id $true | Where-Object { $_.Cls -eq "#32770" -and $_.Txt -like "*Internet Download Manager*" } | Select-Object -First 1)
if (-not $main) { Write-Output "`n(no main window found)"; exit }
Write-Output "`n=== main window menu ==="
$menu = [U]::GetMenu($main.H)
if ($menu -eq [IntPtr]::Zero) { Write-Output "  (no menu)" } else { Dump-Menu $menu 1 }

# screenshot the main window region via full-screen capture
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$b = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
$g = [System.Drawing.Graphics]::FromImage($b)
$g.CopyFromScreen(0,0,0,0,$b.Size)
$shot = Join-Path $ShotDir ("verify-{0}.png" -f (Get-Date -Format "HHmmss"))
$b.Save($shot, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $b.Dispose()
Write-Output "`nscreenshot: $shot"
