param(
    [string]$Exe = "C:\Program Files (x86)\Internet Download Manager\IDMan.exe",
    [string]$Label = "run"
)
# Launch IDMan, dismiss Tip-of-the-Day, then open About (0x8012) and Registration (0x800F)
# and dump every dialog's child text so we can read Full/Trial and the registration state.
$ErrorActionPreference = "Continue"

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class A {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  public static string T(IntPtr h){ var sb=new StringBuilder(8192); GetWindowTextW(h,sb,8192); return sb.ToString(); }
  public static string C(IntPtr h){ var sb=new StringBuilder(512); GetClassNameW(h,sb,512); return sb.ToString(); }
}
"@

function Get-Wins([int]$targetPid, [bool]$vis) {
    $res = New-Object System.Collections.ArrayList
    $cb = [A+EnumProc]{
        param($h, $p)
        $pp = 0; [void][A]::GetWindowThreadProcessId($h, [ref]$pp)
        if ($pp -eq $targetPid -and ((-not $vis) -or [A]::IsWindowVisible($h))) {
            [void]$res.Add([pscustomobject]@{ H=[IntPtr]$h; Cls=[A]::C($h); Txt=[A]::T($h) })
        }
        return $true
    }
    [void][A]::EnumWindows($cb, [IntPtr]::Zero)
    return $res
}

function Dump-Wins([int]$targetPid, [string]$tag) {
    Write-Output "--- $tag ---"
    foreach ($wd in (Get-Wins $targetPid $true)) {
        Write-Output ("  DIALOG [{0}] '{1}'" -f $wd.Cls, $wd.Txt)
        $cb = [A+EnumProc]{
            param($h, $p)
            $t = [A]::T($h); $c = [A]::C($h)
            if ($t -ne "") { Write-Output ("      {0}: {1}" -f $c, $t) }
            return $true
        }
        [void][A]::EnumChildWindows($wd.H, $cb, [IntPtr]::Zero)
    }
}

Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
Start-Sleep -Milliseconds 1500

Write-Output "############ LABEL=$Label  EXE=$Exe"
$p = Start-Process -FilePath $Exe -PassThru
Start-Sleep -Seconds 5
$p.Refresh()
Write-Output "pid=$($p.Id) alive=$(-not $p.HasExited)"
if ($p.HasExited) { Write-Output "EXITED code=$($p.ExitCode)"; return }

# dismiss Tip of the Day (每日提示) so the main window is unblocked
foreach ($wd in (Get-Wins $p.Id $true)) {
    if ($wd.Txt -match "每日提示|Tip") {
        Write-Output "closing tip dialog '$($wd.Txt)'"
        [void][A]::PostMessageW($wd.H, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)  # WM_CLOSE
    }
}
Start-Sleep -Seconds 2
Dump-Wins $p.Id "after startup"

$main = (Get-Wins $p.Id $true | Where-Object { $_.Cls -eq "#32770" -and $_.Txt -like "*Internet Download Manager*" } | Select-Object -First 1)
if (-not $main) { Write-Output "!! main window not found"; return }
Write-Output "main hwnd=0x$('{0:X}' -f $main.H.ToInt64())"

Write-Output "`n>>> opening About (WM_COMMAND 0x8012)"
[void][A]::PostMessageW($main.H, 0x0111, [IntPtr]0x8012, [IntPtr]::Zero)
Start-Sleep -Seconds 3
Dump-Wins $p.Id "About dialog"

foreach ($wd in (Get-Wins $p.Id $true)) { if ($wd.H -ne $main.H -and $wd.Txt -notmatch "Internet Download Manager 6.43") { [void][A]::PostMessageW($wd.H, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) } }
Start-Sleep -Seconds 2

Write-Output "`n>>> opening Registration (WM_COMMAND 0x800F)"
[void][A]::PostMessageW($main.H, 0x0111, [IntPtr]0x800F, [IntPtr]::Zero)
Start-Sleep -Seconds 3
Dump-Wins $p.Id "Registration dialog"

Write-Output "`n>>> registry idmvers = $((Get-ItemProperty 'HKCU:\Software\DownloadManager' -Name idmvers -ErrorAction SilentlyContinue).idmvers)"
