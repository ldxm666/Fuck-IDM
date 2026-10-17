param(
    [string]$Exe = "C:\Program Files (x86)\Internet Download Manager\IDMan_test.exe",
    [string]$Label = "final",
    [int]$Seconds = 75
)
# End-to-end check: serve a local file, drive a real IDM download with the patched build,
# and watch every window/dialog for trial nags while verifying the bytes land on disk.
$ErrorActionPreference = "Continue"
$w = "D:\pojie应用\jiesuo\work\idm-6.43b8"
$dl = Join-Path $w "dltest"; $out = Join-Path $w "dlout"
New-Item -ItemType Directory -Force -Path $dl, $out | Out-Null
$py = "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"

$tf = Join-Path $dl "test.bin"
if (-not (Test-Path $tf)) {
    $buf = New-Object byte[] (5MB); (New-Object Random 1234).NextBytes($buf)
    [System.IO.File]::WriteAllBytes($tf, $buf)
}
$expect = (Get-Item $tf).Length

Get-Job -Name idmhttp -ErrorAction SilentlyContinue | Remove-Job -Force
Start-Job -Name idmhttp -ScriptBlock { param($pydir,$dir) Set-Location $dir; & $pydir -m http.server 8899 --bind 127.0.0.1 } -ArgumentList $py, $dl | Out-Null
Start-Sleep -Seconds 2

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class FV {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public static string T(IntPtr h){ var sb=new StringBuilder(4096); GetWindowTextW(h,sb,4096); return sb.ToString(); }
  public static string C(IntPtr h){ var sb=new StringBuilder(512); GetClassNameW(h,sb,512); return sb.ToString(); }
}
"@

function Snap([int]$targetPid) {
  $rows = New-Object System.Collections.ArrayList
  $cb = [FV+EnumProc]{
    param($h,$p)
    $pp=0; [void][FV]::GetWindowThreadProcessId($h,[ref]$pp)
    if ($pp -eq $targetPid -and [FV]::IsWindowVisible($h)) {
      [void]$rows.Add(("[{0}] {1}" -f [FV]::C($h), [FV]::T($h)))
      $cb2=[FV+EnumProc]{ param($ch,$q) $t=[FV]::T($ch); if($t){ [void]$rows.Add("    child: $t") }; return $true }
      [void][FV]::EnumChildWindows($h,$cb2,[IntPtr]::Zero)
    }
    return $true }
  [void][FV]::EnumWindows($cb,[IntPtr]::Zero)
  return $rows
}

Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "IDMan*" } | ForEach-Object { try{$_.Kill()}catch{} }
Start-Sleep -Seconds 3
Remove-Item (Join-Path $out "test.bin") -Force -ErrorAction SilentlyContinue

Write-Output "############ $Label   exe=$Exe"
$p = Start-Process -FilePath $Exe -ArgumentList @("/d","http://127.0.0.1:8899/test.bin","/p",$out,"/f","test.bin","/n") -PassThru
Write-Output "pid=$($p.Id)  expecting $expect bytes"

$seen = @{}
$done = $false
for ($i = 1; $i -le $Seconds; $i++) {
  Start-Sleep -Seconds 1
  $f = Join-Path $out "test.bin"
  foreach ($r in (Snap $p.Id)) { if (-not $seen.ContainsKey($r)) { $seen[$r] = $i; Write-Output "  t=${i}s NEW  $r" } }
  if ((Test-Path $f) -and (Get-Item $f).Length -eq $expect) { Write-Output "  t=${i}s >>> download complete ($expect bytes)"; $done = $true; break }
}
$f = Join-Path $out "test.bin"
$got = if (Test-Path $f) { (Get-Item $f).Length } else { 0 }
Write-Output "`n=== RESULT ==="
Write-Output "downloaded : $done  ($got / $expect bytes)"
Write-Output "hash match : $((Get-FileHash $f -Algorithm SHA256).Hash -eq (Get-FileHash $tf -Algorithm SHA256).Hash)"
Write-Output "windows seen during run:"
$seen.Keys | Sort-Object | ForEach-Object { Write-Output "   $_" }
$p.Refresh(); Write-Output "IDMan alive: $(-not $p.HasExited)"
