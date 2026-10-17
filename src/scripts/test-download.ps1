# Reproduce the expired-trial behaviour with a real download against a local HTTP server.
$ErrorActionPreference = "Continue"
$w = "D:\pojie应用\jiesuo\work\idm-6.43b8"
$dl = Join-Path $w "dltest"
$out = Join-Path $w "dlout"
New-Item -ItemType Directory -Force -Path $dl, $out | Out-Null

# 5 MB test payload
$tf = Join-Path $dl "test.bin"
if (-not (Test-Path $tf) -or (Get-Item $tf).Length -ne 5MB) {
    $buf = New-Object byte[] (5MB)
    (New-Object Random 1234).NextBytes($buf)
    [System.IO.File]::WriteAllBytes($tf, $buf)
}
Write-Output "payload: $tf  ($((Get-Item $tf).Length) bytes)"

# local HTTP server
Get-Job -Name idmhttp -ErrorAction SilentlyContinue | Remove-Job -Force
$py = "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"
Start-Job -Name idmhttp -ScriptBlock {
    param($pydir, $dir)
    Set-Location $dir
    & $pydir -m http.server 8899 --bind 127.0.0.1
} -ArgumentList $py, $dl | Out-Null
Start-Sleep -Seconds 2
try { $r = Invoke-WebRequest "http://127.0.0.1:8899/test.bin" -Method Head -TimeoutSec 5; Write-Output "server OK: $($r.StatusCode) len=$($r.Headers['Content-Length'])" }
catch { Write-Output "server check failed: $_" }

# clean previous output + kill IDM
Remove-Item (Join-Path $out "test.bin") -Force -ErrorAction SilentlyContinue
Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "killing IDMan pid=$($_.Id)"; $_.Kill() }
Start-Sleep -Seconds 2

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class W3 {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
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

function Dump([int]$targetPid) {
  $res = New-Object System.Collections.ArrayList
  $cb = [W3+EnumProc]{
    param($h, $p)
    $pp = 0; [void][W3]::GetWindowThreadProcessId($h, [ref]$pp)
    if ($pp -eq $targetPid -and [W3]::IsWindowVisible($h)) {
      $t = [W3]::T($h); $c = [W3]::C($h)
      [void]$res.Add("  [$c] $t")
      $cb2 = [W3+EnumProc]{ param($ch,$q)
        if ([W3]::IsWindowVisible($ch)) { $ct=[W3]::T($ch); if($ct){ [void]$res.Add("      child[$([W3]::C($ch))] $ct") } }
        return $true }
      [void][W3]::EnumChildWindows($h, $cb2, [IntPtr]::Zero)
    }
    return $true
  }
  [void][W3]::EnumWindows($cb, [IntPtr]::Zero)
  return $res
}

Write-Output "`n=== launching IDM download ==="
$url = "http://127.0.0.1:8899/test.bin"
$p = Start-Process -FilePath "C:\Program Files (x86)\Internet Download Manager\IDMan.exe" `
     -ArgumentList @("/d", $url, "/p", $out, "/f", "test.bin") -PassThru
Write-Output "IDMan pid=$($p.Id)"

for ($i = 1; $i -le 8; $i++) {
  Start-Sleep -Seconds 3
  Write-Output "`n--- t=$($i*3)s ---"
  if ($p.HasExited) { Write-Output "IDMan exited (code=$($p.ExitCode))"; break }
  Dump $p.Id
  $f = Join-Path $out "test.bin"
  if (Test-Path $f) { Write-Output "  >>> downloaded: $((Get-Item $f).Length) bytes" }
}
$f = Join-Path $out "test.bin"
Write-Output "`n=== final ==="
Write-Output "downloaded: $(Test-Path $f) $(if(Test-Path $f){(Get-Item $f).Length}else{0}) bytes"
