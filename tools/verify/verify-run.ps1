<#
  verify-run.ps1 - cold-start soak harness for the IDM b15 P1..P6 patch set.

  For each run: kill IDM -> clear MData -> launch -> poll until SOAK seconds or
  process exit.  Records survival time, every top-level window ever observed
  (class + title + visibility), and every MData appearance.

  Run ELEVATED (clears HKLM CLSID values, kills processes).
#>
param(
  [string]$Mode = 'with-serial',
  [int]$Runs = 5,
  [int]$SoakSeconds = 300,
  [int]$PollMs = 1000,
  [string]$OutDir = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify'
)
$ErrorActionPreference = 'Continue'
$EXE = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log   = Join-Path $OutDir ("soak-$Mode-$stamp.log")
$csv   = Join-Path $OutDir ("soak-$Mode-$stamp.csv")
function W($m){ $m | Tee-Object -FilePath $log -Append }

# ---------------------------------------------------------------- Win32 helper
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class W32 {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public static string T(IntPtr h){ var sb=new StringBuilder(4096); GetWindowTextW(h,sb,4096); return sb.ToString(); }
  public static string C(IntPtr h){ var sb=new StringBuilder(512); GetClassNameW(h,sb,512); return sb.ToString(); }
}
"@
function Get-Windows([int]$targetPid){
  $res = New-Object System.Collections.ArrayList
  $cb = [W32+EnumProc]{
    param($h,$p)
    $pp=0; [void][W32]::GetWindowThreadProcessId($h,[ref]$pp)
    if($pp -eq $targetPid){
      [void]$res.Add([pscustomobject]@{ H=[IntPtr]$h; Cls=[W32]::C($h); Txt=[W32]::T($h); Vis=[W32]::IsWindowVisible($h) })
    }
    return $true
  }
  [void][W32]::EnumWindows($cb,[IntPtr]::Zero)
  return $res
}

# --------------------------------------------------------------- MData helpers
$TREES = @('HKCU:\Software\Classes\CLSID','HKCU:\Software\Classes\Wow6432Node\CLSID',
           'HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID')
function Get-MDataHits {
  $hits = New-Object System.Collections.ArrayList
  foreach($t in $TREES){
    if(-not (Test-Path $t)){ continue }
    Get-ChildItem $t -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      $pr = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
      if($pr -and ($pr.PSObject.Properties.Name -contains 'MData')){
        [void]$hits.Add([pscustomobject]@{ Path=$_.Name; Len=($pr.MData).Length })
      }
    }
  }
  return $hits
}
function Clear-MData {
  $n=0
  foreach($t in $TREES){
    if(-not (Test-Path $t)){ continue }
    Get-ChildItem $t -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      $pr = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
      if($pr -and ($pr.PSObject.Properties.Name -contains 'MData')){
        try{ Remove-ItemProperty -Path $_.PSPath -Name 'MData' -Force -ErrorAction Stop; $script:n++ }catch{}
      }
    }
  }
  return $script:n
}

$COUNTERFEIT = '假冒|counterfeit|正在退出|is exiting|序列号被用来|Serial Number'
$results = New-Object System.Collections.ArrayList
"mode,run,survival_s,alive_at_soak,exit_code,popup_seen,mdata_hits,mdata_cleared_before" | Out-File -FilePath $csv -Encoding utf8

W ("=== SOAK mode={0} runs={1} soak={2}s  {3} ===" -f $Mode,$Runs,$SoakSeconds,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("elevated = {0}" -f ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

for($run=1; $run -le $Runs; $run++){
  W ""
  W ("########## mode=$Mode run=$run/$Runs  {0} ##########" -f (Get-Date -Format 'HH:mm:ss'))

  # ---- clean state
  Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
  Start-Sleep -Seconds 2
  $cleared = Clear-MData
  $pre = @(Get-MDataHits).Count
  W ("pre-run: MData cleared={0}  MData present after clear={1}" -f $cleared,$pre)

  # ---- launch
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p  = Start-Process -FilePath $EXE -PassThru
  $pidIdm = $p.Id
  W ("launched pid={0} at {1}" -f $pidIdm,(Get-Date -Format 'HH:mm:ss'))

  $seen   = @{}          # window signature -> first-seen elapsed
  $popup  = $false
  $mdataEver = 0
  $mdataFirst = $null
  $alive  = $true
  $exitCode = $null
  $lastLog = -10

  while($sw.Elapsed.TotalSeconds -lt $SoakSeconds){
    Start-Sleep -Milliseconds $PollMs
    $el = $sw.Elapsed.TotalSeconds

    # windows
    try{
      foreach($w in (Get-Windows $pidIdm)){
        $sig = "{0}|{1}|{2}" -f $w.Cls,$w.Txt,$w.Vis
        if(-not $seen.ContainsKey($sig)){ $seen[$sig] = [math]::Round($el,1) }
        if($w.Vis -and $w.Cls -eq '#32770' -and $w.Txt -match $COUNTERFEIT){ $popup = $true }
      }
    }catch{}

    # mdata
    try{
      $h = @(Get-MDataHits)
      if($h.Count -gt 0){
        $mdataEver += $h.Count
        if($null -eq $mdataFirst){ $mdataFirst = [math]::Round($el,1); W ("  !! MData APPEARED at {0}s : {1}" -f $mdataFirst,($h | ForEach-Object {$_.Path}) -join '; ') }
      }
    }catch{}

    # process liveness
    $p.Refresh()
    if($p.HasExited){ $alive=$false; $exitCode=$p.ExitCode; W ("  !! IDMan.exe EXITED at {0}s code={1}" -f [math]::Round($el,1),$exitCode); break }

    if(($el - $lastLog) -ge 30){ $lastLog=$el; W ("  t={0,5}s alive  mdata={1}" -f [math]::Round($el,0),$mdataEver) }
  }
  $survival = [math]::Round($sw.Elapsed.TotalSeconds,1)
  $sw.Stop()

  # final window dump
  $finalWins = @()
  if($alive){ try{ $finalWins = @(Get-Windows $pidIdm) }catch{} }
  W ("--- final window list (alive={0}) ---" -f $alive)
  if($finalWins.Count -eq 0){ W "  (none)" }
  foreach($w in $finalWins){ W ("  hwnd=0x{0:X} vis={1,-5} class='{2}' title='{3}'" -f $w.H.ToInt64(),$w.Vis,$w.Cls,$w.Txt) }
  W ("--- every distinct window observed during run ---")
  foreach($k in ($seen.Keys | Sort-Object { $seen[$_] })){
    $parts=$k.Split('|'); W ("  t={0,6}s vis={1,-5} class='{2}' title='{3}'" -f $seen[$k],$parts[2],$parts[0],$parts[1])
  }
  W ("RESULT run={0} survival={1}s alive_at_soak={2} exit={3} popup={4} mdata={5}" -f $run,$survival,$alive,$exitCode,$popup,$mdataEver)

  [void]$results.Add([pscustomobject]@{ mode=$Mode; run=$run; survival=$survival; alive=$alive; exit=$exitCode; popup=$popup; mdata=$mdataEver; cleared=$cleared })
  "{0},{1},{2},{3},{4},{5},{6},{7}" -f $Mode,$run,$survival,$alive,$exitCode,$popup,$mdataEver,$cleared | Out-File -FilePath $csv -Append -Encoding utf8

  Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
  Start-Sleep -Seconds 3
}
W ""
W "=== SUMMARY mode=$Mode ==="
$results | Format-Table -AutoSize | Out-String | ForEach-Object { W $_ }
W ("log={0}" -f $log)
W ("csv={0}" -f $csv)
