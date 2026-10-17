<#
  verify-run2.ps1 - cold-start soak harness v2 (fixed) for IDM b15 P1..P6.

  v2 fixes vs v1:
    * MData polling uses the 5 CLSID GUIDs IDM actually references (targeted
      RegistryKey opens) instead of a recursive Get-ChildItem over the whole
      CLSID tree.  v1's scan took ~30s/iteration, so a 300s soak got only ~9
      samples and could miss a write entirely.
    * a nonzero exit code is recorded as CRASH (not just a number)
    * Clear-MData returns a real count
  Run ELEVATED.
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
$log = Join-Path $OutDir ("soak2-$Mode-$stamp.log")
$csv = Join-Path $OutDir ("soak2-$Mode-$stamp.csv")
function W($m){ $m | Tee-Object -FilePath $log -Append }

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
    if($pp -eq $targetPid){ [void]$res.Add([pscustomobject]@{ H=[IntPtr]$h; Cls=[W32]::C($h); Txt=[W32]::T($h); Vis=[W32]::IsWindowVisible($h) }) }
    return $true
  }
  [void][W32]::EnumWindows($cb,[IntPtr]::Zero)
  return $res
}

# ---- MData: the 5 GUIDs IDMan.exe actually references (patches/mdata-writer-static.md)
$GUIDS = @('{E6871B76-C3C8-44DD-B947-ABFFE144860D}','{84797876-C678-1780-A556-0CD06786780F}',
           '{6DDF00DB-1234-46EC-8356-27E7B2051192}','{79873CC5-3951-43ED-BDF9-D8759474B6FD}',
           '{07999AC3-058B-40BF-984F-69EB1E554CA7}')
$ROOTS = @(
  @([Microsoft.Win32.Registry]::CurrentUser, 'Software\Classes\CLSID','HKCU\CLSID'),
  @([Microsoft.Win32.Registry]::CurrentUser, 'Software\Classes\Wow6432Node\CLSID','HKCU\Wow'),
  @([Microsoft.Win32.Registry]::LocalMachine,'SOFTWARE\Classes\CLSID','HKLM\CLSID'),
  @([Microsoft.Win32.Registry]::LocalMachine,'SOFTWARE\Classes\WOW6432Node\CLSID','HKLM\Wow')
)
function Get-MDataFast {
  $hits = New-Object System.Collections.ArrayList
  foreach($r in $ROOTS){
    $hive=$r[0]; $base=$r[1]; $tag=$r[2]
    foreach($g in $GUIDS){
      $k=$null
      try{ $k=$hive.OpenSubKey("$base\$g") }catch{ continue }
      if($k -eq $null){ continue }
      try{
        if($k.GetValueNames() -contains 'MData'){
          $v=$k.GetValue('MData')
          [void]$hits.Add([pscustomobject]@{ Path="$tag\$g"; Len=if($v -is [byte[]]){$v.Length}else{-1} })
        }
      }catch{}
      try{ $k.Close() }catch{}
    }
  }
  return $hits
}
function Clear-MDataFast {
  $n=0
  foreach($r in $ROOTS){
    $hive=$r[0]; $base=$r[1]
    foreach($g in $GUIDS){
      $k=$null
      try{ $k=$hive.OpenSubKey("$base\$g",$true) }catch{ continue }
      if($k -eq $null){ continue }
      try{ if($k.GetValueNames() -contains 'MData'){ $k.DeleteValue('MData',$false); $n++ } }catch{}
      try{ $k.Close() }catch{}
    }
  }
  return $n
}
# recursive catch-all (slow, used once per mode)
$TREES=@('HKCU:\Software\Classes\CLSID','HKCU:\Software\Classes\Wow6432Node\CLSID',
         'HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID')
function Clear-MDataDeep {
  $n=0
  foreach($t in $TREES){
    if(-not (Test-Path $t)){ continue }
    Get-ChildItem $t -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      $pr = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
      if($pr -and ($pr.PSObject.Properties.Name -contains 'MData')){
        try{ Remove-ItemProperty -Path $_.PSPath -Name 'MData' -Force -ErrorAction Stop; $n++ }catch{}
      }
    }
  }
  return $n
}

$COUNTERFEIT = '假冒|counterfeit|正在退出|is exiting|序列号被用来|Serial Number'
"mode,run,survival_s,outcome,exit_code_hex,popup_seen,mdata_hits,samples" | Out-File -FilePath $csv -Encoding utf8
$rows = New-Object System.Collections.ArrayList

W ("=== SOAK v2 mode={0} runs={1} soak={2}s  {3} ===" -f $Mode,$Runs,$SoakSeconds,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("elevated = {0}" -f ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
Start-Sleep -Seconds 2
W ("deep MData clear before mode: {0}" -f (Clear-MDataDeep))

for($run=1; $run -le $Runs; $run++){
  W ""
  W ("########## mode=$Mode run=$run/$Runs  {0} ##########" -f (Get-Date -Format 'HH:mm:ss'))
  Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
  Start-Sleep -Seconds 2
  $cleared = Clear-MDataFast
  $pre = @(Get-MDataFast).Count
  W ("pre-run: fast-cleared={0}  MData present={1}" -f $cleared,$pre)

  $sw=[Diagnostics.Stopwatch]::StartNew()
  $p=Start-Process -FilePath $EXE -PassThru
  $idmPid=$p.Id
  W ("launched pid={0} at {1}" -f $idmPid,(Get-Date -Format 'HH:mm:ss'))

  $seen=@{}; $popup=$false; $mdataHits=0; $samples=0
  $alive=$true; $exitHex=$null; $outcome='UNKNOWN'; $lastLog=-10
  $firstPopupAt=$null

  while($sw.Elapsed.TotalSeconds -lt $SoakSeconds){
    Start-Sleep -Milliseconds $PollMs
    $el=$sw.Elapsed.TotalSeconds; $samples++

    try{
      foreach($w in (Get-Windows $idmPid)){
        $sig="{0}|{1}|{2}" -f $w.Cls,$w.Txt,$w.Vis
        if(-not $seen.ContainsKey($sig)){ $seen[$sig]=[math]::Round($el,1) }
        if($w.Vis -and $w.Cls -eq '#32770' -and $w.Txt -match $COUNTERFEIT){
          $popup=$true; if($null -eq $firstPopupAt){ $firstPopupAt=[math]::Round($el,1) }
        }
      }
    }catch{}

    try{
      $h=@(Get-MDataFast)
      if($h.Count -gt 0){
        $mdataHits += $h.Count
        W ("  !! MData PRESENT at {0}s : {1}" -f [math]::Round($el,1),(($h|ForEach-Object{$_.Path}) -join '; '))
      }
    }catch{}

    $p.Refresh()
    if($p.HasExited){
      $alive=$false
      $ec=$p.ExitCode
      $exitHex = '0x{0:X8}' -f ($ec -band 0xFFFFFFFF)
      if($ec -eq 0){ $outcome='clean-exit-0' } else { $outcome="CRASH/selfkill $exitHex" }
      W ("  !! IDMan.exe DIED at {0}s  exitcode={1} ({2})  <<< {3}" -f [math]::Round($el,1),$ec,$exitHex,$outcome)
      break
    }
    if(($el-$lastLog) -ge 60){ $lastLog=$el; W ("  t={0,4}s alive  mdata={1}  samples={2}" -f [math]::Round($el,0),$mdataHits,$samples) }
  }
  $survival=[math]::Round($sw.Elapsed.TotalSeconds,1); $sw.Stop()
  if($alive){ $outcome='SURVIVED-SOAK' }

  $finalWins=@()
  if($alive){ try{ $finalWins=@(Get-Windows $idmPid) }catch{} }
  W ("--- final window list (alive={0}) ---" -f $alive)
  if($finalWins.Count -eq 0){ W "  (none)" }
  foreach($w in $finalWins){ W ("  hwnd=0x{0:X} vis={1,-5} class='{2}' title='{3}'" -f $w.H.ToInt64(),$w.Vis,$w.Cls,$w.Txt) }
  W "--- every distinct window observed (class|title|visible -> first seen) ---"
  foreach($k in ($seen.Keys | Sort-Object { $seen[$_] })){
    $q=$k.Split('|'); W ("  t={0,6}s vis={1,-5} class='{2}' title='{3}'" -f $seen[$k],$q[2],$q[0],$q[1])
  }
  W ("RESULT run={0} survival={1}s outcome={2} popup={3} (first@{4}s) mdata_hits={5} samples={6}" -f $run,$survival,$outcome,$popup,$firstPopupAt,$mdataHits,$samples)
  [void]$rows.Add([pscustomobject]@{mode=$Mode;run=$run;survival=$survival;outcome=$outcome;popup=$popup;mdata=$mdataHits})
  "{0},{1},{2},{3},{4},{5},{6},{7}" -f $Mode,$run,$survival,$outcome,$exitHex,$popup,$mdataHits,$samples | Out-File -FilePath $csv -Append -Encoding utf8

  Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
  Start-Sleep -Seconds 3
}
W ""
W "=== SUMMARY mode=$Mode ==="
$rows | Format-Table -AutoSize | Out-String | ForEach-Object { W $_ }
W ("csv={0}" -f $csv)
