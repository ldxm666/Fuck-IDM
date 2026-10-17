<#
  verify-run3.ps1 - cold-start soak harness v3 for IDM b15 P1..P6.

  v3 changes vs v2:
    * popup detection split into TWO independent signals:
        popup_counterfeit   - 假冒/counterfeit/正在退出/is exiting/序列号被用来
        popup_registration  - 注册/Register/Registration
      v2 only matched the counterfeit set, so the visible
      "注册 Internet Download Manager" dialog was scored popup=False.
    * EVERY visible top-level window is recorded with its first-seen time and
      written to the log as raw evidence (class + title + visible + hwnd).
    * nonzero exit is reported as NONZERO-EXIT/CRASH and is a hard failure.
    * records hosts + DNS state at mode start.
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
$log = Join-Path $OutDir ("soak3-$Mode-$stamp.log")
$csv = Join-Path $OutDir ("soak3-$Mode-$stamp.csv")
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
      try{ if($k.GetValueNames() -contains 'MData'){ $val=$k.GetValue('MData'); [void]$hits.Add([pscustomobject]@{Path="$tag\$g"; Len=if($val -is [byte[]]){$val.Length}else{-1}}) } }catch{}
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

$RE_COUNTERFEIT = '假冒|counterfeit|正在退出|is exiting|序列号被用来|Serial Number'
$RE_REGISTRATION = '注册|Register|Registration'

"mode,run,survival_s,outcome,exit_code_hex,popup_counterfeit,popup_registration,popup_other,mdata_hits,samples" | Out-File -FilePath $csv -Encoding utf8
$rows = New-Object System.Collections.ArrayList

W ("=== SOAK v3 mode={0} runs={1} soak={2}s  {3} ===" -f $Mode,$Runs,$SoakSeconds,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("elevated = {0}" -f ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
W ("installed sha256 = {0}" -f (Get-FileHash $EXE -Algorithm SHA256).Hash)

# hosts + DNS state
$HOSTS="$env:SystemRoot\System32\drivers\etc\hosts"
$act=@(); $com=0
foreach($l in (Get-Content -LiteralPath $HOSTS -ErrorAction SilentlyContinue)){
  if($l -match 'PermanentFix'){
    if($l.TrimStart().StartsWith('#')){ $com++ } else { $act += ($l -replace '\s*#.*$','').Trim() }
  }
}
W ("hosts: active marker lines={0} commented={1}" -f $act.Count,$com)
foreach($a in $act){ W ("   ACTIVE: {0}" -f $a) }
foreach($d in 'internetdownloadmanager.com','www.internetdownloadmanager.com','secure.internetdownloadmanager.com','register.internetdownloadmanager.com','tonec.com','www.tonec.com'){
  $ips = try { (Resolve-DnsName $d -Type A -ErrorAction Stop | Where-Object {$_.IPAddress} | ForEach-Object {$_.IPAddress}) -join ',' } catch { 'UNRESOLVED' }
  if(-not $ips){ $ips='UNRESOLVED' }
  W ("   DNS {0,-38} -> {1}" -f $d,$ips)
}
$reg=Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue
W ("registration at mode start: Serial='{0}' FName='{1}' LName='{2}' Email='{3}'" -f $reg.Serial,$reg.FName,$reg.LName,$reg.Email)

for($run=1; $run -le $Runs; $run++){
  W ""
  W ("########## mode=$Mode run=$run/$Runs  {0} ##########" -f (Get-Date -Format 'HH:mm:ss'))
  Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
  Start-Sleep -Seconds 2
  $cleared = Clear-MDataFast
  W ("pre-run: fast-cleared={0}  MData present={1}" -f $cleared,(@(Get-MDataFast).Count))
  $r0=Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue
  W ("pre-run Serial='{0}'" -f $r0.Serial)

  $sw=[Diagnostics.Stopwatch]::StartNew()
  $p=Start-Process -FilePath $EXE -PassThru
  $idmPid=$p.Id
  W ("launched pid={0} at {1}" -f $idmPid,(Get-Date -Format 'HH:mm:ss'))

  $seen=@{}; $popC=$false; $popR=$false; $mdataHits=0; $samples=0
  $alive=$true; $exitHex=''; $outcome='UNKNOWN'; $lastLog=-10
  $popCAt=$null; $popRAt=$null; $visDumps=New-Object System.Collections.ArrayList
  # Third, rename-proof signal: ANY visible #32770 owned by IDMan that is not the
  # main window counts as a popup, whatever its title says.
  $popO=$false; $popOAt=$null; $popOTitles=New-Object System.Collections.ArrayList

  while($sw.Elapsed.TotalSeconds -lt $SoakSeconds){
    Start-Sleep -Milliseconds $PollMs
    $el=$sw.Elapsed.TotalSeconds; $samples++
    try{
      foreach($w in (Get-Windows $idmPid)){
        $sig="{0}|{1}|{2}" -f $w.Cls,$w.Txt,$w.Vis
        if(-not $seen.ContainsKey($sig)){
          $seen[$sig]=[math]::Round($el,1)
          if($w.Vis){ [void]$visDumps.Add(("t={0,7}s hwnd=0x{1:X} class='{2}' title='{3}'" -f [math]::Round($el,1),$w.H.ToInt64(),$w.Cls,$w.Txt)) }
        }
        if($w.Vis -and $w.Cls -eq '#32770'){
          if($w.Txt -match $RE_COUNTERFEIT){ $popC=$true; if($null -eq $popCAt){$popCAt=[math]::Round($el,1)} }
          if($w.Txt -match $RE_REGISTRATION){ $popR=$true; if($null -eq $popRAt){$popRAt=[math]::Round($el,1)} }
          if($w.Txt -notmatch '^Internet Download Manager'){
            $popO=$true
            if($null -eq $popOAt){ $popOAt=[math]::Round($el,1) }
            if(-not $popOTitles.Contains($w.Txt)){ [void]$popOTitles.Add($w.Txt) }
          }
        }
      }
    }catch{}
    try{
      $h=@(Get-MDataFast)
      if($h.Count -gt 0){ $mdataHits += $h.Count; W ("  !! MData PRESENT at {0}s : {1}" -f [math]::Round($el,1),(($h|ForEach-Object{$_.Path}) -join '; ')) }
    }catch{}
    $p.Refresh()
    if($p.HasExited){
      $alive=$false; $ec=$p.ExitCode; $exitHex='0x{0:X8}' -f ($ec -band 0xFFFFFFFF)
      if($ec -eq 0){ $outcome='clean-exit-0' } else { $outcome="NONZERO-EXIT $exitHex (hard failure)" }
      W ("  !! IDMan.exe DIED at {0}s exitcode={1} ({2})  <<< {3}" -f [math]::Round($el,1),$ec,$exitHex,$outcome)
      break
    }
    if(($el-$lastLog) -ge 60){ $lastLog=$el; W ("  t={0,4}s alive mdata={1} samples={2}" -f [math]::Round($el,0),$mdataHits,$samples) }
  }
  $survival=[math]::Round($sw.Elapsed.TotalSeconds,1); $sw.Stop()
  if($alive){ $outcome='SURVIVED-SOAK' }

  W ("--- EVERY visible top-level window observed during run (raw evidence) ---")
  if($visDumps.Count -eq 0){ W "  (none)" }
  foreach($d in $visDumps){ W ("  {0}" -f $d) }
  $fw=@(); if($alive){ try{ $fw=@(Get-Windows $idmPid) }catch{} }
  W ("--- final window list (alive={0}) ---" -f $alive)
  if($fw.Count -eq 0){ W "  (none)" } else { foreach($w in $fw){ W ("  hwnd=0x{0:X} vis={1,-5} class='{2}' title='{3}'" -f $w.H.ToInt64(),$w.Vis,$w.Cls,$w.Txt) } }
  W "--- every distinct window (class|title|visible -> first seen) ---"
  foreach($k in ($seen.Keys | Sort-Object { $seen[$_] })){ $q=$k.Split('|'); W ("  t={0,7}s vis={1,-5} class='{2}' title='{3}'" -f $seen[$k],$q[2],$q[0],$q[1]) }
  W ("RESULT run={0} survival={1}s outcome={2} popup_counterfeit={3}@{4}s popup_registration={5}@{6}s popup_other={7}@{8}s mdata={9} samples={10}" -f $run,$survival,$outcome,$popC,$popCAt,$popR,$popRAt,$popO,$popOAt,$mdataHits,$samples)
  if($popOTitles.Count -gt 0){ W ("   popup_other titles: {0}" -f (($popOTitles | ForEach-Object { "'$_'" }) -join ' | ')) }
  [void]$rows.Add([pscustomobject]@{mode=$Mode;run=$run;survival=$survival;outcome=$outcome;popC=$popC;popR=$popR;popO=$popO;mdata=$mdataHits})
  "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}" -f $Mode,$run,$survival,$outcome,$exitHex,$popC,$popR,$popO,$mdataHits,$samples | Out-File -FilePath $csv -Append -Encoding utf8
  Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
  Start-Sleep -Seconds 3
}
W ""
W "=== SUMMARY mode=$Mode ==="
$rows | Format-Table -AutoSize | Out-String | ForEach-Object { W $_ }
W ("csv={0}" -f $csv)
