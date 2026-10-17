<#
  stale-mdata-download.ps1 - two tests the lead asked for, in one run:
    (A) stale-MData: leave MData in place, cold-start IDM, watch the full SOAK window.
    (B) functional download: drive a real download THROUGH IDM while MData is present,
        then compare sha256 against a reference fetched independently.
  Run ELEVATED.
#>
param(
  [string]$Url = 'https://proof.ovh.net/files/10Mb.dat',
  [string]$FileName = 'ovh-10Mb.dat',
  [int]$SoakSeconds = 300,
  [int]$PollMs = 1000,
  [string]$OutDir = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify'
)
$ErrorActionPreference='Continue'
$EXE='C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$DL=Join-Path $OutDir 'dl'
New-Item -ItemType Directory -Force -Path $DL | Out-Null
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$log=Join-Path $OutDir ("stale-mdata-$stamp.log")
function W($m){ $m | Tee-Object -FilePath $log -Append }
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class W32b {
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
  $res=New-Object System.Collections.ArrayList
  $cb=[W32b+EnumProc]{ param($h,$p)
    $pp=0; [void][W32b]::GetWindowThreadProcessId($h,[ref]$pp)
    if($pp -eq $targetPid){ [void]$res.Add([pscustomobject]@{H=[IntPtr]$h;Cls=[W32b]::C($h);Txt=[W32b]::T($h);Vis=[W32b]::IsWindowVisible($h)}) }
    return $true }
  [void][W32b]::EnumWindows($cb,[IntPtr]::Zero); return $res
}
$GUIDS=@('{E6871B76-C3C8-44DD-B947-ABFFE144860D}','{84797876-C678-1780-A556-0CD06786780F}',
         '{6DDF00DB-1234-46EC-8356-27E7B2051192}','{79873CC5-3951-43ED-BDF9-D8759474B6FD}',
         '{07999AC3-058B-40BF-984F-69EB1E554CA7}')
$ROOTS=@(@([Microsoft.Win32.Registry]::CurrentUser,'Software\Classes\CLSID','HKCU\CLSID'),
         @([Microsoft.Win32.Registry]::CurrentUser,'Software\Classes\Wow6432Node\CLSID','HKCU\Wow'),
         @([Microsoft.Win32.Registry]::LocalMachine,'SOFTWARE\Classes\CLSID','HKLM\CLSID'),
         @([Microsoft.Win32.Registry]::LocalMachine,'SOFTWARE\Classes\WOW6432Node\CLSID','HKLM\Wow'))
function Get-MData {
  $hits=New-Object System.Collections.ArrayList
  foreach($r in $ROOTS){ $hive=$r[0];$base=$r[1];$tag=$r[2]
    foreach($g in $GUIDS){ $k=$null
      try{ $k=$hive.OpenSubKey("$base\$g") }catch{ continue }
      if($k -eq $null){ continue }
      try{ if($k.GetValueNames() -contains 'MData'){ $val=$k.GetValue('MData')
        $sha=''; if($val -is [byte[]]){ $sha=(Get-FileHash -InputStream (New-Object IO.MemoryStream(,$val)) -Algorithm SHA256).Hash }
        [void]$hits.Add([pscustomobject]@{Path="$tag\$g";Len=if($val -is [byte[]]){$val.Length}else{-1};Sha=$sha}) } }catch{}
      try{$k.Close()}catch{} } }
  return $hits
}
W ("=== stale-MData + download test  {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("installed sha256 = {0}" -f (Get-FileHash $EXE -Algorithm SHA256).Hash)
$reg=Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue
W ("registration: Serial='{0}' FName='{1}' LName='{2}'" -f $reg.Serial,$reg.FName,$reg.LName)

# ---- STEP 1: make sure MData EXISTS and LEAVE IT THERE
Get-Process IDMan -ErrorAction SilentlyContinue | ForEach-Object { try{$_.Kill()}catch{} }
Start-Sleep -Seconds 2
$md=@(Get-MData)
if($md.Count -eq 0){
  W "MData absent -> priming: launch IDM until MData appears (max 150s), then kill"
  $pp=Start-Process -FilePath $EXE -PassThru
  $swp=[Diagnostics.Stopwatch]::StartNew()
  while($swp.Elapsed.TotalSeconds -lt 150){ Start-Sleep -Seconds 2; if(@(Get-MData).Count -gt 0){ break } }
  $swp.Stop()
  $md=@(Get-MData)
  W ("priming done: MData present={0} after {1}s" -f $md.Count,[math]::Round($swp.Elapsed.TotalSeconds,1))
  try{ $pp.Kill() }catch{}
  Start-Sleep -Seconds 3
} else { W "MData already present (not cleared)" }
$md=@(Get-MData)
W ("=== PRE-RUN STATE: MData deliberately LEFT IN PLACE ({0} value(s)) ===" -f $md.Count)
foreach($m in $md){ W ("   {0}  len={1}  sha256={2}" -f $m.Path,$m.Len,$m.Sha) }
if($md.Count -eq 0){ W "!! could not establish stale MData; aborting"; exit 1 }

# ---- reference hash fetched WITHOUT IDM
$refFile=Join-Path $DL 'reference.bin'
W ("fetching reference copy (not via IDM): {0}" -f $Url)
try{
  Invoke-WebRequest -Uri $Url -OutFile $refFile -TimeoutSec 120 -UseBasicParsing
  $refHash=(Get-FileHash $refFile -Algorithm SHA256).Hash
  W ("reference: {0} bytes  sha256={1}" -f (Get-Item $refFile).Length,$refHash)
}catch{ W ("reference fetch FAILED: {0}" -f $_.Exception.Message); $refHash=$null }

# ---- STEP 2: cold start IDM with MData present, then download through it
$sw=[Diagnostics.Stopwatch]::StartNew()
$p=Start-Process -FilePath $EXE -PassThru
$idmPid=$p.Id
W ("launched IDMan pid={0} at {1}  (MData present at launch)" -f $idmPid,(Get-Date -Format 'HH:mm:ss'))
Start-Sleep -Seconds 10
$mdNow=@(Get-MData)
W ("MData at t=10s: {0} value(s)" -f $mdNow.Count)

$target=Join-Path $DL $FileName
if(Test-Path $target){ Remove-Item $target -Force }
W ("triggering download via IDM: /d {0} /p {1} /f {2} /q" -f $Url,$DL,$FileName)
$dp=Start-Process -FilePath $EXE -ArgumentList @('/d',$Url,'/p',$DL,'/f',$FileName,'/q') -PassThru
W ("downloader invocation pid={0}" -f $dp.Id)

$seen=@{}; $popC=$false; $popR=$false; $popO=$false; $popOT=New-Object System.Collections.ArrayList
$popOAt=$null; $mdataMax=0; $lastLog=-10; $dlDoneAt=$null; $alive=$true; $exitHex=''; $outcome='UNKNOWN'
while($sw.Elapsed.TotalSeconds -lt $SoakSeconds){
  Start-Sleep -Milliseconds $PollMs
  $el=$sw.Elapsed.TotalSeconds
  try{ foreach($w in (Get-Windows $idmPid)){
    $sig="{0}|{1}|{2}" -f $w.Cls,$w.Txt,$w.Vis
    if(-not $seen.ContainsKey($sig)){ $seen[$sig]=[math]::Round($el,1) }
    if($w.Vis -and $w.Cls -eq '#32770'){
      if($w.Txt -match '假冒|counterfeit|正在退出|is exiting|Serial Number|提示'){ $popC=$true }
      if($w.Txt -match '注册|Register|Registration'){ $popR=$true }
      if($w.Txt -notmatch '^Internet Download Manager'){ $popO=$true; if($null -eq $popOAt){$popOAt=[math]::Round($el,1)}
        if(-not $popOT.Contains($w.Txt)){ [void]$popOT.Add($w.Txt) } } } } }catch{}
  $mdc=@(Get-MData).Count; if($mdc -gt $mdataMax){ $mdataMax=$mdc }
  if($null -eq $dlDoneAt -and (Test-Path $target)){
    $sz=(Get-Item $target).Length
    if($sz -gt 0 -and $sz -eq (Get-Item $refFile -ErrorAction SilentlyContinue).Length){ $dlDoneAt=[math]::Round($el,1); W ("  download reached full size {0} bytes at {1}s" -f $sz,$dlDoneAt) }
  }
  $p.Refresh()
  if($p.HasExited){ $alive=$false; $ec=$p.ExitCode; $exitHex='0x{0:X8}' -f ($ec -band 0xFFFFFFFF)
    $outcome=if($ec -eq 0){'clean-exit-0'}else{"NONZERO-EXIT $exitHex (hard failure)"}
    W ("  !! IDMan.exe DIED at {0}s exitcode={1} ({2}) <<< {3}" -f [math]::Round($el,1),$ec,$exitHex,$outcome); break }
  if(($el-$lastLog) -ge 60){ $lastLog=$el; $curSz=0; if(Test-Path $target){ $curSz=(Get-Item $target).Length }; W ("  t={0,4}s alive mdata={1} dlbytes={2}" -f [math]::Round($el,0),$mdc,$curSz) }
}
$survival=[math]::Round($sw.Elapsed.TotalSeconds,1); $sw.Stop()
if($alive){ $outcome='SURVIVED-SOAK' }

W "--- every distinct window observed ---"
foreach($k in ($seen.Keys | Sort-Object { $seen[$_] })){ $q=$k.Split('|'); W ("  t={0,7}s vis={1,-5} class='{2}' title='{3}'" -f $seen[$k],$q[2],$q[0],$q[1]) }
W ("--- final window list (alive={0}) ---" -f $alive)
$fw=@(); if($alive){ try{ $fw=@(Get-Windows $idmPid) }catch{} }
if($fw.Count -eq 0){ W "  (none)" } else { foreach($w in $fw){ W ("  hwnd=0x{0:X} vis={1,-5} class='{2}' title='{3}'" -f $w.H.ToInt64(),$w.Vis,$w.Cls,$w.Txt) } }

W ""
W "=== DOWNLOAD VERIFICATION ==="
$ok=$false
if(Test-Path $target){
  $th=(Get-FileHash $target -Algorithm SHA256).Hash
  $ts=(Get-Item $target).Length
  W ("IDM download : {0} bytes  sha256={1}" -f $ts,$th)
  W ("reference    : {0} bytes  sha256={1}" -f (Get-Item $refFile -ErrorAction SilentlyContinue).Length,$refHash)
  if($refHash -and $th -eq $refHash){ $ok=$true; W "MATCH: sha256 identical -> download is bit-correct" }
  else { W "MISMATCH or incomplete -> download NOT verified" }
} else { W "IDM produced NO file at $target" }
W ""
W ("=== VERDICT ===")
W ("stale MData at launch : {0} value(s) -> {1}" -f $md.Count, ($(if($md.Count -gt 0){'IDM STARTED AND SURVIVED WITH MData PRESENT'}else{'n/a'})))
W ("survival              : {0}s  ({1})" -f $survival,$outcome)
W ("popup_counterfeit     : {0}" -f $popC)
W ("popup_registration    : {0}" -f $popR)
W ("popup_other           : {0} @ {1}s  titles={2}" -f $popO,$popOAt,(($popOT|ForEach-Object{"'$_'"}) -join ' | '))
W ("download verified     : {0}" -f $ok)
W ("log={0}" -f $log)
