<#
  stage1-stale-mdata.ps1 - DRAFT, task-3 stage-1 item 3 deliverable.

  PURPOSE
    The previous deployer round NEVER ran the stale-MData test. Its premise: the
    tripwire path writes a 256-byte REG_NONE "MData" blob and then ExitProcess(0).
    If the patch family really removed the CAUSE, then a *pre-existing* MData must
    be harmless on a cold start. If IDM still dies on sight of a stale MData, the
    patch only suppressed the writer, not the reactor - a different, worse bug.

  SEQUENCE
    0. Assert-Elevated; no other IDMan.exe running; assert binary sha256.
    1. ESTABLISH stale MData: if absent, launch IDM until one appears (max 180s),
       then kill IDM *without* deleting MData. Re-read and confirm it persists on
       disk for 60s (MData can be auto-deleted by CConfirm::OnTimer, so a
       persistence window is the real test that it is "stale").
    2. COLD START with MData present. Watch the full soak window.
    3. Report survival, exit code, popups (with FULL forensics), MData count over
       time, and whether MData was deleted by IDM itself.

  RUN FROM AN ELEVATED POWERSHELL:
    powershell -NoProfile -ExecutionPolicy Bypass -File `
      D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\stage1-stale-mdata.ps1 `
      -ExpectedSha <T1 sha256>
#>
[CmdletBinding()]
param(
  [int]   $SoakSeconds = 300,
  [int]   $PollMs      = 1000,
  [int]   $PrimeMaxSec = 180,
  [string]$ExpectedSha = '',
  [string]$OutDir      = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify'
)
$ErrorActionPreference='Continue'
. (Join-Path $OutDir 'verify-v3-common.ps1')
$EXE='C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$log=Join-Path $OutDir ("stale-mdata-$stamp.log")
function W($m){ $m | Tee-Object -FilePath $log -Append }
function Fail($m){ W ("!! ABORT: {0}" -f $m); W "=== stale-mdata ABORTED ==="; exit 2 }

$RE_COUNTERFEIT='假冒|counterfeit|正在退出|is exiting|序列号被用来|Serial Number|提示'
$RE_REGISTRATION='注册|Register|Registration'

W ("=== stale-MData cold-start test  {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("log = {0}" -f $log)
try{ [void](Assert-Elevated) }catch{ Fail $_.Exception.Message }
W "elevated = True"

$sha = Get-BinHash
W ("installed sha256 = {0}" -f $sha)
if($ExpectedSha -and $sha -ne $ExpectedSha.ToUpper()){ Fail "sha256 mismatch vs -ExpectedSha $ExpectedSha" }
if(-not $ExpectedSha){ W "!! -ExpectedSha not supplied (baseline mode)" }

$run=@(Get-Process IDMan -ErrorAction SilentlyContinue)
if($run.Count -gt 0){ Fail ("IDMan.exe already running (pid {0}) - exclusive access required" -f (($run|ForEach-Object{$_.Id}) -join ',')) }
W "exclusive access OK (no IDMan.exe running)"

$hb = Get-HostsPermanentFixLines
W ("hosts permanent-fix: active={0} commented={1}" -f $hb.ActiveCount,$hb.CommentedCount)
foreach($r in (Get-DnsBlockState)){ W ("  DNS {0,-38} -> {1}  blocked={2}" -f $r.Domain,($(if($r.Ips){$r.Ips}else{'<unresolved>'})),$r.Blocked) }
$reg=Get-IdmRegistration
W ("registration: Serial='{0}' FName='{1}' LName='{2}'" -f $reg.Serial,$reg.FName,$reg.LName)

# ---------------- 1) establish stale MData ---------------------------------
W ""
W "--- STEP 1: establish MData and LEAVE it in place ---"
$md=@(Get-MData)
if($md.Count -eq 0){
  W ("MData absent -> priming: launch IDM and wait up to {0}s" -f $PrimeMaxSec)
  $pp=Start-Process -FilePath $EXE -PassThru
  $swp=[Diagnostics.Stopwatch]::StartNew(); $sawAt=$null
  while($swp.Elapsed.TotalSeconds -lt $PrimeMaxSec){
    Start-Sleep -Seconds 2
    if(@(Get-MData).Count -gt 0){ $sawAt=[math]::Round($swp.Elapsed.TotalSeconds,1); break }
    $pp.Refresh(); if($pp.HasExited){ W ("  primer IDMan.exe exited early at {0}s code={1}" -f [math]::Round($swp.Elapsed.TotalSeconds,1),$pp.ExitCode); break }
  }
  $swp.Stop()
  $md=@(Get-MData)
  W ("priming done: MData count={0} firstSeenAt={1}s primerAlive={2}" -f $md.Count,$sawAt,(-not $pp.HasExited))
  if(-not $pp.HasExited){ try{ $pp.Kill() }catch{} }
  Start-Sleep -Seconds 3
} else { W "MData already present (NOT cleared)" }

$md=@(Get-MData)
W ("PRE-RUN MData = {0} value(s):" -f $md.Count)
foreach($m in $md){ W ("   {0}  len={1}  sha256={2}" -f $m.Path,$m.Len,$m.Sha) }
if($md.Count -eq 0){ Fail "could not establish a stale MData to test against" }

W "--- persistence window: does MData survive 60s with IDM stopped? ---"
$swp=[Diagnostics.Stopwatch]::StartNew(); $goneAt=$null
while($swp.Elapsed.TotalSeconds -lt 60){
  Start-Sleep -Seconds 3
  if(@(Get-MData).Count -eq 0){ $goneAt=[math]::Round($swp.Elapsed.TotalSeconds,1); break }
}
$swp.Stop()
if($null -eq $goneAt){ W "MData PERSISTED for the full 60s -> genuinely stale on disk" }
else { W ("!! MData disappeared at {0}s with IDM stopped - something else deletes it; the test is still valid but note this" -f $goneAt) }
$mdStale=@(Get-MData)
W ("stale MData going into the cold start = {0} value(s)" -f $mdStale.Count)

# ---------------- 2) cold start with stale MData ---------------------------
W ""
W "--- STEP 2: cold start with MData present ---"
$sw=[Diagnostics.Stopwatch]::StartNew()
$p=Start-Process -FilePath $EXE -PassThru
$idmPid=$p.Id
W ("launched pid={0} at {1}" -f $idmPid,(Get-Date -Format 'HH:mm:ss'))

$seen=@{}; $popC=$false; $popR=$false; $popO=$false
$popCAt=$null; $popRAt=$null; $popOAt=$null
$popOTitles=New-Object System.Collections.ArrayList
$modalDetails=New-Object System.Collections.ArrayList
$mdataMax=0; $mdataFirstSeen=$null; $lastLog=-10
$alive=$true; $exitHex=''; $outcome='UNKNOWN'

while($sw.Elapsed.TotalSeconds -lt $SoakSeconds){
  Start-Sleep -Milliseconds $PollMs
  $el=$sw.Elapsed.TotalSeconds
  try{
    foreach($w in (Get-IdmWindows -Pid $idmPid)){
      $sig="{0}|{1}|{2}" -f $w.Cls,$w.Txt,$w.Vis
      if(-not $seen.ContainsKey($sig)){ $seen[$sig]=[math]::Round($el,1) }
      if($w.Vis -and $w.Cls -eq '#32770'){
        if($w.Txt -match $RE_COUNTERFEIT){ if(-not $popC){ $popC=$true; $popCAt=[math]::Round($el,1) } }
        if($w.Txt -match $RE_REGISTRATION){ if(-not $popR){ $popR=$true; $popRAt=[math]::Round($el,1) } }
        if($w.Txt -notmatch '^Internet Download Manager'){
          if(-not $popO){ $popO=$true; $popOAt=[math]::Round($el,1) }
          if(-not $popOTitles.Contains($w.Txt)){ [void]$popOTitles.Add($w.Txt) }
        }
        # FULL forensics on first sighting of this exact dialog
        $hkey='M|{0}' -f $w.Hwnd
        if(-not $seen.ContainsKey($hkey)){
          $seen[$hkey]=[math]::Round($el,1)
          $d = Get-ModalDetail -Hwnd $w.H
          [void]$modalDetails.Add([pscustomobject]@{ At=[math]::Round($el,1); Class=$d.Class; Title=$d.Title; BodyOneLine=$d.BodyOneLine; ButtonSet=$d.ButtonSet })
        }
      }
    }
  }catch{}
  $mc=@(Get-MData).Count
  if($mc -gt $mdataMax){ $mdataMax=$mc }
  if($mc -gt 0 -and $null -eq $mdataFirstSeen){ $mdataFirstSeen=[math]::Round($el,1) }
  $p.Refresh()
  if($p.HasExited){
    $alive=$false; $ec=$p.ExitCode; $exitHex='0x{0:X8}' -f ($ec -band 0xFFFFFFFF)
    $outcome = if($ec -eq 0){'clean-exit-0'} else {"NONZERO-EXIT $exitHex (hard failure)"}
    W ("  !! IDMan.exe DIED at {0}s exitcode={1} ({2})  <<< {3}" -f [math]::Round($el,1),$ec,$exitHex,$outcome)
    break
  }
  if(($el-$lastLog) -ge 60){ $lastLog=$el; W ("  t={0,4}s alive mdataNow={1} mdataMax={2}" -f [math]::Round($el,0),$mc,$mdataMax) }
}
$survival=[math]::Round($sw.Elapsed.TotalSeconds,1); $sw.Stop()
if($alive){ $outcome='SURVIVED-SOAK' }

W ""
W "--- POPUP FORENSICS (task-3 item 6: title + body + buttons) ---"
if($modalDetails.Count -eq 0){ W "  (no #32770 dialog ever appeared)" }
foreach($d in $modalDetails){
  W ("  t={0}s class='{1}'" -f $d.At,$d.Class)
  W ("    TITLE  : {0}" -f $d.Title)
  W ("    BODY   : {0}" -f $d.BodyOneLine)
  W ("    BUTTONS: {0}" -f $d.ButtonSet)
}
W "--- every distinct window (class|title|visible -> first seen) ---"
foreach($k in ($seen.Keys | Sort-Object { $seen[$_] })){
  if($k -like 'M|*'){ continue }
  $q=$k.Split('|'); W ("  t={0,7}s vis={1,-5} class='{2}' title='{3}'" -f $seen[$k],$q[2],$q[0],$q[1])
}

$mdEnd=@(Get-MData)
W ""
W "=== VERDICT ==="
W ("stale MData at launch : {0} value(s)   sha256={1}" -f $mdStale.Count,(($mdStale|ForEach-Object{$_.Sha}) -join ';'))
W ("stale MData at end    : {0} value(s)   -> {1}" -f $mdEnd.Count, $(if($mdEnd.Count -eq 0){'IDM DELETED IT itself'}else{'still present'}))
W ("survival              : {0}s  ({1})" -f $survival,$outcome)
W ("exit_code_hex         : {0}" -f $(if($exitHex){$exitHex}else{'(still alive)'}))
W ("popup_counterfeit     : {0} @ {1}s" -f $popC,$popCAt)
W ("popup_registration    : {0} @ {1}s" -f $popR,$popRAt)
W ("popup_other           : {0} @ {1}s  titles={2}" -f $popO,$popOAt,(($popOTitles|ForEach-Object{"'$_'"}) -join ' | '))
W ("mdata_seen_during_run : max={0} firstSeenAt={1}s" -f $mdataMax,$mdataFirstSeen)
W ("PASS criterion        : survival=={0}s AND no counterfeit popup AND exitCode in (0,alive) AND no NEW MData written by IDM" -f $SoakSeconds)
W ("log={0}" -f $log)
