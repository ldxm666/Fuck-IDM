<#
  stage3-p8-observe.ps1 - decisive P8 acceptance run.

  WHY THIS EXISTS (and why it is NOT stage2-longrun.ps1)
    P8 patches IDMGrHlp.exe (the process that actually owns the counterfeit dialog).
    The popup was only ever reproduced under a SPECIFIC condition set:
        with-serial  AND  license server REACHABLE (hosts 3/6, not 6/6)
    stage2-longrun.ps1 calls scripts/idm-permanent-fix.ps1, which REWRITES hosts and
    restores the 6/6 block. Under a 6/6 block the server is unreachable, no verdict
    arrives, and the popup would be absent for a reason that has nothing to do with
    P8 -> a FALSE PASS. So this script deliberately does NOT call that fix script.

    It therefore makes NO global state changes at all:
      * hosts is left exactly as found (and asserted to be server-REACHABLE)
      * the HKLM serial is only READ, never written
      * MData is only READ, never cleared (to stay closest to the reproducing run;
        the pre-existing value is recorded and t=0 state is stated explicitly)

    E7: "is IDM running" is decided by the elevated process enumeration AND a
    classified writable probe - never by a Low-IL Get-Process count.

  P8 EXPECTATION UNDER TEST
    ~256s after IDM starts, IDMan launches IDMGrHlp.exe (/ch 3 /w <hwnd>), which
    raises the counterfeit MessageBox. Expected after P8: that dialog never appears.
    A console-only negative is not enough, so this script also records whether
    IDMGrHlp.exe started at all, whether it exited abnormally, and MData timing.

  E8 DISCIPLINE (Lead, 2026-10-17 - MEASURED, do not violate)
    Any test that can spawn `IDMGrHlp*` or `IDMan` - INCLUDING A/B control copies -
    must be SERIALISED with on-device soak/acceptance runs. The helper process counts
    as part of the IDM exclusive-access scope.
    Why this exists: prober ran an A/B control (an UNPATCHED copy kept at
    .scratch\idm_probe\IDMGrHlp_orig.exe) CONCURRENTLY with this script's first
    600s run. The control's dialog windows appeared in this script's enumeration as
    `proc=IDMGrHlp_orig`, which looked exactly like "P8 failed". The run was void:
    neither a P8 failure nor a file-layout problem - it was concurrency.
    Therefore: (a) confirm exclusivity from an ELEVATED shell before starting, and
    (b) NEVER identify the helper by process NAME - match the EXECUTABLE PATH, because
    a renamed copy defeats name matching (this is also why `Get-Process -Name IDMGrHlp`
    reported 0 while a helper was plainly on screen).

  P8 ACCEPTANCE (this script)
    Deploy P8 to IDMGrHlp.exe, then cold-start IDM and watch >=600s. Judgement is by
    ExecutablePath, and every dialog process's FULL PATH is printed so it is obvious
    which FILE is responsible.

  ===========================================================================
  TWO CONFIRMED FACTS - MEASURED 2026-10-17, each cost a wasted run. Keep them.
  ===========================================================================
  (1) THE REGISTRATION DIALOG IS *NOT* EVIDENCE OF A no-serial STATE.
      Measured: a run whose HKLM `Serial` was already `A7K2M-P9Q4T-VB3XN-6WR8D`
      still showed the dialog `注册 Internet Download Manager` at t=1s (owner
      IDMan.exe). The dialog appears WITH a serial present, so it must never be
      used to infer that the serial was cleared. The only valid check for the
      registration state is reading HKLM\...\Internet Download Manager\Serial.
      (I previously inferred "no-serial" from this dialog and had to retract it.)

  (2) THE HELPER LAUNCH IS CONDITIONAL, SO END-TO-END CANNOT JUDGE P8.
      Measured: IDM launched IDMGrHlp.exe at ~256s in prober's run, but in TWO
      independent 600s runs here it never launched it at all (checked by
      ExecutablePath, not by name). The trigger condition is UNKNOWN.
      Consequence: a run with no target popup proves NOTHING about P8 when the
      helper never started - the popup could not have appeared anyway. Such a run
      must be reported INCONCLUSIVE, never as a pass.
      The decisive P8 evidence is prober's A/B contrast (both copies reached the
      call sites; only the patched copy showed ZERO MessageBoxA hits), which also
      rules out an early-exit false negative. Do not re-litigate P8 end-to-end.

  RUN ELEVATED:
    powershell -NoProfile -ExecutionPolicy Bypass -File stage3-p8-observe.ps1 -SoakSeconds 600
#>
[CmdletBinding()]
param(
  [int]   $SoakSeconds = 600,
  [int]   $PollMs      = 1000,
  [string]$OutDir      = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify',
  [string]$P8Sha       = '63197914F0B2C0F547C0AC572C85F5A1783CF7D228BEFDDEDB6BBA78461351F4',
  [string]$HlpOrigSha  = 'B3B6281EA820EAE8192E50B30698CF4C3B8BC3D4376C978403BC9E18E5857C23',
  # For the P9 (mdata_write) metric the pre-existing blob MUST be removed first,
  # otherwise a value left over from an earlier build is indistinguishable from a
  # fresh write and the metric is meaningless (Lead, 2026-10-17).
  [switch]$ClearMDataFirst
)
$ErrorActionPreference='Continue'
. (Join-Path $OutDir 'verify-v3-common.ps1')
$EXE='C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$HLP='C:\Program Files (x86)\Internet Download Manager\IDMGrHlp.exe'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$log=Join-Path $OutDir ("p8-run-$stamp.log")
$shotDir=Join-Path $OutDir 'shots'
New-Item -ItemType Directory -Force -Path $shotDir | Out-Null
function W($m){ $m; try{ Add-Content -LiteralPath $log -Value $m -ErrorAction Stop }catch{} }
function Fail($m){ W ("!! ABORT: {0}" -f $m); W "=== P8 RUN ABORTED ==="; exit 2 }

Add-Type -ReferencedAssemblies 'System.Drawing' -TypeDefinition @"
using System; using System.Drawing; using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public class P8Grab {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string Save(IntPtr hwnd, string path){
    RECT r;
    try{
      if(!GetWindowRect(hwnd, out r)) return "ERR:GetWindowRect";
      int w=r.R-r.L, h=r.B-r.T; if(w<=0||h<=0) return "ERR:empty-rect";
      if(w>4096) w=4096; if(h>4096) h=4096;
      try{ using(var b=new Bitmap(w,h)) using(var g=Graphics.FromImage(b)){ IntPtr hdc=g.GetHdc(); bool ok=PrintWindow(hwnd,hdc,2); g.ReleaseHdc(hdc); if(ok){ b.Save(path,ImageFormat.Png); return "printwindow:"+path; } } }catch{}
      try{ using(var b=new Bitmap(w,h)) using(var g=Graphics.FromImage(b)){ g.CopyFromScreen(r.L,r.T,0,0,new Size(w,h),CopyPixelOperation.SourceCopy); b.Save(path,ImageFormat.Png); return "screen:"+path; } }catch(Exception e){ return "ERR:"+e.Message; }
    }catch(Exception e){ return "ERR:"+e.Message; }
  }
}
"@

# --- IDM-family detection BY EXECUTABLE PATH (E8) ---------------------------
# Matching by process NAME is defeated by a renamed copy: during the first P8 run a
# control copy named IDMGrHlp_orig.exe was on screen while `Get-Process -Name IDMGrHlp`
# returned 0. Match the full image path instead, and always report the path.
$script:IDM_DIR = 'C:\Program Files (x86)\Internet Download Manager'
function Get-IdmFamilyProcesses {
  $res = New-Object System.Collections.ArrayList
  foreach($pr in (Get-Process -ErrorAction SilentlyContinue)){
    $path = $null
    try{ $path = $pr.Path }catch{ continue }      # path is unreadable for other-user procs
    if(-not $path){ continue }
    if($path -like "$script:IDM_DIR\*"){
      [void]$res.Add([pscustomobject]@{ Pid=$pr.Id; Name=$pr.ProcessName; Path=$path })
    }
  }
  return $res
}
function Get-ProcPathByPid([int]$procId){
  try{ return (Get-Process -Id $procId -ErrorAction Stop).Path }catch{ return '<unresolved>' }
}

W ("=== P8 ACCEPTANCE RUN  {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("log = {0}" -f $log)
try{ [void](Assert-Elevated) }catch{ Fail $_.Exception.Message }
W "elevated = True"

# ---- 1) binary identity ---------------------------------------------------
$idmSha = Get-BinHash
$hlpSha = (Get-FileHash -LiteralPath $HLP -Algorithm SHA256).Hash
W ("IDMan.exe     sha256 = {0}" -f $idmSha)
W ("IDMGrHlp.exe  sha256 = {0}" -f $hlpSha)
W ("  P8 applied  (== 63197914...) = {0}" -f ($hlpSha -eq $P8Sha))
W ("  pristine    (== B3B6281E...) = {0}" -f ($hlpSha -eq $HlpOrigSha))
if($hlpSha -ne $P8Sha){ Fail "IDMGrHlp.exe does not carry P8 - refusing to score a run against the wrong binary" }
W ("  IDMan still 16-point (== BF853E81...) = {0}   [mdata is BASELINE this round]" -f ($idmSha -eq 'BF853E81DDCDD3A4E41D0093F92404C67253ADF7285B5FEB022E1C4CD83029BC'))

# ---- 2) E7 idle check + REQUIRED condition: server must be REACHABLE ------
$busy = Test-TargetBusy $EXE 15 2
if($busy.Busy){ Fail "IDMan.exe is still locked after 15 attempts - another actor owns IDM" }
W "idle check: IDMan.exe writable (not busy) OK"

# --- E8 EXCLUSIVITY: no IDM-family process may already be running -----------
# Counted by EXECUTABLE PATH, so a renamed helper copy cannot hide (that is exactly
# how the first run got contaminated). Any hit here means another actor - e.g. a
# concurrent A/B control - is live and the run must not start.
W ""
W "--- E8 exclusivity check (by ExecutablePath, not by name) ---"
$fam = @(Get-IdmFamilyProcesses)
if($fam.Count -gt 0){
  foreach($f in $fam){ W ("   RUNNING: pid={0} name={1} path={2}" -f $f.Pid,$f.Name,$f.Path) }
  Fail "IDM-family processes already running (see above). E8: helper processes count as IDM exclusive scope - serialise with any A/B or probe test first."
} else { W "   no process is running from the IDM install dir -> exclusive" }

W ""
W "!!! CONDITION UNDER TEST: the license server must be REACHABLE, otherwise the"
W "!!! counterfeit path can never fire and a missing popup proves nothing about P8."
$hb = Get-HostsPermanentFixLines
W ("hosts: active={0} commented={1}" -f $hb.ActiveCount,$hb.CommentedCount)
$dns = Get-DnsBlockState
$reachable = 0; $blocked = 0
foreach($r in $dns){
  W ("  DNS {0,-38} -> {1}  blocked={2}" -f $r.Domain,($(if($r.Ips){$r.Ips}else{'<unresolved>'})),$r.Blocked)
  if($r.Blocked){ $blocked++ } else { $reachable++ }
}
W ("  => reachable domains = {0} / blocked = {1}" -f $reachable,$blocked)
if($reachable -eq 0){
  W "!! WARNING: every domain resolves to 0.0.0.0, so the server is UNREACHABLE."
  W "!! Under these conditions the popup CANNOT be expected - a clean run would be a"
  W "!! FALSE PASS for P8. Restore the reproducing condition (hosts 3/6) first."
  Fail "server unreachable - conditions do not match the run that produced the popup"
}
W "  precondition OK: server reachable, conditions match the reproducing run"

$reg = Get-IdmRegistration
W ("registration: Serial='{0}' FName='{1}' LName='{2}'" -f $reg.Serial,$reg.FName,$reg.LName)
if(-not $reg.Serial){ Fail "no serial present - the counterfeit branch requires with-serial" }

$mdPre = @(Get-MData)
W ("MData at t=0 (before any clearing): {0} value(s)" -f $mdPre.Count)
foreach($m in $mdPre){ W ("   PRE-EXISTING {0} len={1} sha256={2}" -f $m.Path,$m.Len,$m.Sha) }
if($ClearMDataFirst){
  $n = Clear-MData
  $mdAfter = @(Get-MData)
  W ("   -ClearMDataFirst: cleared {0} value(s); now present = {1}" -f $n,$mdAfter.Count)
  if($mdAfter.Count -ne 0){
    Fail "MData still present after clearing - the P9 metric would be ambiguous (HKCU/HKLM ACL? run elevated)"
  }
  W "   => any MData seen at t>0 from here on IS a fresh write by IDM (P9 metric is unambiguous)"
} else {
  W "   (NOT cleared: a value seen later may be the pre-existing blob - metric is BASELINE only)"
}

# ---- 3) launch and observe ----------------------------------------------
W ""
W ("--- launching IDM; observing {0}s at {1}ms ---" -f $SoakSeconds,$PollMs)
$sw=[Diagnostics.Stopwatch]::StartNew()
$p=Start-Process -FilePath $EXE -PassThru
$idmPid=$p.Id
W ("launched pid={0} at {1}" -f $idmPid,(Get-Date -Format 'HH:mm:ss'))

$seen=@{}; $modalDetails=New-Object System.Collections.ArrayList
$targetHits=New-Object System.Collections.ArrayList; $suspects=New-Object System.Collections.ArrayList
$hlpFirstSeen=$null; $hlpSeen=0; $mdataFirstSeen=$null; $lastLog=-30
$alive=$true; $exitHex=''; $outcome='UNKNOWN'

while($sw.Elapsed.TotalSeconds -lt $SoakSeconds){
  Start-Sleep -Milliseconds $PollMs
  $el=$sw.Elapsed.TotalSeconds
  # Helper detection BY PATH (E8). Name matching reported 0 while a helper was on
  # screen; a renamed copy must not be able to hide. We distinguish the DEPLOYED
  # helper (install dir) from any out-of-tree copy, because only the deployed one
  # is what P8 patches.
  try{
    foreach($f in (Get-IdmFamilyProcesses)){
      if($f.Name -notlike 'IDMGrHlp*'){ continue }
      $hlpSeen++
      if($null -eq $hlpFirstSeen){
        $hlpFirstSeen=[math]::Round($el,1)
        W ("  t={0}s HELPER STARTED pid={1} name={2} PATH={3}" -f $hlpFirstSeen,$f.Pid,$f.Name,$f.Path)
        W ("       is this the P8-deployed helper? {0}" -f ($f.Path -eq "$script:IDM_DIR\IDMGrHlp.exe"))
      }
    }
  }catch{}
  # ALL processes, not just IDMan - the target dialog is owned by a separate helper
  try{
    foreach($w in (Get-AllTopLevelWindows -VisibleOnly)){
      $sig="{0}|{1}|{2}" -f $w.Proc,$w.Cls,$w.Txt
      if(-not $seen.ContainsKey($sig)){ $seen[$sig]=[math]::Round($el,1) }
      if($w.Cls -ne '#32770'){ continue }
      $hk='D|{0}' -f $w.Hwnd
      if($seen.ContainsKey($hk)){ continue }
      $seen[$hk]=[math]::Round($el,1)
      $d = Get-ModalDetail -Hwnd $w.H
      $ownerPath = Get-ProcPathByPid $w.Pid
      $png = try{ [string][P8Grab]::Save($w.H,(Join-Path $shotDir ("p8-{0}-t{1}-{2}.png" -f $stamp,[math]::Round($el,0),$w.Proc))) }catch{ 'ERR:'+$_.Exception.Message }
      $t = Test-IsTargetPopup -Title $d.Title -Body $d.BodyOneLine -Buttons $d.ButtonSet
      [void]$modalDetails.Add([pscustomobject]@{
        At=[math]::Round($el,1); Proc=$w.Proc; Pid=$w.Pid; Hwnd=$w.Hwnd
        Title=$d.Title; Body=$d.Body; Buttons=$d.ButtonSet
        OwnerPath=$ownerPath
        Bare=$t.BareTitle; Ver=$t.VersionTitle; Target=$t.IsTarget; Shot=$png })
      W ("  t={0}s DIALOG proc={1} pid={2} title='{3}' IS-TARGET={4}" -f [math]::Round($el,1),$w.Proc,$w.Pid,$d.Title,$t.IsTarget)
      W ("       OWNER PATH: {0}" -f $ownerPath)
      W ("       BODY   : {0}" -f $d.BodyOneLine)
      W ("       BUTTONS: {0}" -f $d.ButtonSet)
      W ("       SHOT   : {0}" -f $png)
      if($t.IsTarget){ [void]$targetHits.Add([pscustomobject]@{At=[math]::Round($el,1);Proc=$w.Proc;Pid=$w.Pid;Title=$d.Title;OwnerPath=$ownerPath}) }
      elseif($t.BareTitle){ [void]$suspects.Add([pscustomobject]@{At=[math]::Round($el,1);Proc=$w.Proc;Pid=$w.Pid;Title=$d.Title;OwnerPath=$ownerPath}) }
    }
  }catch{}
  $mc=@(Get-MData).Count
  # MData was NOT cleared before this run, so "present" is ambiguous between
  # "still the pre-existing blob" and "freshly rewritten by IDM". Record it as a
  # BASELINE observation only; never score it as a P9 result this round.
  if($mc -gt 0 -and $null -eq $mdataFirstSeen){
    $mdataFirstSeen=[math]::Round($el,1)
    W ("  t={0}s MData present ({1} value(s)) - {2}" -f $mdataFirstSeen,$mc, $(if($ClearMDataFirst){'CLEARED at t=0 => THIS IS A FRESH WRITE  <<< P9 FAIL'}else{'PRE-EXISTING at t=0 => not proof of a fresh write [BASELINE]'}))
  }
  $p.Refresh()
  if($p.HasExited){
    $alive=$false; $ec=$p.ExitCode; $exitHex='0x{0:X8}' -f ($ec -band 0xFFFFFFFF)
    $outcome = if($ec -eq 0){'clean-exit-0'} else {"NONZERO-EXIT $exitHex (HARD FAILURE)"}
    W ("  !! IDMan.exe DIED at {0}s exitcode={1} ({2})" -f [math]::Round($el,1),$ec,$exitHex)
    break
  }
  if(($el-$lastLog) -ge 60){ $lastLog=$el; W ("  t={0,4}s alive idm=True idmgrhlp={1} dialogs={2} target={3} mdataNow={4}" -f [math]::Round($el,0),$hlpSeen,$modalDetails.Count,$targetHits.Count,$mc) }
}
$survival=[math]::Round($sw.Elapsed.TotalSeconds,1); $sw.Stop()
if($alive){ $outcome='SURVIVED-WINDOW' }

# ---- 4) verdict ----------------------------------------------------------
$hlpAlive = @(Get-Process -Name IDMGrHlp -ErrorAction SilentlyContinue).Count
W ""
W "=== P8 VERDICT ==="
W ("window                : {0}s  mode=with-serial, server REACHABLE" -f $SoakSeconds)
W ("IDMan survival        : {0}s  outcome={1}  exit={2}" -f $survival,$outcome,$(if($exitHex){$exitHex}else{'(alive)'}))
W ("IDMGrHlp-helper started: {0}  firstSeenAt={1}s  <= by ExecutablePath" -f ($hlpFirstSeen -ne $null),$hlpFirstSeen)
W "--- every dialog observed, with the OWNER's full ExecutablePath ---"
if($modalDetails.Count -eq 0){ W "  (no dialog)" }
foreach($d in $modalDetails){
  W ("  t={0}s target={1} title='{2}'" -f $d.At,$d.Target,$d.Title)
  W ("     OWNER PATH = {0}" -f $d.OwnerPath)
  W ("     => deployed P8 helper? {0}" -f ($d.OwnerPath -eq "$script:IDM_DIR\IDMGrHlp.exe"))
}
W ("dialogs (#32770)      : {0}  (all processes)" -f $modalDetails.Count)
W ("TARGET popup hits     : {0}" -f $targetHits.Count)
W ("bare-title suspects   : {0}" -f $suspects.Count)
foreach($h in $targetHits){ W ("    !! TARGET at {0}s proc={1} pid={2} title='{3}'" -f $h.At,$h.Proc,$h.Pid,$h.Title) }
foreach($h in $suspects){ W ("    ~  suspect at {0}s proc={1} pid={2} title='{3}'" -f $h.At,$h.Proc,$h.Pid,$h.Title) }
W ("MData first at t>0    : {0}   [BASELINE: 16-point IDMan, expected to appear]" -f $(if($mdataFirstSeen){"$($mdataFirstSeen)s"}else{'never'}))
W ""
if($targetHits.Count -eq 0 -and $hlpFirstSeen -ne $null -and $alive){
  W "P8 RESULT : PASS-looking - IDMGrHlp.exe ran, target popup did NOT appear in the full window."
  W "            (IDMGrHlp starting is what makes this a real negative rather than a"
  W "             no-op: if it never launched, the absence would prove nothing.)"
} elseif($hlpFirstSeen -eq $null){
  W "P8 RESULT : INCONCLUSIVE - IDMGrHlp.exe never appeared, so the absence of the popup"
  W "            does not test P8 at all. Report this, do not claim a pass."
} else {
  W "P8 RESULT : FAIL - the target popup still appeared. Either P8 did not take effect or"
  W "            there is a THIRD path (patcher has not excluded CreateDialogIndirectParamA)."
}
if($exitHex -and $exitHex -ne '0x00000000'){ W ("ABNORMAL EXIT: {0} - check for a self-check/rollback need" -f $exitHex) }
W ("rollback if needed: [IO.File]::Copy('{0}\IDMGrHlp.exe.p8-backup','{1}',$true)" -f $OutDir,$HLP)
W ("log={0}" -f $log)
