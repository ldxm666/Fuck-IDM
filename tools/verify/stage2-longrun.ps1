<#
  stage2-longrun.ps1 - DRAFT, long-observation round for task-3.

  WHY THIS EXISTS
    The user confirmed the counterfeit dialog is NOT tied to a fixed 62s; it appears
    "during the period after activation" at an unpredictable time, and the screenshot
    they supplied is a real recent capture from this machine. A 300s window therefore
    misses it by construction - which is one reason the previous "all soaks passed,
    no popups" conclusion cannot be trusted. This round watches continuously for
    >= 900s with 1s sampling.

  JUDGEMENT RULES IMPLEMENTED (Lead decisions, 2026-10-17)
    [A] USABILITY      : survives the window, no crash, no nonzero exit, no popup.
    [B] ROOT-CAUSE     : mdata MUST be 0 for all t > 0. Any MData at t > 0 is an
                         OPEN DEFECT and is reported SEPARATELY - never folded into
                         a pass. (The 15-point build writes MData at ~62-64s 5/5
                         runs and never cleans it; see stage1-findings-mdata-*.log.)
    [C] HIGH-SUSPECT   : a visible modal whose title is the BARE "Internet Download
                         Manager" (no version suffix) is flagged separately and
                         loudly. The real main window title is
                         "Internet Download Manager 6.43", so the bare title is the
                         user's dialog fingerprint. A versioned title is the main
                         window and is NOT a hit.
    [D] FORENSICS      : on EVERY distinct dialog, capture title + full body text +
                         button set + timestamp + a PNG screenshot.
    [E] COLD START     : assert 0 IDMan.exe before launching, every single time.
                         (HKCU\...\Run has "IDMan ... /onboot", so IDM can
                         self-start; a leaked process makes the exit code meaningless.)

  RUN ELEVATED (reads HKLM CLSID keys for MData; writes logs under work/**):
    powershell -NoProfile -ExecutionPolicy Bypass -File `
      D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\stage2-longrun.ps1 `
      -ExpectedSha <T1/T7 sha256> -SoakSeconds 900
#>
[CmdletBinding()]
param(
  [string]$Mode        = 'with-serial',
  # 600s minimum per Lead: the target popup was measured appearing at ~256s after
  # IDM start and staying visible ~11 min, so a 300s window barely covers it and
  # also competes with the P9 MData-at-~62s metric. Default 600s.
  [int]   $SoakSeconds = 600,
  [int]   $PollMs      = 1000,
  [string]$ExpectedSha = '',
  [string]$FixScript   = 'D:\pojie应用\jiesuo\work\idm-6.43b8\scripts\idm-permanent-fix.ps1',
  [string]$OutDir      = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify'
)
$ErrorActionPreference='Continue'
. (Join-Path $OutDir 'verify-v3-common.ps1')
$EXE='C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$log=Join-Path $OutDir ("longrun-$Mode-$stamp.log")
$shotDir=Join-Path $OutDir 'shots'
New-Item -ItemType Directory -Force -Path $shotDir | Out-Null
# W(): emit to pipeline AND best-effort file. Logging into work/** fails from the
# Low-IL sandbox token, so never let a log write break the observation run.
function W($m){ $m; try{ Add-Content -LiteralPath $log -Value $m -ErrorAction Stop }catch{} }
function Fail($m){ W ("!! ABORT: {0}" -f $m); W "=== longrun ABORTED ==="; exit 2 }

$BARE_TITLE = '^Internet Download Manager$'          # rule [C]
$MAIN_TITLE = '^Internet Download Manager \d'        # the real main window, for contrast

# --- screenshot plumbing ----------------------------------------------------
# NOTE: System.Drawing.Imaging is NOT reachable from pwsh 7 without an explicit
# -ReferencedAssemblies; the first draft of this block failed to compile with
# "namespace 'Imaging' does not exist in 'System.Drawing'". Verified fix:
#   Add-Type -TypeDefinition ... -ReferencedAssemblies 'System.Drawing'
# Also verified at runtime: PrintWindow(hwnd, hdc, 2) returns FALSE for at least
# some real windows (measured on this host), so a screen-region fallback is
# mandatory or the forensic screenshots silently never appear. The fallback was
# measured to produce a real 35 KB PNG. Requires the window to be visible - which
# a modal dialog is by definition.
if(-not ('WV3Grab' -as [type])){
Add-Type -ReferencedAssemblies 'System.Drawing' -TypeDefinition @"
using System; using System.Drawing; using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public class WV3Grab {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  // returns "printwindow:<path>", "screen:<path>" or "ERR:<why>"
  public static string Save(IntPtr hwnd, string path){
    RECT r;
    try{
      if(!GetWindowRect(hwnd, out r)) return "ERR:GetWindowRect";
      int w = r.R - r.L, h = r.B - r.T;
      if(w <= 0 || h <= 0) return "ERR:empty-rect";
      if(w > 4096) w = 4096; if(h > 4096) h = 4096;
      try{                                   // tier 1: off-screen render
        using(var bmp = new Bitmap(w, h))
        using(var g = Graphics.FromImage(bmp)){
          IntPtr hdc = g.GetHdc();
          bool ok = PrintWindow(hwnd, hdc, 2);   // 2 = PW_RENDERFULLCONTENT
          g.ReleaseHdc(hdc);
          if(ok){ bmp.Save(path, ImageFormat.Png); return "printwindow:" + path; }
        }
      }catch{}
      try{                                   // tier 2: screen region
        using(var bmp = new Bitmap(w, h))
        using(var g = Graphics.FromImage(bmp)){
          g.CopyFromScreen(r.L, r.T, 0, 0, new Size(w, h), CopyPixelOperation.SourceCopy);
          bmp.Save(path, ImageFormat.Png);
          return "screen:" + path;
        }
      }catch(Exception e2){ return "ERR:" + e2.Message; }
    }catch(Exception e){ return "ERR:" + e.Message; }
  }
}
"@
}

W ("=== LONGRUN mode={0} window={1}s poll={2}ms  {3} ===" -f $Mode,$SoakSeconds,$PollMs,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("log = {0}" -f $log)
try{ [void](Assert-Elevated) }catch{ Fail $_.Exception.Message }
W "elevated = True"

$sha = Get-BinHash
W ("installed sha256 = {0}" -f $sha)
if($ExpectedSha -and $sha -ne $ExpectedSha.ToUpper()){ Fail "sha256 mismatch vs -ExpectedSha $ExpectedSha - wrong build, refusing to burn $SoakSeconds s" }
if(-not $ExpectedSha){ W "!! -ExpectedSha NOT supplied - this run is exploratory only, do NOT use it for a final verdict" }

# --- rule [E]: cold start --------------------------------------------------
$run=@(Get-Process IDMan -ErrorAction SilentlyContinue)
if($run.Count -gt 0){ Fail ("rule [E]: {0} IDMan.exe already running (pid {1}). Hosts/registry/Tasks are global - another task is mid-run. Not proceeding." -f $run.Count, (($run|ForEach-Object{$_.Id}) -join ',')) }
W "rule [E] OK: 0 IDMan.exe before launch"

# --- set the mode, then verify it took ------------------------------------
W ("--- set RegMode={0} ---" -f $Mode)
W (& powershell -NoProfile -ExecutionPolicy Bypass -File $FixScript -RegMode $Mode 2>&1 | Out-String)
W "--- ipconfig /flushdns ---"
W (& ipconfig /flushdns 2>&1 | Out-String)
$reg=Get-IdmRegistration
W ("post-apply registry: Serial='{0}' FName='{1}'" -f $reg.Serial,$reg.FName)
if($Mode -eq 'no-serial'   -and $reg.Serial){ Fail "no-serial requested but HKLM Serial is still set" }
if($Mode -eq 'with-serial' -and -not $reg.Serial){ Fail "with-serial requested but HKLM Serial is empty" }

$hb=Get-HostsPermanentFixLines
W ("hosts: active={0} commented={1}" -f $hb.ActiveCount,$hb.CommentedCount)
$dnsBad=0
foreach($r in (Get-DnsBlockState)){
  W ("  DNS {0,-38} -> {1}  blocked={2}" -f $r.Domain,($(if($r.Ips){$r.Ips}else{'<unresolved>'})),$r.Blocked)
  if(-not $r.Blocked){ $dnsBad++ }
}
if($dnsBad -gt 0){ Fail "$dnsBad domain(s) not resolving to 0.0.0.0" }
W "DNS precondition OK (6/6 -> 0.0.0.0)"

# --- baseline MData (rule B) ----------------------------------------------
$mdPre = @(Get-MData)
W ("rule [B] MData at t=0: {0} value(s)" -f $mdPre.Count)
foreach($m in $mdPre){ W ("   PRE-EXISTING {0} len={1} sha256={2}" -f $m.Path,$m.Len,$m.Sha) }
if($mdPre.Count -gt 0){ W "   NOTE: pre-existing MData is carried into this run; rule [B] only judges NEW appearances after t>0" }

# --- launch ----------------------------------------------------------------
$sw=[Diagnostics.Stopwatch]::StartNew()
$p=Start-Process -FilePath $EXE -PassThru
$idmPid=$p.Id
W ("launched pid={0} at {1}" -f $idmPid,(Get-Date -Format 'HH:mm:ss'))

$seen=@{}                        # window signature -> first seen time
$modalDetails=New-Object System.Collections.ArrayList
$bareHits=New-Object System.Collections.ArrayList
$mdataFirstSeen=$null; $mdataMax=0; $mdataAt=New-Object System.Collections.ArrayList
$lastLog=-30; $alive=$true; $exitHex=''; $outcome='UNKNOWN'
$popupAny=$false

while($sw.Elapsed.TotalSeconds -lt $SoakSeconds){
  Start-Sleep -Milliseconds $PollMs
  $el=$sw.Elapsed.TotalSeconds
  try{
    # PROCESS-AGNOSTIC. The target dialog is owned by IDMGrHlp.exe (a SEPARATE
    # process), so a pid-scoped enumeration provably misses it - which is why the
    # earlier rounds reported "no popups" while the user saw one. Measured intel:
    #   [03:11:27] class=#32770 pid=15856 proc=IDMGrHlp
    #              title=[Internet Download Manager] buttons=[确定][取消]
    #              body=[...fake Serial Number...]  at ~256s after IDM start.
    foreach($w in (Get-AllTopLevelWindows -VisibleOnly)){
      $sig="{0}|{1}|{2}|{3}" -f $w.Proc,$w.Cls,$w.Txt,$w.Vis
      if(-not $seen.ContainsKey($sig)){ $seen[$sig]=[math]::Round($el,1) }
      if($w.Cls -eq '#32770'){
        $popupAny=$true
        $hkey='M|{0}' -f $w.Hwnd
        if(-not $seen.ContainsKey($hkey)){
          $seen[$hkey]=[math]::Round($el,1)
          $d=Get-ModalDetail -Hwnd $w.H
          $png=''
          try{
            $png=[string][WV3Grab]::Save($w.H,(Join-Path $shotDir ("modal-{0}-t{1}-{2}.png" -f $stamp,[math]::Round($el,0),$w.Proc)))
          }catch{ $png='ERR:'+$_.Exception.Message }
          # screenshot failure is recorded, never silently dropped
          $shotOk = ($png -like 'printwindow:*') -or ($png -like 'screen:*')
          $t = Test-IsTargetPopup -Title $d.Title -Body $d.BodyOneLine -Buttons $d.ButtonSet
          [void]$modalDetails.Add([pscustomobject]@{
            At=[math]::Round($el,1); Hwnd=$w.Hwnd; Proc=$w.Proc; Pid=$w.Pid; Class=$d.Class; Title=$d.Title
            Body=$d.BodyOneLine; Buttons=$d.ButtonSet
            Bare=$t.BareTitle; Main=$t.VersionTitle; Target=$t.IsTarget
            Shot=$png; ShotOk=$shotOk })
          if($t.IsTarget -or $t.BareTitle){
            [void]$bareHits.Add([pscustomobject]@{
              At=[math]::Round($el,1); Hwnd=$w.Hwnd; Proc=$w.Proc; Pid=$w.Pid
              Title=$d.Title; Target=$t.IsTarget })
            W ("  !! SUSPECT POPUP at {0}s proc={1} pid={2} title='{3}' target={4}" -f [math]::Round($el,1),$w.Proc,$w.Pid,$d.Title,$t.IsTarget)
          }
        }
      }
    }
  }catch{}
  $mc=@(Get-MData).Count
  if($mc -gt 0){
    if($null -eq $mdataFirstSeen){ $mdataFirstSeen=[math]::Round($el,1); W ("  !! rule [B] MData FIRST APPEARED at {0}s ({1} value(s))" -f $mdataFirstSeen,$mc) }
    if($mc -gt $mdataMax){ $mdataMax=$mc }
    if($mdataAt.Count -lt 12){ [void]$mdataAt.Add([math]::Round($el,1)) }
  }
  $p.Refresh()
  if($p.HasExited){
    $alive=$false; $ec=$p.ExitCode; $exitHex='0x{0:X8}' -f ($ec -band 0xFFFFFFFF)
    $outcome = if($ec -eq 0){'clean-exit-0'} else {"NONZERO-EXIT $exitHex (hard failure)"}
    W ("  !! IDMan.exe DIED at {0}s exitcode={1} ({2})  <<< {3}" -f [math]::Round($el,1),$ec,$exitHex,$outcome)
    break
  }
  if(($el-$lastLog) -ge 60){ $lastLog=$el; W ("  t={0,4}s alive mdataNow={1} mdataMax={2} bareTitleHits={3} dialogs={4}" -f [math]::Round($el,0),$mc,$mdataMax,$bareHits.Count,$modalDetails.Count) }
}
$survival=[math]::Round($sw.Elapsed.TotalSeconds,1); $sw.Stop()
if($alive){ $outcome='SURVIVED-WINDOW' }

# --- rule [D]: forensics ---------------------------------------------------
W ""
W "--- rule [D] DIALOG FORENSICS (proc + title + body + buttons + time + shot) ---"
if($modalDetails.Count -eq 0){ W "  (no #32770 dialog appeared in the whole window)" }
foreach($d in $modalDetails){
  W ("  t={0}s hwnd={1} proc={2} pid={3} class='{4}'" -f $d.At,$d.Hwnd,$d.Proc,$d.Pid,$d.Class)
  W ("    TITLE   : {0}" -f $d.Title)
  W ("    BODY    : {0}" -f $d.Body)
  W ("    BUTTONS : {0}" -f $d.Buttons)
  W ("    bareTitle={0}  mainWindowTitle={1}  IS-TARGET={2}  shot={3}" -f $d.Bare,$d.Main,$d.Target,$d.Shot)
}
W "--- every distinct window (proc|class|title|visible -> first seen) ---"
foreach($k in ($seen.Keys | Sort-Object { $seen[$_] })){
  if($k -like 'M|*'){ continue }
  $q=$k.Split('|'); W ("  t={0,7}s proc={1,-14} vis={2,-5} class='{3}' title='{4}'" -f $seen[$k],$q[0],$q[3],$q[1],$q[2])
}

$mdEnd=@(Get-MData)
$targetHits = @($modalDetails | Where-Object { $_.Target })

# --- verdict: two metrics, judged separately ------------------------------
# [A] USABILITY fails on a target popup, a bare-title popup, ANY unexpected dialog,
#     a crash, or a nonzero exit. [B] ROOT-CAUSE fails on any NEW MData at t>0.
$usagePass = $alive -and ($exitHex -eq '') -and ($bareHits.Count -eq 0) -and ($modalDetails.Count -eq 0)
$rootPass  = ($mdataFirstSeen -eq $null) -and ($mdEnd.Count -eq 0)

W ""
W "=== VERDICT (two metrics, separate) ==="
W ("window                : {0}s   mode={1}" -f $SoakSeconds,$Mode)
W ("survival              : {0}s   outcome={1}" -f $survival,$outcome)
W ("exit_code_hex         : {0}" -f $(if($exitHex){$exitHex}else{'(still alive)'}))
W ("dialogs (#32770)      : {0}   (all processes, not just IDMan)" -f $modalDetails.Count)
W ("TARGET popups matched : {0}   (IDMGrHlp + bare title + body/button markers)" -f $targetHits.Count)
W ("suspect/bare hits [C] : {0}" -f $bareHits.Count)
foreach($b in $bareHits){ W ("    !! SUSPECT at {0}s proc={1} pid={2} title='{3}' isTarget={4}" -f $b.At,$b.Proc,$b.Pid,$b.Title,$b.Target) }
W ("MData at t=0          : {0}" -f $mdPre.Count)
W ("MData first at t>0    : {0}" -f $(if($mdataFirstSeen){"$($mdataFirstSeen)s"}else{'never'}))
W ("MData max / at end    : {0} / {1}" -f $mdataMax,$mdEnd.Count)
foreach($t in $mdataAt){ W ("    MData observed at {0}s" -f $t) }
W ""
W ("[A] USABILITY         : {0}" -f $(if($usagePass){'PASS'}else{'FAIL'}))
W ("[B] ROOT-CAUSE (MData): {0}{1}" -f $(if($rootPass){'PASS'}else{'FAIL'}), $(if($rootPass){''}else{'   <<< OPEN DEFECT - do NOT fold into a pass'}))
if(-not $rootPass -and $usagePass){
  W "    NOTE: usability passes while root-cause fails. Report as: 'usable but root cause NOT eliminated'."
  W "    This is the exact shape of the 15-point build - do not let it be reported as fixed."
}
W ("log={0}" -f $log)
