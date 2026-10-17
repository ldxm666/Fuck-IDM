<#
  deploy-17pt.ps1 - deploy the frozen 17-point IDMan.exe (P1-P4, P5, P6, P7, P9)
  and verify it byte-for-byte before anything else touches the machine.

  RUN ELEVATED. Elevated child has no console, so this script writes its own log.

  ===========================================================================
  E7 (environment law, MEASURED 2026-10-17 03:16) - "WHO IS RUNNING?" IS HARD
  ===========================================================================
  `Get-Process IDMan` gives a FALSE NEGATIVE under the DSH Low-IL sandbox token:
      Low-IL  Get-Process IDMan  -> 0        <- FALSE, IDM was pid 48424 and alive
      Elevated Get-Process IDMan -> 1 (pid 48424)
  The process was spawned high-integrity (Frida spawn via an elevated parent), so
  the Low-IL token cannot enumerate it. `tasklist` and `Get-CimInstance Win32_Process`
  are ALSO denied from Low-IL ("Access denied"), so there is no Low-IL enumeration
  fallback. Never use a process count from the sandboxed shell as a go/no-go for
  deployment.

  The authoritative check is a WRITABLE PROBE on the target file - but THE PROBE
  ITSELF ONLY MEANS ANYTHING WHEN RUN ELEVATED, and the ERROR STRING must be
  classified. Measured side by side at the same instant:

    context   probe result                                        interpretation
    ------------------------------------------------------------------------------
    Low-IL    "Access to the path ... is denied"                  PERMISSION artifact
    Elevated  "being used by another process" (sharing violation) GENUINE lock

  Why this matters: `BUILTIN\Users` has only `(RX)` on the install dir, so a Low-IL
  shell can NEVER open the exe for write. From Low-IL the probe is therefore a
  CONSTANT "locked" and would block deployment forever, and it cannot distinguish
  "IDM is running" from "I lack permission". Only elevated can a sharing violation
  be observed at all. Hence:

      SHARING-VIOLATION ("being used by another process" / 另一个进程)
          => a process really holds it => DO NOT DEPLOY
      ACCESS-DENIED ("Access to the path ... is denied" / 拒绝访问)
          => permission problem, NOT evidence of a lock => escalate / run elevated

  ===========================================================================
  WHAT THIS SCRIPT DOES
  ===========================================================================
    0. assert elevated; resolve all paths ABSOLUTELY and print Test-Path for each
       (the elevated child's CWD is C:\Windows\System32 - relative paths read empty)
    1. report ACL state and remove a stale DENY(W,D) if present. A DENY breaks
       Frida spawn (frida.NotSupportedError 0x00000005) and deployment itself.
       This run must NOT ADD one (E6).
    2. authoritative busy-check: writable probe, classified, with 2s x 15 backoff
       logging the failure class of every attempt. On exhaustion, list Restart
       Manager holders as EVIDENCE ONLY - this script never kills a process.
    3. verify the currently installed hash, then copy the verified 17-point image.
    4. verify the installed hash equals -ExpectedSha, and byte-check every patch
       site P1-P7 plus P9, including the P9 NEIGHBOUR guard.

  P9 NOTE (Lead/patcher correction): the P9 file offset is 0x66AD9, NOT 0x66B09.
  0x66B09 falls INSIDE the imm32 of `push 0x69D1E4` and is not an instruction
  boundary. P9 rewrites the call at 0x66AD9:
        old  ff 15 90 50 69 00   (call dword ptr [0x695090])
        new  83 c4 18 90 90 90   (add esp,0x18 ; nop x3 - equal length, balanced)
  and must not disturb the adjacent `push 0x69D1E4` at 0x66AD0.

  USAGE
    powershell -NoProfile -ExecutionPolicy Bypass -File deploy-17pt.ps1 `
      -ExpectedSha 2879bda68d1ebb2cce0ed77c7975248a40de89f7b02e94fcb1831b270ba3c47a
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ExpectedSha,
  # Optional pre-built 17-point IDMan.exe image. CONFIRMED PRESENT and independently
  # verified by deployer at 03:19: 6,201,712 B, sha256 2879BDA6...C47A, with
  #   0x66AD9 = 83 C4 18 90 90 90 (P9)   0x66AD0 = 68 E4 D1 69 00 (neighbour, unchanged)
  #   0x68060 = 31 C0 C3 (P7)            0x4D2D4 = 90 x8 (P5 W1)
  # If this image is absent the script falls back to the engine route
  # (restore pristine -> apply_patches_to_install.py).
  [string]$ImagePath = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\lead-ref-17pt.exe',
  [string]$EngineScript = 'D:\pojie应用\jiesuo\work\idm-6.43b8\scripts\apply_patches_to_install.py',
  [string]$Root      = 'D:\pojie应用\jiesuo',
  [string]$ExePath   = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe',
  [string]$Pristine  = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe.bak-original',
  [string]$PristineSha = '279CEED9AAA646650716EE326C0D996BE4CE5DB4B252CF5B2747F4938A7CE737',
  [int]   $ProbeTries = 15,
  [int]   $ProbeDelaySec = 2,
  [switch]$SkipBusyCheck,          # only for a dry hash/byte inspection
  # Dual-route cross-validation (Lead suggestion). After the image route is deployed
  # and byte-verified, additionally restore pristine -> run the engine and require
  # the SAME hash; then re-copy the verified image so the final installed artefact is
  # always the byte-verified image. Two independent producers agreeing on one hash is
  # much stronger evidence than either alone.
  [switch]$CrossCheckEngine,
  [string]$LogDir    = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify'
)
$ErrorActionPreference = 'Continue'
function Test-DirWritable([string]$dir){
  try{ $p=Join-Path $dir ('.wprobe-'+[guid]::NewGuid().ToString('N')+'.tmp'); [IO.File]::WriteAllText($p,'x'); Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue; return $true }catch{ return $false }
}
try{ New-Item -ItemType Directory -Force -Path $LogDir -ErrorAction Stop | Out-Null }catch{}
$logDirEff = if(Test-DirWritable $LogDir){ $LogDir } else { $env:TEMP }
$log = Join-Path $logDirEff ('deploy-17pt-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
function W($m){ $m; try{ Add-Content -LiteralPath $log -Value $m -ErrorAction Stop }catch{} }
function ShaOf([string]$p){ (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }

function Classify-OpenError([string]$msg){
  if($msg -match 'being used by another process|另一个进程'){ return 'SHARING-VIOLATION' }
  if($msg -match 'denied|拒绝访问'){ return 'ACCESS-DENIED' }
  return 'OTHER'
}
# Authoritative busy-check. MUST be called from an elevated context or its result
# is meaningless (see the E7 block above).
function Test-TargetBusy([string]$exe,[int]$tries,[int]$delay){
  for($i=1;$i -le $tries;$i++){
    try{
      $fs=[IO.File]::Open($exe,'Open','ReadWrite','None'); $fs.Close()
      W ("   attempt {0}/{1}: WRITABLE (not locked)" -f $i,$tries)
      return @{ Busy=$false; Class='NONE' }
    }catch{
      $cls = Classify-OpenError $_.Exception.Message
      W ("   attempt {0}/{1}: {2}  :: {3}" -f $i,$tries,$cls,$_.Exception.Message)
      if($cls -eq 'ACCESS-DENIED'){
        W "   !! ACCESS-DENIED from an elevated shell is unexpected -> treat as unknown, NOT as 'not running'"
      }
    }
    if($i -lt $tries){ Start-Sleep -Seconds $delay }
  }
  return @{ Busy=$true; Class='EXHAUSTED' }
}
function ByteAt([string]$p,[int]$off,[int]$n){
  $fs=[IO.File]::Open($p,'Open','Read','ReadWrite')
  try{ $b=New-Object byte[] $n; $fs.Position=$off; [void]$fs.Read($b,0,$n); return (($b|ForEach-Object{'{0:X2}' -f $_}) -join ' ') }
  finally{ $fs.Close() }
}

W ("=== deploy 17-point  {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
W ("elevated   = {0}" -f $elevated)
W ("psver      = {0}" -f $PSVersionTable.PSVersion.ToString())
W ("inherited CWD = {0}" -f (Get-Location).Path)
Set-Location -LiteralPath $Root
W ("cwd set to = {0}" -f (Get-Location).Path)
W ("log        = {0}" -f $log)
if(-not $elevated){ W "!! ABORT: must run elevated (writes Program Files; the probe is meaningless from Low-IL)."; W "=== done ==="; exit 2 }

W ""
W "--- 0) all paths must EXIST (absolute; CWD is System32 in an elevated child) ---"
$imagesPresent = Test-Path -LiteralPath $ImagePath
W ("   Test-Path {0,-5} {1}" -f $imagesPresent,$ImagePath)
$required = @($Root,$ExePath,$Pristine)
if(-not $imagesPresent){ $required += $EngineScript }
$missing = @()
foreach($p in $required){ $e=Test-Path -LiteralPath $p; W ("   Test-Path {0,-5} {1}" -f $e,$p); if(-not $e){ $missing+=$p } }
if($missing.Count){ W ("!! ABORT missing: " + ($missing -join ' ; ')); W "=== done ==="; exit 3 }
if($imagesPresent){ W "   deploy route = verified pre-built image" }
else{ W "   deploy route = ENGINE (no 17-point image on disk): restore pristine, then apply_patches_to_install.py" }

W ""
W "--- 1) ACL state (remove a stale DENY; never ADD one - E6) ---"
$acl = (& icacls "$ExePath" 2>&1 | Out-String)
W ("   current ACL: " + (($acl -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 6) -join ' | ')
if($acl -match 'Everyone:.*\(DENY\)'){
  W "   DENY present -> removing with: icacls <exe> /remove:d Everyone"
  $rm = (& icacls "$ExePath" /remove:d Everyone 2>&1 | Out-String); W ("   " + $rm.Trim())
} else { W "   no Everyone DENY present - nothing to remove (and none will be added)" }

W ""
W "--- 2) authoritative busy-check (writable probe, classified, {0}x{1}s backoff) ---" -f $ProbeTries,$ProbeDelaySec
if($SkipBusyCheck){ W "   SKIPPED by -SkipBusyCheck (dry inspection only)" }
else{
  $busy = Test-TargetBusy $ExePath $ProbeTries $ProbeDelaySec
  if($busy.Busy){
    W "   RESULT: still busy after {0} attempts - NOT deploying." -f $ProbeTries
    W "   Per E7: wait for prober's explicit 'run finished + cleaned up' signal rather than retrying blindly."
    # Evidence only - this script never kills anything.
    try{
      Add-Type -TypeDefinition @"
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public class RMHolders {
  [StructLayout(LayoutKind.Sequential)] struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
  const int CCH_RM_MAX_APP_NAME = 255; const int CCH_RM_MAX_SVC_NAME = 63;
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct RM_PROCESS_INFO {
    public RM_UNIQUE_PROCESS Process;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=CCH_RM_MAX_APP_NAME+1)] public string strAppName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=CCH_RM_MAX_SVC_NAME+1)] public string strServiceShortName;
    public int ApplicationType; public uint AppStatus; public uint TSSessionId; [MarshalAs(UnmanagedType.Bool)] public bool bRestartable; }
  [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] static extern int RmStartSession(out uint h, int f, string k);
  [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint h);
  [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] static extern int RmRegisterResources(uint h, uint nf, string[] f, uint na, RM_UNIQUE_PROCESS[] a, uint ns, string[] s);
  [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint h, out uint need, ref uint cnt, [In,Out] RM_PROCESS_INFO[] arr, ref uint reasons);
  public static List<string> Who(string path){
    var res=new List<string>(); uint ses; string key=Guid.NewGuid().ToString();
    if(RmStartSession(out ses,0,key)!=0){ res.Add("RmStartSession failed"); return res; }
    try{
      if(RmRegisterResources(ses,1,new string[]{path},0,null,0,null)!=0){ res.Add("RmRegisterResources failed"); return res; }
      uint need=0,cnt=0,rea=0; RmGetList(ses,out need,ref cnt,null,ref rea);
      if(need==0){ res.Add("(Restart Manager reports no holder)"); return res; }
      cnt=need; var arr=new RM_PROCESS_INFO[cnt];
      if(RmGetList(ses,out need,ref cnt,arr,ref rea)!=0){ res.Add("RmGetList failed"); return res; }
      for(int i=0;i<cnt;i++) res.Add("pid="+arr[i].Process.dwProcessId+" app='"+arr[i].strAppName+"' svc='"+arr[i].strServiceShortName+"'");
    } finally { RmEndSession(ses); }
    return res; }
}
"@ -ErrorAction Stop
      W "   Restart Manager holders (evidence only, nothing is killed):"
      foreach($x in [RMHolders]::Who($ExePath)){ W ("      " + $x) }
    }catch{ W ("   Restart Manager query failed: " + $_.Exception.Message) }
    W "=== done (aborted: target busy) ==="; exit 4
  }
  W "   RESULT: not busy -> safe to deploy"
}

W ""
W "--- 3) deploy ---"
W ("   installed before = {0}" -f (ShaOf $ExePath))
if($imagesPresent){
  W ("   image            = {0}  ({1})" -f (ShaOf $ImagePath),$ImagePath)
  W ("   expected         = {0}" -f $ExpectedSha.ToUpper())
  try{
    [IO.File]::Copy($ImagePath, $ExePath, $true)     # Copy(overwrite) - no CWD/relative issues
    W "   [IO.File]::Copy(...,true) OK"
  }catch{
    W ("   !! COPY FAILED [{0}]: {1}" -f (Classify-OpenError $_.Exception.Message), $_.Exception.Message)
    W "=== done (aborted) ==="; exit 5
  }
} else {
  # Engine route. Restore pristine first so the result is deterministic regardless
  # of what was installed, then let the engine apply every site it knows about.
  W "   [engine route] restoring pristine base"
  try{
    [IO.File]::Copy($Pristine, $ExePath, $true)
  }catch{
    W ("   !! RESTORE FAILED [{0}]: {1}" -f (Classify-OpenError $_.Exception.Message), $_.Exception.Message)
    W "   (a SHARING-VIOLATION here means a process still holds the exe - see E7)"
    W "=== done (aborted) ==="; exit 5
  }
  $baseHash = ShaOf $ExePath
  W ("   base after restore = {0}  (pristine expected {1}, match={2})" -f $baseHash,$PristineSha,($baseHash -eq $PristineSha))
  if($baseHash -ne $PristineSha){
    W "!! ABORT: base is not the pristine b15 build - engine output would not be reproducible."
    W "=== done (aborted) ==="; exit 5
  }
  W ("   running engine: python -X utf8 {0}" -f $EngineScript)
  Set-Location -LiteralPath $Root
  $eng = (& python -X utf8 $EngineScript 2>&1 | Out-String)
  W $eng
  W ("   engine exitcode = {0}" -f $LASTEXITCODE)
  W ("   installed after engine = {0}" -f (ShaOf $ExePath))
  if((ShaOf $ExePath) -ne $ExpectedSha.ToUpper()){
    W "   !! engine did not reach -ExpectedSha."
    W "   !! Do NOT hand-patch. Report to Lead/patcher: the engine's site set and the"
    W "   !! frozen build disagree (expected 17 sites incl. P9 at 0x66AD9)."
    W "=== done (aborted) ==="; exit 6
  }
}
$installed = ShaOf $ExePath
W ("   installed after  = {0}" -f $installed)
W ("   HASH MATCH       = {0}" -f ($installed -eq $ExpectedSha.ToUpper()))
if($installed -ne $ExpectedSha.ToUpper()){ W "!! ABORT: hash mismatch - do not run anything on this binary"; W "=== done ==="; exit 6 }

W ""
W "--- 4) byte verification: P1-P7 + P9, installed vs pristine ---"
$checks = @(
  @('P1 registration_flag_init', 0x379524, 4, '00 00 00 00'),
  @('P2 expiry_display_9999',    0x29545E, 4, '39 39 39 39'),
  @('P3 trial_nag_kill',         0x7C8D0,  5, 'E9 38 00 00 00'),
  @('P4 counterfeit_gate',       0x4D252,  6, 'E9 B9 FC FF FF 90'),
  @('P5 W1 tripwire_exit',       0x4D2D4,  8, '90 90 90 90 90 90 90 90'),
  @('P5 W2 tripwire_exit',       0x66AF9,  8, '90 90 90 90 90 90 90 90'),
  @('P5 W3 tripwire_exit',       0x120B7A, 8, '90 90 90 90 90 90 90 90'),
  @('P5 W4 tripwire_branch',     0x6C5EC,  2, '90 90'),
  @('P6 license_popup_523AF',    0x523AF,  5, '90 90 90 90 90'),
  @('P7 counterfeit_broadcast',  0x68060,  3, '31 C0 C3'),
  @('P9  mdata_write_at_4676D9', 0x66AD9,  6, '83 C4 18 90 90 90'),
  @('P9  NEIGHBOUR 0x66AD0',     0x66AD0,  5, '68 E4 D1 69 00'),
  @('P9b mdata_write_at_521654', 0x120A54, 6, '83 C4 18 90 90 90'),
  @('P9b NEIGHBOUR 0x120A4B',    0x120A4B, 5, '68 E4 D1 69 00'),
  # P10 - the IDMan.exe-side counterfeit dialog producer (the 3rd path, i.e. the one
  # that actually reproduced ~8s after a download trigger).
  #   file 0x75444 / VA 0x476044 : E8 D7 EC FF FF -> 31 C0 90 90 90   (5 == 5)
  # Do NOT add a stack cleanup here: this site is cdecl and the existing
  # `83 C4 10` already sits 5 bytes later, so an extra add-esp would unbalance it.
  @('P10 counterfeit_popup_476044', 0x75444, 5, '31 C0 90 90 90')
)
$allOk = $true
foreach($c in $checks){
  $got = ByteAt $ExePath $c[1] $c[2]
  $org = ByteAt $Pristine $c[1] $c[2]
  $ok  = ($got -eq $c[3])
  if($c[0] -like '*NEIGHBOUR*'){ $ok = ($got -eq '68 E4 D1 69 00') }
  if(-not $ok){ $allOk = $false }
  W ("   {0,-30} 0x{1:X6} got=[{2}] want=[{3}] ok={4} | pristine=[{5}]" -f $c[0],$c[1],$got,$c[3],$ok,$org)
}
W ("   ALL BYTE CHECKS OK = {0}" -f $allOk)
W ""
if($CrossCheckEngine){
  W "--- 5) DUAL-ROUTE CROSS-CHECK: pristine + engine must reach the same hash ---"
  W ("   restoring pristine: {0}" -f $Pristine)
  try{ [IO.File]::Copy($Pristine,$ExePath,$true) }
  catch{ W ("   !! restore FAILED [{0}]: {1}" -f (Classify-OpenError $_.Exception.Message),$_.Exception.Message); W "=== done (cross-check aborted; installed file may now be pristine!) ==="; exit 7 }
  $b2 = ShaOf $ExePath
  W ("   base = {0}  pristine-match={1}" -f $b2,($b2 -eq $PristineSha))
  if($b2 -ne $PristineSha){ W "!! base not pristine - cross-check meaningless"; W "=== done ==="; exit 7 }
  Set-Location -LiteralPath $Root
  $eng = (& python -X utf8 $EngineScript 2>&1 | Out-String)
  W ("   engine exitcode = {0}" -f $LASTEXITCODE)
  $engHash = ShaOf $ExePath
  W ("   engine-produced hash = {0}" -f $engHash)
  W ("   engine == image hash = {0}   <-- dual-route agreement" -f ($engHash -eq $ExpectedSha.ToUpper()))
  if($engHash -ne $ExpectedSha.ToUpper()){
    W "   !! Routes DISAGREE. Do not trust either blindly - report to Lead/patcher."
  }
  # Whatever happened above, leave the installed file as the byte-verified image.
  W "   re-copying the verified image so the installed artefact is the verified one"
  try{ [IO.File]::Copy($ImagePath,$ExePath,$true) }
  catch{ W ("   !! re-copy FAILED: {0}" -f $_.Exception.Message); W "=== done ==="; exit 8 }
  W ("   final installed = {0}  match={1}" -f (ShaOf $ExePath),((ShaOf $ExePath) -eq $ExpectedSha.ToUpper()))
}
W ""
W "--- NOTE the P9 neighbour check above: if 0x66AD0 is not '68 E4 D1 69 00' the"
W "    patch landed on the wrong boundary (patcher initially quoted 0x66B09, which"
W "    is inside that imm32). ---"
W "=== done ==="
