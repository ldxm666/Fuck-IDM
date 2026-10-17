<#
  stage4-p19-accept.ps1 - FINAL acceptance for the 19-point build (P10 = IDMan-side
  counterfeit dialog producer).

  WHY A SEPARATE SCRIPT
    P10 suppresses a dialog raised by IDMan.exe that only appears when a DOWNLOAD IS
    TRIGGERED. A passive soak never triggers it, so stage3 could never test P10.
    Measured reproduction (deployer, 04:37): after
        IDMan.exe /d https://proof.ovh.net/files/10Mb.dat /p <dl> /f ovh-10Mb.dat /q
    the dialog appeared within ~8 SECONDS on the IDMan.exe process itself:
        title    'Internet Download Manager'                (bare)
        body     '...fake Serial Number or the Serial Number has been blocked...'
        buttons  '确定'                                     (SINGLE)
    A second variant exists (owner IDMGrHlp.exe, buttons '确定|取消', body WITHOUT the
    'or ... has been blocked' clause). Both share the same bare title, so judgement
    must be on BODY/BUTTONS, never the title alone.

  E8 / E7
    * Confirm exclusivity by EXECUTABLE PATH before starting.
    * Identify popup owners by EXECUTABLE PATH, never by process name.

  CONDITIONS REQUIRED (asserted, else abort)
    with-serial + license server REACHABLE (hosts 3/6) + MData cleared to 0 +
    no IDM-family process at start.

  RUN ELEVATED:
    powershell -NoProfile -ExecutionPolicy Bypass -File stage4-p19-accept.ps1 -WindowSeconds 300
#>
[CmdletBinding()]
param(
  [int]   $WindowSeconds = 300,
  [int]   $PollMs        = 1000,
  [int]   $TriggerAfterSec = 5,
  [string]$Url   = 'https://proof.ovh.net/files/10Mb.dat',
  [string]$OutDir = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify',
  [string]$ExpectSha = '5C728E83DACD086B3FDE156D1DC076BE5E00CF622F44DC9B91B539C6176CEA76'
)
$ErrorActionPreference='Continue'
. (Join-Path $OutDir 'verify-v3-common.ps1')
$EXE='C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$HELPER_DIR='C:\Program Files (x86)\Internet Download Manager'
$DL=Join-Path $OutDir 'dl'
New-Item -ItemType Directory -Force -Path $DL | Out-Null
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$log=Join-Path $OutDir ("p19-accept-$stamp.log")
$shotDir=Join-Path $OutDir 'shots'
New-Item -ItemType Directory -Force -Path $shotDir | Out-Null
function W($m){ $m; try{ Add-Content -LiteralPath $log -Value $m -ErrorAction Stop }catch{} }
function Fail($m){ W ("!! ABORT: {0}" -f $m); W "=== ABORTED ==="; exit 2 }

Add-Type -ReferencedAssemblies 'System.Drawing' -TypeDefinition @"
using System; using System.Drawing; using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public class P19 {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint f);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string Save(IntPtr hwnd, string path){
    RECT r; if(!GetWindowRect(hwnd, out r)) return "ERR:rect";
    int w=r.R-r.L,hh=r.B-r.T; if(w<=0||hh<=0) return "ERR:empty";
    if(w>4096) w=4096; if(hh>4096) hh=4096;
    try{ using(var b=new Bitmap(w,hh)) using(var g=Graphics.FromImage(b)){ IntPtr dc=g.GetHdc(); bool ok=PrintWindow(hwnd,dc,2); g.ReleaseHdc(dc); if(ok){ b.Save(path,ImageFormat.Png); return "printwindow:"+path; } } }catch{}
    try{ using(var b=new Bitmap(w,hh)) using(var g=Graphics.FromImage(b)){ g.CopyFromScreen(r.L,r.T,0,0,new Size(w,hh),CopyPixelOperation.SourceCopy); b.Save(path,ImageFormat.Png); return "screen:"+path; } }catch(Exception e){ return "ERR:"+e.Message; }
  }
}
"@
# real mouse click (posted VK_RETURN was ignored by IDM's download dialog - measured)
Add-Type -TypeDefinition @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class Clk {
  public delegate bool EP(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr par, EP cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string T(IntPtr h){ var sb=new StringBuilder(2048); GetWindowTextW(h,sb,2048); return sb.ToString(); }
  public static string C(IntPtr h){ var sb=new StringBuilder(256); GetClassNameW(h,sb,256); return sb.ToString(); }
  public static List<IntPtr> Kids(IntPtr par){ var r=new List<IntPtr>(); EnumChildWindows(par,(h,p)=>{ r.Add(h); return true; }, IntPtr.Zero); return r; }
  public static bool Click(IntPtr h){
    RECT r; if(!GetWindowRect(h, out r)) return false;
    SetCursorPos((r.L+r.R)/2,(r.T+r.B)/2);
    System.Threading.Thread.Sleep(150);
    mouse_event(0x0002,0,0,0,IntPtr.Zero); System.Threading.Thread.Sleep(80); mouse_event(0x0004,0,0,0,IntPtr.Zero);
    return true;
  }
}
"@
function Get-Fam {
  $r=New-Object System.Collections.ArrayList
  foreach($p in (Get-Process -ErrorAction SilentlyContinue)){
    $x=$null; try{ $x=$p.Path }catch{ continue }
    if($x -and $x -like "$HELPER_DIR\*"){ [void]$r.Add([pscustomobject]@{Pid=$p.Id;Name=$p.ProcessName;Path=$x}) }
  }
  return $r
}
function Get-ProcPath([int]$procId){ try{ return (Get-Process -Id $procId -ErrorAction Stop).Path }catch{ return '<unresolved>' } }

W ("=== 19-POINT FINAL ACCEPTANCE  {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("log = {0}" -f $log)
try{ [void](Assert-Elevated) }catch{ Fail $_.Exception.Message }
W "elevated = True"

$sha = Get-BinHash
W ("installed IDMan.exe sha256 = {0}" -f $sha)
W ("  == 19-point expected      = {0}" -f ($sha -eq $ExpectSha))
if($sha -ne $ExpectSha){ Fail "installed build is not the 19-point image" }
W ("IDMGrHlp.exe sha256 = {0}  (P8 = 63197914...)" -f (Get-FileHash -LiteralPath (Join-Path $HELPER_DIR 'IDMGrHlp.exe') -Algorithm SHA256).Hash)

W ""
W "--- E8 exclusivity (by ExecutablePath) ---"
$fam=@(Get-Fam)
if($fam.Count -gt 0){ foreach($f in $fam){ W ("   RUNNING pid={0} name={1} path={2}" -f $f.Pid,$f.Name,$f.Path) }; Fail "IDM-family processes already running" }
W "   none running from the IDM install dir -> exclusive"
$busy = Test-TargetBusy $EXE 15 2
if($busy.Busy){ Fail "IDMan.exe still locked" }
W "   IDMan.exe writable -> free"

W ""
W "--- required conditions ---"
$dns=Get-DnsBlockState; $reach=0
foreach($r in $dns){ W ("   DNS {0,-38} -> {1} blocked={2}" -f $r.Domain,($(if($r.Ips){$r.Ips}else{'<unresolved>'})),$r.Blocked); if(-not $r.Blocked){$reach++} }
if($reach -eq 0){ Fail "license server UNREACHABLE - the counterfeit path cannot fire, a clean run would be a false pass" }
W ("   reachable = {0} (server reachable: reproducing condition met)" -f $reach)
$reg=Get-IdmRegistration
W ("   Serial = '{0}'  (with-serial required)" -f $reg.Serial)
if(-not $reg.Serial){ Fail "no serial - counterfeit branch requires with-serial" }
$mdPre=@(Get-MData)
W ("   MData at t=0 = {0} -> clearing" -f $mdPre.Count)
$cleared=Clear-MData
if(@(Get-MData).Count -ne 0){ Fail "MData still present after clearing - metric would be ambiguous" }
W ("   cleared={0}; now 0 => any MData at t>0 is a FRESH write" -f $cleared)

W ""
W ("--- launching IDM; will trigger the download at t~{0}s; window {1}s ---" -f $TriggerAfterSec,$WindowSeconds)
$sw=[Diagnostics.Stopwatch]::StartNew()
$p=Start-Process -FilePath $EXE -PassThru
$idmPid=$p.Id
W ("launched pid={0} at {1}" -f $idmPid,(Get-Date -Format 'HH:mm:ss'))

$seen=@{}; $modals=New-Object System.Collections.ArrayList
$targets=New-Object System.Collections.ArrayList; $clickedDl=$false
$mdataFirst=$null; $lastLog=-30; $alive=$true; $exitHex=''; $outcome='UNKNOWN'
$triggered=$false

while($sw.Elapsed.TotalSeconds -lt $WindowSeconds){
  Start-Sleep -Milliseconds $PollMs
  $el=$sw.Elapsed.TotalSeconds
  # ---- trigger the download once, shortly after IDM is up -------------------
  if(-not $triggered -and $el -ge $TriggerAfterSec){
    $triggered=$true
    W ("  t={0}s TRIGGER: IDMan.exe /d {1} /p {2} /f ovh-10Mb.dat /q" -f [math]::Round($el,1),$Url,$DL)
    Start-Process -FilePath $EXE -ArgumentList @('/d',$Url,'/p',$DL,'/f','ovh-10Mb.dat','/q') | Out-Null
  }
  # ---- process-agnostic dialog sweep ---------------------------------------
  try{
    foreach($w in (Get-AllTopLevelWindows -VisibleOnly)){
      if($w.Cls -ne '#32770'){ continue }
      $ownerPath = Get-ProcPath $w.Pid
      $hk='D|{0}' -f $w.Hwnd
      if($seen.ContainsKey($hk)){ continue }
      $seen[$hk]=[math]::Round($el,1)
      $d=Get-ModalDetail -Hwnd $w.H
      $t=Test-IsTargetPopup -Title $d.Title -Body $d.BodyOneLine -Buttons $d.ButtonSet
      $png=''
      if($t.IsTarget){
        try{ $png=[string][P19]::Save($w.H,(Join-Path $shotDir ("p19-{0}-t{1}-{2}.png" -f $stamp,[math]::Round($el,0),$w.Pid))) }catch{ $png='ERR:'+$_.Exception.Message }
      }
      [void]$modals.Add([pscustomobject]@{At=[math]::Round($el,1);Pid=$w.Pid;Proc=$w.Proc;OwnerPath=$ownerPath;Title=$d.Title;Body=$d.Body;Buttons=$d.ButtonSet;Target=$t.IsTarget;Shot=$png})
      W ("  t={0}s DIALOG pid={1} proc={2} title='{3}' IS-TARGET={4}" -f [math]::Round($el,1),$w.Pid,$w.Proc,$d.Title,$t.IsTarget)
      W ("       OWNER PATH: {0}" -f $ownerPath)
      W ("       BODY      : {0}" -f $d.BodyOneLine)
      W ("       BUTTONS   : {0}" -f $d.ButtonSet)
      if($t.IsTarget){ [void]$targets.Add([pscustomobject]@{At=[math]::Round($el,1);Pid=$w.Pid;Proc=$w.Proc;OwnerPath=$ownerPath;Title=$d.Title;Shot=$png}) }
      # unblock a pending download confirmation so the download can complete
      if(-not $clickedDl -and $d.Title -eq '下载文件信息'){
        foreach($k in [Clk]::Kids($w.H)){
          if([Clk]::C($k) -eq 'Button' -and [Clk]::T($k) -like '开始下载*'){
            W ("       CLICK '开始下载' -> {0}" -f [Clk]::Click($k)); $clickedDl=$true
          }
        }
      }
    }
  }catch{}
  $mc=@(Get-MData).Count
  if($mc -gt 0 -and $null -eq $mdataFirst){ $mdataFirst=[math]::Round($el,1); W ("  t={0}s MData FRESH WRITE ({1} value(s))  <<< P9/P10 REGRESSION" -f $mdataFirst,$mc) }
  $p.Refresh()
  if($p.HasExited){
    $alive=$false; $ec=$p.ExitCode; $exitHex='0x{0:X8}' -f ($ec -band 0xFFFFFFFF)
    $outcome = if($ec -eq 0){'clean-exit-0'} else {"NONZERO-EXIT $exitHex (HARD FAILURE)"}
    W ("  !! IDMan.exe DIED at {0}s exitcode={1} ({2})" -f [math]::Round($el,1),$ec,$exitHex); break
  }
  if(($el-$lastLog) -ge 30){ $lastLog=$el; W ("  t={0,4}s alive idm=True dialogs={1} target={2} mdataNow={3} dlClicked={4}" -f [math]::Round($el,0),$modals.Count,$targets.Count,$mc,$clickedDl) }
}
$survival=[math]::Round($sw.Elapsed.TotalSeconds,1); $sw.Stop()
if($alive){ $outcome='SURVIVED-WINDOW' }

$dlFile=Join-Path $DL 'ovh-10Mb.dat'
$dlSize=0; if(Test-Path $dlFile){ $dlSize=(Get-Item $dlFile).Length }

W ""
W "=== FINAL VERDICT (19-point) ==="
W ("window                 : {0}s   survival {1}s   outcome {2}   exit {3}" -f $WindowSeconds,$survival,$outcome,$(if($exitHex){$exitHex}else{'(alive)'}))
W ("download triggered     : {0}   confirm-dialog clicked: {1}" -f $triggered,$clickedDl)
W ("download file bytes    : {0}" -f $dlSize)
W ""
W ("[A] USABILITY  (survive / no crash / no WER / no 0x80000003 / no popup) : {0}" -f $(if($alive -and -not $exitHex -and $targets.Count -eq 0){'PASS'}else{'FAIL'}))
W ("[B] ROOT-CAUSE (mdata == 0 for all t>0)                                 : {0}{1}" -f $(if($null -eq $mdataFirst){'PASS'}else{'FAIL'}), $(if($null -eq $mdataFirst){''}else{'  <<< REGRESSION'}))
W ("[C] TARGET POPUP HITS (0 == P10 effective)                              : {0}" -f $targets.Count)
foreach($t in $targets){ W ("    !! TARGET at {0}s pid={1} proc={2} path={3} title='{4}' shot={5}" -f $t.At,$t.Pid,$t.Proc,$t.OwnerPath,$t.Title,$t.Shot) }
W ""
W "--- all dialogs seen (with owner ExecutablePath) ---"
foreach($d in $modals){ W ("  t={0}s target={1} title='{2}' owner={3} buttons=[{4}]" -f $d.At,$d.Target,$d.Title,$d.OwnerPath,$d.Buttons) }
W ("log={0}" -f $log)
