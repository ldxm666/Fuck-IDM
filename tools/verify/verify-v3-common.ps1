<#
  verify-v3-common.ps1 - shared helpers for the stage-2 verification scripts.

  DRAFT (task-3 stage-1 item 3). Deliberately self-contained: it does NOT dot-source
  or modify verify-run3.ps1 / idm_engine.py / scripts/**.

  Provides:
    Get-IdmWindows        - every top-level window owned by a pid (class/title/visible)
    Get-ModalDetail       - FULL forensics for one dialog: title, every visible text
                            control's body, the caption of every button, in order.
                            This is the task-3 item-6 "弹窗取证" primitive: title +
                            body text + button set.  Nothing else captured it before.
    Get-MData             - all MData values across all 5 CLSID keys x 4 registry views
    Get-IdmRegistration   - current HKLM registration state
    Get-DnsBlockState     - the ACCEPTED oracle: Resolve-DnsName -> must be 0.0.0.0
    Assert-Elevated       - hard stop with an explanation if the token is filtered

  Load with:  . 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\verify-v3-common.ps1'
#>

function Assert-Elevated {
  $elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if($elev){ return $true }
  $grp = (& whoami /groups 2>&1 | Out-String)
  $deny = $grp -match 'BUILTIN\\Administrators.*deny only'
  throw ("verify-v3-common: not elevated ({0}). A filtered (UAC deny-only) token cannot read " -f $(if($deny){'Administrator, deny-only'}else{'non-admin'})) `
      + "HKLM CLSID keys, so MData would be silently under-reported as 0. Re-run from an elevated PowerShell."
}

# --- Win32 plumbing --------------------------------------------------------
if(-not ('WV3W32' -as [type])){
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class WV3W32 {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  public static string T(IntPtr h){ var sb=new StringBuilder(8192); GetWindowTextW(h,sb,8192); return sb.ToString(); }
  public static string C(IntPtr h){ var sb=new StringBuilder(512); GetClassNameW(h,sb,512); return sb.ToString(); }
}
"@
}

function Get-IdmWindows {
  param([Parameter(Mandatory)][int]$Pid)
  $res = New-Object System.Collections.ArrayList
  $cb = [WV3W32+EnumProc]{
    param($h,$p)
    $pp=0; [void][WV3W32]::GetWindowThreadProcessId($h,[ref]$pp)
    if($pp -eq $Pid){
      [void]$res.Add([pscustomobject]@{
        H=[IntPtr]$h; Hwnd=('0x{0:X}' -f $h.ToInt64())
        Cls=[WV3W32]::C($h); Txt=[WV3W32]::T($h); Vis=[WV3W32]::IsWindowVisible($h) })
    }
    return $true
  }
  [void][WV3W32]::EnumWindows($cb,[IntPtr]::Zero)
  return $res
}

# Full forensics for a dialog: title + body text + button captions.
# IDM's dialogs are classic Win32: static/edit controls carry the text, buttons
# carry their captions.  Enumerating children is the only way to get the BODY of a
# MessageBox, whose own window text is just the title.
function Get-ModalDetail {
  param([Parameter(Mandatory)][IntPtr]$Hwnd)
  $cls=[WV3W32]::C($Hwnd); $title=[WV3W32]::T($Hwnd)
  $texts=New-Object System.Collections.ArrayList
  $btns =New-Object System.Collections.ArrayList
  $cb = [WV3W32+EnumProc]{
    param($h,$p)
    $c=[WV3W32]::C($h); $t=[WV3W32]::T($h); $len=[WV3W32]::GetWindowTextLengthW($h)
    if($t){
      if($c -eq 'Button'){ [void]$btns.Add($t) }
      else { [void]$texts.Add(('[{0}] {1}' -f $c,$t)) }
    }
    return $true
  }
  [void][WV3W32]::EnumChildWindows($Hwnd,$cb,[IntPtr]::Zero)
  return [pscustomobject]@{
    Hwnd   = ('0x{0:X}' -f $Hwnd.ToInt64())
    Class  = $cls
    Title  = $title
    Body   = ($texts -join "`n")
    BodyOneLine = (($texts -join ' / ') -replace '\s+',' ')
    Buttons= @($btns)
    ButtonSet = ($btns -join ' | ')
  }
}

# --- process-agnostic window enumeration (REQUIRED) -------------------------
# MEASURED INTEL (prober, 932s with-serial run, 2026-10-17):
#   The counterfeit dialog does NOT come from IDMan.exe. It is owned by a SEPARATE
#   process:
#       [03:11:27] class=#32770  pid=15856  proc=IDMGrHlp
#         title=[Internet Download Manager]      <-- BARE title, no version
#         buttons=[确定][取消]
#         body=[...has been registered with a fake Serial Number. Be aware that the
#               cracked product may work incorrectly and download files with errors.
#               Thus we advise you to purchase the full-featured product.]
#   Appeared ~256s after IDM started, stayed visible ~11 minutes.
#   IDMGrHlp.exe does NOT contain that text -> it is fed in at runtime.
#   => A watcher anchored on the IDMan pid CANNOT see it, which is exactly why
#      earlier rounds reported "no popups" while the user saw one.
#   => Enumerate ALL top-level windows and report the OWNING PROCESS NAME.
$script:V3_PROCNAME_CACHE = @{}
function Get-ProcNameByPid([int]$procId){
  if($script:V3_PROCNAME_CACHE.ContainsKey($procId)){ return $script:V3_PROCNAME_CACHE[$procId] }
  # E7 EXTENSION (measured 03:27): a per-pid process LOOKUP also fails under the
  # Low-IL token - two ALIVE processes (IDMan pid 43856, IDMGrHlp pid 15856) both
  # resolved to '<gone>' from Low-IL while an elevated shell resolved them normally.
  # So: the PID from GetWindowThreadProcessId is authoritative; the PROCESS NAME is
  # only reliable when this runs elevated. '<unresolved>' therefore means "unknown
  # here", NOT "the process exited" - never report it as the latter.
  $n = try{ (Get-Process -Id $procId -ErrorAction Stop).ProcessName }catch{ '<unresolved>' }
  $script:V3_PROCNAME_CACHE[$procId] = $n
  return $n
}

function Get-AllTopLevelWindows {
  param([switch]$VisibleOnly)
  $res = New-Object System.Collections.ArrayList
  $cb = [WV3W32+EnumProc]{
    param($h,$p)
    $pp=0; [void][WV3W32]::GetWindowThreadProcessId($h,[ref]$pp)
    $vis=[WV3W32]::IsWindowVisible($h)
    if($VisibleOnly -and -not $vis){ return $true }
    [void]$res.Add([pscustomobject]@{
      H=[IntPtr]$h
      Hwnd=('0x{0:X}' -f $h.ToInt64())
      Pid=$pp
      Proc=(Get-ProcNameByPid $pp)
      Cls=[WV3W32]::C($h)
      Txt=[WV3W32]::T($h)
      Vis=$vis })
    return $true
  }
  [void][WV3W32]::EnumWindows($cb,[IntPtr]::Zero)
  return $res
}

# Target-popup fingerprint. Deliberately stricter than "bare title": we require the
# BARE title AND any of the observed body/button markers, so IDM's ordinary main
# window ("Internet Download Manager 6.43") and unrelated dialogs do not trip it.
$script:V3_TARGET_BODY = 'fake Serial Number|counterfeit|re-?register|has been registered'
$script:V3_TARGET_BTNS = '取消|Cancel'
function Test-IsTargetPopup {
  param(
    [Parameter(Mandatory)][string]$Title,
    [string]$Body = '',
    [string]$Buttons = ''
  )
  $bare = ($Title -match '^Internet Download Manager$')
  $vers = ($Title -match '^Internet Download Manager \d')
  $bodyHit = ($Body    -match $script:V3_TARGET_BODY)
  $btnHit  = ($Buttons -match $script:V3_TARGET_BTNS)
  return [pscustomobject]@{
    IsTarget     = ($bare -and ($bodyHit -or $btnHit))
    BareTitle    = $bare
    VersionTitle = $vers
    BodyHit      = $bodyHit
    ButtonHit    = $btnHit
  }
}

# --- MData -----------------------------------------------------------------
$script:V3_GUIDS = @('{E6871B76-C3C8-44DD-B947-ABFFE144860D}','{84797876-C678-1780-A556-0CD06786780F}',
                     '{6DDF00DB-1234-46EC-8356-27E7B2051192}','{79873CC5-3951-43ED-BDF9-D8759474B6FD}',
                     '{07999AC3-058B-40BF-984F-69EB1E554CA7}')
$script:V3_ROOTS = @(
  @([Microsoft.Win32.Registry]::CurrentUser, 'Software\Classes\CLSID','HKCU\CLSID'),
  @([Microsoft.Win32.Registry]::CurrentUser, 'Software\Classes\Wow6432Node\CLSID','HKCU\Wow'),
  @([Microsoft.Win32.Registry]::LocalMachine,'SOFTWARE\Classes\CLSID','HKLM\CLSID'),
  @([Microsoft.Win32.Registry]::LocalMachine,'SOFTWARE\Classes\WOW6432Node\CLSID','HKLM\Wow')
)

function Get-MData {
  $hits=New-Object System.Collections.ArrayList
  foreach($r in $script:V3_ROOTS){
    $hive=$r[0]; $base=$r[1]; $tag=$r[2]
    foreach($g in $script:V3_GUIDS){
      $k=$null
      try{ $k=$hive.OpenSubKey("$base\$g") }catch{ continue }
      if($null -eq $k){ continue }
      try{
        if($k.GetValueNames() -contains 'MData'){
          $val=$k.GetValue('MData')
          $sha=''; if($val -is [byte[]]){ $sha=(Get-FileHash -InputStream (New-Object IO.MemoryStream(,$val)) -Algorithm SHA256).Hash }
          [void]$hits.Add([pscustomobject]@{ Path="$tag\$g"; Len=$(if($val -is [byte[]]){$val.Length}else{-1}); Sha=$sha })
        }
      }catch{}
      try{ $k.Close() }catch{}
    }
  }
  return $hits
}

function Clear-MData {
  $n=0
  foreach($r in $script:V3_ROOTS){
    $hive=$r[0]; $base=$r[1]
    foreach($g in $script:V3_GUIDS){
      $k=$null
      try{ $k=$hive.OpenSubKey("$base\$g",$true) }catch{ continue }
      if($null -eq $k){ continue }
      try{ if($k.GetValueNames() -contains 'MData'){ $k.DeleteValue('MData',$false); $n++ } }catch{}
      try{ $k.Close() }catch{}
    }
  }
  return $n
}

function Get-IdmRegistration {
  return Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue
}

# --- DNS / hosts oracle ----------------------------------------------------
function Get-DnsBlockState {
  param([string[]]$Domains = @('internetdownloadmanager.com','www.internetdownloadmanager.com',
                               'secure.internetdownloadmanager.com','register.internetdownloadmanager.com',
                               'tonec.com','www.tonec.com'))
  $rows=@()
  foreach($d in $Domains){
    $ips = try { @(Resolve-DnsName $d -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) } catch { @() }
    $ips = @($ips)
    $rows += [pscustomobject]@{ Domain=$d; Ips=($ips -join ','); Count=$ips.Count; Blocked=($ips.Count -eq 1 -and [string]$ips[0] -eq '0.0.0.0') }
  }
  return $rows
}

function Get-HostsPermanentFixLines {
  $HOSTS="$env:SystemRoot\System32\drivers\etc\hosts"
  $active=@(); $commented=@()
  foreach($l in (Get-Content -LiteralPath $HOSTS -ErrorAction SilentlyContinue)){
    if($l -notmatch 'PermanentFix'){ continue }
    if($l.TrimStart().StartsWith('#')){ $commented += $l.Trim() } else { $active += ($l -replace '\s*#.*$','').Trim() }
  }
  return [pscustomobject]@{ Active=$active; Commented=$commented; ActiveCount=$active.Count; CommentedCount=$commented.Count }
}

function Get-BinHash {
  param([string]$Path='C:\Program Files (x86)\Internet Download Manager\IDMan.exe')
  return (Get-FileHash $Path -Algorithm SHA256).Hash
}
