<#
  firewall-block.ps1 - outbound firewall block for IDMan.exe (hardening, NOT YET APPLIED).

  WHY THIS EXISTS
    The hosts block is repaired (neutralised) by IDM ITSELF, measured:
    IDMan.exe contains the plaintext strings
      "Your browser may not open IDM website because an important system file is
       damaged on your computer. IDM will repair this file now."
      "IDM cannot check for updates because an important system file is damaged on
       your computer. Repair this file?"
    "an important system file" is the hosts file; the observed `#0.0.0.0 <domain>`
    prefixing is that repair. Timeline: hosts mtime 03:02:02 vs IDM start 03:02:00,
    and a 140s read-only watch with IDM stopped showed ZERO further changes, so it
    is a start-time action. Evidence:
      work/idm-6.43b8/logs/permanent-fix/hosts-commenter-resolved-20261017.log
    IDM also states it "may not use \"hosts\" file when they connect to IDM home
    site" and will "check for updates successfully even with your damaged hosts
    file" -> our Resolve-DnsName acceptance test proves the RESOLVER is blocked,
    NOT that IDM is blocked. hosts is therefore the WEAKEST layer.
    A Windows Firewall rule is enforced in the kernel/WFP, is not a file IDM can
    edit, and does not depend on how IDM resolves names. It is the tamper-resistant
    layer, but keep hosts as well (defence in depth).

  !!! DO NOT "SIMPLIFY" THE RULE INTO A BLANKET BLOCK - IT BREAKS DOWNLOADS !!!
    FORBIDDEN:
        netsh advfirewall firewall add rule ... program="<IDMan.exe>" action=block
    That is a PROGRAM-WIDE outbound block with NO destination limit. IDM is a
    DOWNLOADER: its normal job requires outbound traffic, so that form silently
    destroys the user's download functionality. It must never be used.
    REQUIRED (destination-limited): keep the program scope but restrict remoteip to
    the IDM-owned / license-server ranges, so ordinary downloads to other hosts
    still work and only the license/update endpoints are cut:
        remoteip=67.18.0.0/16,169.62.35.21
    67.18.0.0/16 covers the addresses our nslookup control measured for the IDM
    domains (67.18.60.145, 67.18.140.140); 169.62.35.21 was measured for tonec.com.
    If more endpoints are later discovered, ADD them to -RemoteIps rather than
    dropping the remoteip clause.

  SCOPE / SAFETY
    * OUTBOUND, program-scoped to IDMan.exe AND destination-limited. Inbound is
      never touched, other programs are never touched, the firewall is never
      disabled.
    * Downloads to normal hosts keep working. Downloads FROM the blocked ranges
      would fail - that is the intended, narrow trade-off.
    * Reversible: -Action remove deletes exactly the named rule.

  LIMITATIONS (honest)
    * IP-range based blocking is a weaker guarantee than it looks: if IDM changes
      its server IPs the rule stops covering them. This is why `status` prints
      RemoteIP and why the layer is advisory, not a proof of unreachability.
    * Applying it requires elevation AND changes the user's firewall, so it is
      opt-in and must be explicitly confirmed by the user before use.

  ---------------------------------------------------------------------------
  ORDERING LAW (Lead, 2026-10-17, measured - do not violate)
  ---------------------------------------------------------------------------
  An ACL DENY on IDMan.exe BREAKS FRIDA SPAWN:
        frida.NotSupportedError: unable to spawn executable at '...\IDMan.exe':
        0x00000005            (ERROR_ACCESS_DENIED)
  Frida must be able to WRITE to the executable to inject, so `DENY(W,D)` kills it.
  Measured both ways: DENY present -> spawn fails; `icacls /remove:d Everyone` ->
  `OPEN-READWRITE OK` and the hash is unchanged.

  Therefore the hardening layers must be applied in THIS order:
    1. hosts block on the update/license domains (tonec.com is already in the list).
       This is the FIRST layer because it does not affect injection or deployment.
    2. firewall destination-limited outbound rule (this script) - also injection-safe.
    3. ACL `DENY(W,D)` on IDMan.exe - LAST, only after ALL dynamic observation,
       Frida work and re-deployment are finished.
  And before ANY deployment / Frida / rebuild step you MUST remove it again:
        icacls "C:\Program Files (x86)\Internet Download Manager\IDMan.exe" /remove:d Everyone
  A DENY on the exe also blocks READ with the Low-IL sandbox token (measured:
  "read denied" while the rule was in place), which additionally breaks read-only
  byte verification of the installed binary.

  USAGE (needs elevation to change the firewall)
    powershell -NoProfile -ExecutionPolicy Bypass -File firewall-block.ps1 -Action status
    powershell -NoProfile -ExecutionPolicy Bypass -File firewall-block.ps1 -Action add
    powershell -NoProfile -ExecutionPolicy Bypass -File firewall-block.ps1 -Action remove

  NOTE: this session's Low-IL token cannot write work/** , so when invoked without
  elevation the script writes its log to %TEMP% instead of failing silently.
#>
[CmdletBinding()]
param(
  [ValidateSet('add','remove','status')]
  [string]$Action = 'status',
  [string]$ExePath = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe',
  [string]$RuleNameOut = 'IDM-Activator-Block-License',
  # Destination limit. 67.18.0.0/16 = the IDM-owned range our nslookup control
  # measured (67.18.60.145 for www/secure, 67.18.140.140 for register);
  # 169.62.35.21 = measured for tonec.com. NEVER remove this clause - see the
  # "DO NOT SIMPLIFY" warning in the header.
  [string]$RemoteIps = '67.18.0.0/16,169.62.35.21',
  [string]$LogDir = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify'
)
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# Log destination with a REAL writability probe. The first version of this script
# only wrapped New-Item in try/catch, but creating a directory and being able to
# create a FILE in it are different permissions: the DSH Low-IL sandbox token can
# see work/** yet cannot create files there, so New-Item succeeded, the log path
# was kept, and every single W() call then blew up with "Access to the path ...
# is denied" (measured). Probe with an actual write and fall back to %TEMP%.
function Test-DirWritable([string]$dir){
  try{
    $probe = Join-Path $dir ('.wprobe-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($probe,'x')
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    return $true
  }catch{ return $false }
}
try { New-Item -ItemType Directory -Force -Path $LogDir -ErrorAction Stop | Out-Null } catch {}
$LogDirEffective = $LogDir
$logFallback = $false
if(-not (Test-DirWritable $LogDirEffective)){ $LogDirEffective = $env:TEMP; $logFallback = $true }
$log = Join-Path $LogDirEffective ("firewall-block-$stamp.log")
# W() always emits to the pipeline (so the caller sees everything even when logging
# is degraded) and only best-effort appends to the file.
function W($m){
  $m
  try{ Add-Content -LiteralPath $log -Value $m -ErrorAction Stop }catch{}
}
if($logFallback){
  W ("!! NOTE: {0} is not writable by this token - logging to {1}" -f $LogDir,$env:TEMP)
}

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

W ("=== firewall-block action={0}  {1} ===" -f $Action,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("elevated = {0}" -f $elevated)
W ("log      = {0}" -f $log)

# The rule scopes to the program path AND a destination range, so:
#   * it survives the exe being REBUILT as long as the path is unchanged (a new
#     build is still covered) - but if the install path ever changes the rule must
#     be recreated, hence the explicit path in every netsh call and in status;
#   * the RemoteIP clause is what keeps ordinary downloads working. `status`
#     MUST therefore print RemoteIP and flag a missing/blank value as a failure,
#     otherwise a blanket-block regression would silently pass review.
function Show-Rules {
  $raw = (& netsh advfirewall firewall show rule name="$RuleNameOut" 2>&1 | Out-String)
  $exists = ($LASTEXITCODE -eq 0) -and ($raw -notmatch 'No rules match|没有与指定条件匹配的规则')
  W ("rule '{0}' exists = {1}" -f $RuleNameOut,$exists)
  if(-not $exists){ return $false }
  foreach($l in ($raw -split "`r?`n")){
    if($l.Trim()){ W ("   " + $l.Trim()) }
  }
  # --- self-check: prove the rule is DESTINATION-LIMITED, not a blanket block ---
  $remote = [regex]::Match($raw,'(?im)^\s*RemoteIP:\s*(.+?)\s*$')
  $action = [regex]::Match($raw,'(?im)^\s*Action:\s*(.+?)\s*$')
  $dirn   = [regex]::Match($raw,'(?im)^\s*Direction:\s*(.+?)\s*$')
  $remoteVal = if($remote.Success){ $remote.Groups[1].Value.Trim() } else { '' }
  W ("SELF-CHECK RemoteIP value  = '{0}'" -f $remoteVal)
  W ("SELF-CHECK Action          = '{0}'" -f $(if($action.Success){$action.Groups[1].Value.Trim()}else{''}))
  W ("SELF-CHECK Direction       = '{0}'" -f $(if($dirn.Success){$dirn.Groups[1].Value.Trim()}else{''}))
  $destLimited = ($remoteVal -ne '') -and ($remoteVal -notmatch 'Any') -and ($remoteVal -match '67\.18\.')
  $isOutbound  = ($dirn.Success) -and ($dirn.Groups[1].Value -match 'Out')
  if($destLimited -and $isOutbound){
    W "SELF-CHECK RESULT = PASS (outbound AND destination-limited -> downloads to other hosts unaffected)"
  } else {
    W "SELF-CHECK RESULT = FAIL"
    if(-not $destLimited){ W "   !! RemoteIP is missing/'Any'/does not contain 67.18. -> THIS IS A BLANKET BLOCK and WILL BREAK DOWNLOADS. Remove it at once: -Action remove" }
    if(-not $isOutbound){ W "   !! Direction is not Out - inbound may have been touched by mistake." }
  }
  return $exists
}

switch($Action){
  'status' {
    W ("target exe      = {0}" -f $ExePath)
    W ("target present  = {0}" -f (Test-Path -LiteralPath $ExePath))
    [void](Show-Rules)
  }
  'add' {
    if(-not $elevated){ W "!! ABORT: adding a firewall rule requires elevation."; W "=== done ==="; exit 2 }
    if(-not (Test-Path -LiteralPath $ExePath)){ W ("!! ABORT: exe not found: {0}" -f $ExePath); W "=== done ==="; exit 3 }
    # HARD GUARD: refuse to create a blanket program block. Without this clause the
    # rule would cut ALL of IDM's outbound traffic and destroy its download
    # functionality - the single worst side effect this script could have.
    if([string]::IsNullOrWhiteSpace($RemoteIps) -or $RemoteIps -match '(?i)any'){
      W ("!! ABORT: -RemoteIps is empty or 'any' ('{0}')." -f $RemoteIps)
      W "!! A program-scoped block with no destination limit breaks IDM's downloads."
      W "!! Refusing to apply. Pass e.g. -RemoteIps '67.18.0.0/16,169.62.35.21'."
      W "=== done ==="; exit 4
    }
    # idempotent: delete-then-add so repeated runs do not stack duplicate rules
    & netsh advfirewall firewall delete rule name="$RuleNameOut" 2>&1 | Out-Null
    W ("applying DESTINATION-LIMITED outbound block:")
    W ("  name    = {0}" -f $RuleNameOut)
    W ("  program = {0}" -f $ExePath)
    W ("  remoteip= {0}" -f $RemoteIps)
    $out = (& netsh advfirewall firewall add rule name="$RuleNameOut" dir=out program="$ExePath" remoteip="$RemoteIps" action=block enable=yes profile=any 2>&1 | Out-String)
    W $out
    W ("add exitcode = {0}" -f $LASTEXITCODE)
    [void](Show-Rules)
  }
  'remove' {
    if(-not $elevated){ W "!! ABORT: removing a firewall rule requires elevation."; W "=== done ==="; exit 2 }
    $out = (& netsh advfirewall firewall delete rule name="$RuleNameOut" 2>&1 | Out-String)
    W $out
    W ("delete exitcode = {0}" -f $LASTEXITCODE)
    $still = Show-Rules
    if($still){ W "!! rule still present after delete" } else { W "rule removed" }
  }
}
W "--- manual rollback command (documented for the final report) ---"
W ("  netsh advfirewall firewall delete rule name=`"{0}`"" -f $RuleNameOut)
W "--- manual re-apply command (NOTE the mandatory remoteip= clause) ---"
W ("  netsh advfirewall firewall add rule name=`"{0}`" dir=out program=`"{1}`" remoteip=`"{2}`" action=block enable=yes profile=any" -f $RuleNameOut,$ExePath,$RemoteIps)
W "--- WARNING: do NOT re-apply without remoteip=. The bare form"
W "    (program + action=block, no remoteip) is a BLANKET outbound block and"
W "    destroys IDM's download functionality. ---"
W "=== done ==="
