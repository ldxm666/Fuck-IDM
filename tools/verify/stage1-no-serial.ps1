<#
  stage1-no-serial.ps1  - DRAFT, task-3 stage-1 item 3 deliverable.

  PURPOSE
    The previous deployer round completed with-serial 4/5 but NEVER ran the
    no-serial mode. This driver runs verify-run3.ps1 -Mode no-serial 5 x 300s.

  WHAT IT ADDS OVER THE OLD drive3-no-serial.ps1 (which must NOT be reused as-is)
    * the old DNS precondition used `ping` and the old permanent-fix script's
      `$ping -match '67\.18\.'` test. That test DOES NOT match the real blocked
      output ("Ping request could not find host ...", exit 1), so it is a broken
      oracle. Here the oracle is Resolve-DnsName, which must return 0.0.0.0.
    * pre-flight: refuses to start if any IDMan.exe is already running, or if the
      expected binary sha256 does not match -ExpectedSha (the T1 hand-off hash).
    * records the filtered/elevated token state and ABORTS early (with a clear
      message) if not elevated, because verify-run3.ps1 cannot read HKLM CLSID
      keys with a filtered token and would silently under-report MData.
    * records all evidence paths up front so stage 2 can paste them straight
      into the report.

  RUN FROM AN ELEVATED POWERSHELL:
    powershell -NoProfile -ExecutionPolicy Bypass -File `
      D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\stage1-no-serial.ps1 `
      -ExpectedSha <T1 sha256>
#>
[CmdletBinding()]
param(
  [string]$Mode           = 'no-serial',
  [int]   $Runs           = 5,
  [int]   $SoakSeconds    = 300,
  [string]$ExpectedSha    = '',      # '' = skip the hash assert (baseline runs)
  [string]$FixScript      = 'D:\pojie应用\jiesuo\work\idm-6.43b8\scripts\idm-permanent-fix.ps1',
  [string]$Harness        = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\verify-run3.ps1',
  [string]$OutDir         = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify'
)
$ErrorActionPreference = 'Continue'
$EXE = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $OutDir ("stage1-$Mode-$stamp.log")
function W($m){ $m | Tee-Object -FilePath $log -Append }
function Fail($m){ W ("!! ABORT: {0}" -f $m); W "=== stage1 $Mode ABORTED ==="; exit 2 }

W ("=== stage1 $Mode driver  {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("log = {0}" -f $log)

# ---- 0) token / elevation -------------------------------------------------
$elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
W ("elevated = {0}" -f $elev)
if(-not $elev){
  # Distinguish "not admin at all" from "admin with a filtered token" (UAC).
  $grp = (& whoami /groups 2>&1 | Out-String)
  $denyOnly = $grp -match 'BUILTIN\\Administrators.*deny only'
  W ("token looks like: {0}" -f ($(if($denyOnly){'Administrator with FILTERED token (UAC, deny-only)'}else{'non-admin user'})))
  Fail "not elevated. verify-run3.ps1 would read HKLM CLSID keys through a deny-only token and silently report mdata=0. Re-run from an elevated PowerShell."
}

# ---- 1) binary identity ---------------------------------------------------
$sha = (Get-FileHash $EXE -Algorithm SHA256).Hash
W ("installed sha256 = {0}" -f $sha)
if($ExpectedSha){
  if($sha -ne $ExpectedSha.ToUpper()){ Fail "installed sha256 != -ExpectedSha ($ExpectedSha). Wrong build deployed - refuse to burn 8x300s." }
  W  "sha256 matches -ExpectedSha"
} else {
  W "!! -ExpectedSha not supplied: this run records whatever is installed. Use it for BASELINE only."
}

# ---- 2) exclusive access: no IDM may be running ---------------------------
$run = @(Get-Process IDMan -ErrorAction SilentlyContinue)
if($run.Count -gt 0){
  Fail ("{0} IDMan.exe process(es) already running (pid {1}). Hosts/registry/Tasks are GLOBAL - another task is mid-run. Do not overlap." -f $run.Count, (($run|ForEach-Object{$_.Id}) -join ','))
}
W "no IDMan.exe running - exclusive access OK"

# ---- 3) force the mode, then verify it took -------------------------------
W "--- set RegMode=$Mode via idm-permanent-fix.ps1 ---"
W (& powershell -NoProfile -ExecutionPolicy Bypass -File $FixScript -RegMode $Mode 2>&1 | Out-String)
W "--- ipconfig /flushdns ---"
W (& ipconfig /flushdns 2>&1 | Out-String)

$c = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue
W ("post-apply registry: Serial='{0}' FName='{1}' LName='{2}' Email='{3}'" -f $c.Serial,$c.FName,$c.LName,$c.Email)
switch($Mode){
  'no-serial'   { if($c.Serial){ Fail "no-serial requested but HKLM Serial is still set ('$($c.Serial)')" } }
  'with-serial' { if(-not $c.Serial){ Fail "with-serial requested but HKLM Serial is empty" } }
  'names-only'  { if($c.Serial){ W "!! names-only requested but a Serial is present - continuing, but flag this" } }
}

# ---- 4) the ACCEPTED DNS oracle: Resolve-DnsName must be 0.0.0.0 ----------
$domains = @('internetdownloadmanager.com','www.internetdownloadmanager.com',
             'secure.internetdownloadmanager.com','register.internetdownloadmanager.com',
             'tonec.com','www.tonec.com')
$bad = 0
W "--- DNS precondition (Resolve-DnsName; 0.0.0.0 == blocked) ---"
foreach($d in $domains){
  $ips = try { @(Resolve-DnsName $d -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) } catch { @() }
  $ips = @($ips)
  $ok  = ($ips.Count -eq 1 -and [string]$ips[0] -eq '0.0.0.0')
  if(-not $ok){ $bad++ }
  W ("  {0,-38} -> {1}  blocked={2}" -f $d, (($ips -join ',') + $(if($ips.Count -eq 0){'<unresolved>'}else{''})), $ok)
}
if($bad -gt 0){ Fail "$bad domain(s) not mapping to 0.0.0.0 - the hosts block is NOT in force" }
W "DNS precondition OK (6/6 -> 0.0.0.0)"

# ---- 5) hand off to the harness ------------------------------------------
W "--- launching verify-run3.ps1 -Mode $Mode -Runs $Runs -SoakSeconds $SoakSeconds ---"
W (& powershell -NoProfile -ExecutionPolicy Bypass -File $Harness -Mode $Mode -Runs $Runs -SoakSeconds $SoakSeconds -OutDir $OutDir 2>&1 | Out-String)

# ---- 6) post-run reality check -------------------------------------------
$still = @(Get-Process IDMan -ErrorAction SilentlyContinue)
W ("post-run IDMan processes = {0} (harness kills at end of each run; non-zero here means a run leaked)" -f $still.Count)
W "--- newest soak3 csv ---"
$csv = Get-ChildItem (Join-Path $OutDir "soak3-$Mode-*.csv") -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
if($csv){ W ("csv = {0}" -f $csv.FullName); W (Get-Content $csv.FullName -Raw) } else { W "!! no soak3 csv found" }
W "--- summarise.py ---"
W (& python (Join-Path $OutDir 'summarize.py') ("soak3-$Mode-*.log") 2>&1 | Out-String)

# ---- 7) TWO-METRIC verdict (Lead decision 2026-10-17) --------------------
# The two metrics MUST be judged separately and both must pass.
#   [A] USABILITY   : survived the window, no crash, no nonzero exit, no popup.
#   [B] ROOT-CAUSE  : MData must be 0 for every t > 0. verify-run3.ps1 clears MData
#                     before each run and logs "MData PRESENT at <t>s" on every
#                     sample it is seen, so ANY such line means MData was written
#                     by IDM during the run. A nonzero count is an OPEN DEFECT -
#                     it must never be folded into a pass.
# Reference: the 15-point build wrote MData at ~62-64s in 5/5 with-serial runs and
# never cleaned it up (logs/verify/stage1-findings-mdata-20261017-0245.log).
#
# BUG FIXED HERE (found by self-test against an existing CSV): the CSV column is
# named `mdata_hits`, NOT `mdata`. Reading $r.mdata yields $null -> [int]$null is
# 0 -> metric [B] passed even for a run with 233 MData hits. A metric that cannot
# fail is worthless; this is the same class of defect as the old ping oracle.
W ""
W "=== TWO-METRIC VERDICT (mode=$Mode) ==="
$allCsv = Get-ChildItem (Join-Path $OutDir "soak3-$Mode-*.csv") -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
$rows = @()
if($csv){ $rows = @(Import-Csv $csv.FullName) }
$usageFail = @(); $rootFail = @()
foreach($r in $rows){
  $surv = [double]$r.survival_s
  $ucrash = ($r.outcome -notlike 'SURVIVED-*') -or ($r.exit_code_hex -ne '')
  $upop  = ($r.popup_counterfeit -eq 'True') -or ($r.popup_registration -eq 'True') -or ($r.popup_other -eq 'True')
  $mh    = if($null -eq $r.mdata_hits -or $r.mdata_hits -eq ''){ -1 } else { [int]$r.mdata_hits }
  if($mh -lt 0){ $rootFail += "run $($r.run) mdata_hits column MISSING/UNPARSEABLE - cannot score metric B" }
  elseif($mh -gt 0){ $rootFail += "run $($r.run) mdata_hits=$mh" }
  if($ucrash -or $upop -or ($surv -lt $SoakSeconds)){ $usageFail += "run $($r.run) (surv=$surv outcome=$($r.outcome) exit=$($r.exit_code_hex) popup=C:$($r.popup_counterfeit)/R:$($r.popup_registration)/O:$($r.popup_other))" }
}
W ("[A] USABILITY   : {0}" -f $(if($rows.Count -gt 0 -and $usageFail.Count -eq 0){'PASS'}else{'FAIL'}))
foreach($x in $usageFail){ W ("      FAIL " + $x) }
W ("[B] ROOT-CAUSE  : {0}{1}" -f $(if($rows.Count -gt 0 -and $rootFail.Count -eq 0){'PASS'}else{'FAIL'}), $(if($rootFail.Count -gt 0){'   <<< OPEN DEFECT - do NOT report as fixed'}else{''}))
foreach($x in $rootFail){ W ("      MData WRITTEN DURING RUN: " + $x) }
if($rows.Count -gt 0 -and $usageFail.Count -eq 0 -and $rootFail.Count -gt 0){
  W "      SHAPE: 'usable but root cause NOT eliminated' - this is the 15-point build's signature."
}
if($rows.Count -eq 0){ W "      (no CSV rows parsed - cannot score; treat as UNSCORED, not as pass)" }
W ("=== stage1 $Mode done (log={0}) ===" -f $log)
