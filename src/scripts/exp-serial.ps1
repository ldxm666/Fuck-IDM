# exp-serial.ps1 — controlled A/B experiment: is `MData` a counterfeit marker
# or just IDM's benign registration record?
#
# Observation that motivates this:
#   * With a forged serial in HKLM, MData kept appearing in
#     HKCU\Software\Classes\Wow6432Node\CLSID\{79873CC5-...} (the CRegistrationDlg
#     store, whose siblings are Model / Therad / SpecVersion).
#   * With the serial deleted, no MData appeared -- but IDM raised a modal
#     "registration" dialog, which also blocks its timer loop.
#
# So "no MData" could be a real effect or an artifact of the modal dialog.
# This script isolates it.
#
# Safety: applies a firewall block on IDMan.exe -> the license/update endpoint
# BEFORE writing any serial, so a forged serial can never be uploaded to
# secure.internetdownloadmanager.com and flagged server-side.
#
# Run ELEVATED. Reversible: delete the Serial value, clear MData, remove the
# firewall rule named below.

param(
    [ValidateSet('with-serial','no-serial')]
    [string]$Mode = 'with-serial',
    [string]$Serial = 'A7K2M-P9Q4T-VB3XN-6WR8D'
)

$ErrorActionPreference = 'Continue'
$root = 'D:\pojie应用\jiesuo\work\idm-6.43b8'
$log  = Join-Path $root ("logs\experiment\exp-serial-{0}.log" -f $Mode)
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
function W($m) { $m | Tee-Object -FilePath $log -Append }

$RULE = 'IDM-Activator-BlockLicenseServer'
$IP   = '67.18.60.145'
$EXE  = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$KEY  = 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager'

W ("=== exp-serial mode={0} {1} ===" -f $Mode, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# 0) stop IDM so nothing rewrites state mid-experiment
Get-Process | Where-Object { $_.ProcessName -like 'IDM*' } | ForEach-Object {
    W ("kill {0} pid {1}" -f $_.ProcessName, $_.Id); $_.Kill()
}
Start-Sleep -Milliseconds 800

# 1) safety net: block the license/update endpoint for IDMan.exe only
if (-not (Get-NetFirewallRule -DisplayName $RULE -ErrorAction SilentlyContinue)) {
    try {
        New-NetFirewallRule -DisplayName $RULE -Direction Outbound -Action Block `
            -Enabled True -Profile Any -Program $EXE -RemoteAddress $IP | Out-Null
        W "firewall rule CREATED (block outbound IDMan.exe -> $IP)"
    } catch { W ("firewall rule FAILED: {0}" -f $_.Exception.Message) }
} else { W "firewall rule already present" }
$r = Get-NetFirewallRule -DisplayName $RULE -ErrorAction SilentlyContinue
W ("firewall state: {0}" -f $(if ($r) { "$($r.Enabled)/$($r.Action)" } else { 'MISSING' }))

# 2) clear every MData value so the run starts from a known-clean state
$trees = @(
    'HKCU:\Software\Classes\CLSID',
    'HKCU:\Software\Classes\Wow6432Node\CLSID',
    'HKLM:\SOFTWARE\Classes\CLSID',
    'HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID'
)
$n = 0
foreach ($t in $trees) {
    if (-not (Test-Path $t)) { continue }
    Get-ChildItem $t -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $_.PSPath
        $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
        if ($props -and ($props.PSObject.Properties.Name -contains 'MData')) {
            try { Remove-ItemProperty -Path $p -Name 'MData' -Force -ErrorAction Stop; $script:n++
                  W ("cleared MData at {0}" -f $_.Name) } catch {}
        }
    }
}
W ("MData cleared: {0}" -f $n)

# 3) set the registration state for this arm of the experiment
if ($Mode -eq 'with-serial') {
    # format-valid per the recovered check: len==23, '-' at idx 5/11/17
    foreach ($kv in @{Serial=$Serial; FName='Lo'; LName='Tester'; Email='lo@example.com'}.GetEnumerator()) {
        try {
            New-ItemProperty -Path $KEY -Name $kv.Key -Value $kv.Value -PropertyType String -Force | Out-Null
            W ("set {0} = {1}" -f $kv.Key, $kv.Value)
        } catch { W ("FAILED set {0}: {1}" -f $kv.Key, $_.Exception.Message) }
    }
} else {
    foreach ($v in 'Serial','FName','LName','Email') {
        try { Remove-ItemProperty -Path $KEY -Name $v -Force -ErrorAction Stop; W ("removed {0}" -f $v) }
        catch { W ("skip {0}" -f $v) }
    }
}

# 4) verify
$cur = Get-ItemProperty -Path $KEY -ErrorAction SilentlyContinue
W ("Serial now = '{0}'" -f $cur.Serial)
W "=== exp-serial done ==="
