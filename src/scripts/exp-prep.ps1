# exp-prep.ps1 — prepare the "pure binary, no guard" experiment.
#
# Hypothesis under test:
#   The guard's forged `Serial` in HKLM is what makes IDM's periodic
#   registration check (CConfirm::OnTimer -> CRegistrationDlg store) treat the
#   install as counterfeit, write the 256-byte MData fingerprint, and exit.
#   The guard then deletes MData and rotates the serial, re-arming the trap.
#   If so, removing the forged serial removes the trigger entirely and no
#   daemon is needed.
#
# This script: disables the guard task, removes the forged registration values,
# and clears every MData value. It is fully reversible from
# logs\experiment\HKLM-IDM-backup.reg.
#
# Run ELEVATED. Writes its own log (cannot be redirected through RunAs).

$ErrorActionPreference = 'Continue'
$root = 'D:\pojie应用\jiesuo\work\idm-6.43b8'
$log  = Join-Path $root 'logs\experiment\exp-prep.log'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
function W($m) { $m | Tee-Object -FilePath $log -Append }

W ("=== exp-prep {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# 1) stop any running IDM so nothing rewrites state mid-experiment
Get-Process | Where-Object { $_.ProcessName -like 'IDM*' } | ForEach-Object {
    W ("kill {0} (pid {1})" -f $_.ProcessName, $_.Id); $_.Kill()
}
Start-Sleep -Milliseconds 500

# 2) disable the guard scheduled task
$out = schtasks /change /tn 'IDM-Activator-Guard' /disable 2>&1
W ("schtasks disable -> {0}" -f ($out -join ' '))
$q = schtasks /query /tn 'IDM-Activator-Guard' /fo LIST 2>&1 | Select-String 'Status'
W ("task status: {0}" -f ($q -join ' '))

# 3) remove the forged registration values from the HKLM 32-bit view
#    (a 32-bit process reading HKLM\SOFTWARE\... lands in WOW6432Node)
$k = 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager'
foreach ($v in 'Serial','FName','LName','Email') {
    try {
        $cur = (Get-ItemProperty -Path $k -Name $v -ErrorAction Stop).$v
        Remove-ItemProperty -Path $k -Name $v -Force -ErrorAction Stop
        W ("removed {0} (was '{1}')" -f $v, $cur)
    } catch { W ("skip {0}: {1}" -f $v, $_.Exception.Message) }
}

# 4) clear every MData value across all CLSID trees (both views, both hives)
$trees = @(
    'HKCU:\Software\Classes\CLSID',
    'HKCU:\Software\Classes\Wow6432Node\CLSID',
    'HKLM:\SOFTWARE\Classes\CLSID',
    'HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID',
    'HKLM:\SOFTWARE\Classes\Wow6432Node\CLSID'
)
$cleared = 0
foreach ($t in $trees) {
    if (-not (Test-Path $t)) { continue }
    Get-ChildItem $t -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $_.PSPath
        $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
        if ($props -and ($props.PSObject.Properties.Name -contains 'MData')) {
            try {
                Remove-ItemProperty -Path $p -Name 'MData' -Force -ErrorAction Stop
                W ("cleared MData at {0}" -f $_.Name)
                $script:cleared++
            } catch { W ("FAILED to clear MData at {0}: {1}" -f $_.Name, $_.Exception.Message) }
        }
    }
}
W ("MData values cleared: {0}" -f $cleared)

W "=== exp-prep done ==="
