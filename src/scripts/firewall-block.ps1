$ErrorActionPreference = 'Continue'
$log = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\firewall-block.txt'
$lines = @()

$IP    = '67.18.60.145'          # secure/www/internetdownloadmanager.com 全部解析到这一个 IP
$RULE  = 'IDM-Activator-BlockLicenseServer'
$EXE   = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe'

# 清掉旧规则
Get-NetFirewallRule -DisplayName $RULE -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# 出站阻断：只针对 IDMan.exe -> 该 IP
try {
    New-NetFirewallRule -DisplayName $RULE `
        -Description 'IDM-Activator: block IDM license/update server so a fake serial can never be flagged' `
        -Direction Outbound -Action Block -Enabled True -Profile Any `
        -Program $EXE -RemoteAddress $IP | Out-Null
    $lines += "CREATED firewall rule '$RULE' (block outbound IDMan.exe -> $IP)"
} catch { $lines += "FAIL create rule: $($_.Exception.Message)" }

# 回读确认
$r = Get-NetFirewallRule -DisplayName $RULE -ErrorAction SilentlyContinue
if ($r) {
    $lines += "  DisplayName = $($r.DisplayName)"
    $lines += "  Direction   = $($r.Direction)  Action = $($r.Action)  Enabled = $($r.Enabled)"
    ($r | Get-NetFirewallAddressFilter).RemoteAddress | ForEach-Object { $lines += "  RemoteAddress = $_" }
    ($r | Get-NetFirewallApplicationFilter).Program | ForEach-Object { $lines += "  Program = $_" }
} else { $lines += "  !! 规则未创建成功" }

Set-Content -LiteralPath $log -Value ($lines -join "`n") -Encoding utf8
