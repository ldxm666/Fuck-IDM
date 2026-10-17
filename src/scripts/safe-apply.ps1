$ErrorActionPreference = 'Continue'
$log = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\safe-apply.txt'
$w   = 'D:\pojie应用\jiesuo\work\idm-6.43b8'
$py  = 'C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe'
$lines = @()

# 1) 停 IDM
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'IDMan*' } |
    ForEach-Object { try { $_.Kill() } catch {} }
Start-Sleep -Seconds 3

# 2) 移除之前那条防火墙拦截规则（counterfeit 是本地判定的，拦网络没用，反而可能影响下载）
$rule = Get-NetFirewallRule -DisplayName 'IDM-Activator-BlockLicenseServer' -ErrorAction SilentlyContinue
if ($rule) {
    $rule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $lines += 'REMOVED firewall rule IDM-Activator-BlockLicenseServer'
} else {
    $lines += 'no firewall rule to remove'
}

# 3) 确保注册表里没有假序列号残留（那是 counterfeit 的源头）
foreach ($k in @('HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager',
                 'HKLM:\SOFTWARE\Internet Download Manager',
                 'HKCU:\Software\Internet Download Manager')) {
    if (Test-Path $k) {
        foreach ($n in @('Serial','FName','LName','Email')) {
            try { Remove-ItemProperty -Path $k -Name $n -ErrorAction Stop; $lines += "DEL $k\$n" } catch {}
        }
    }
}

# 4) 施加安全补丁：P1+P2+P3（工具已确认不含 P4、不写序列号）
$lines += '---- IDM-Activator.py --apply --no-guard ----'
$out = & $py "$w\IDM-Activator.py" --apply --no-guard 2>&1
$lines += ($out | Out-String)

Set-Content -LiteralPath $log -Value ($lines -join "`n") -Encoding utf8
