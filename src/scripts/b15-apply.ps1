$ErrorActionPreference = 'Continue'
$log = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\b15-apply.txt'
$w   = 'D:\pojie应用\jiesuo\work\idm-6.43b8'
$d   = 'C:\Program Files (x86)\Internet Download Manager'
$py  = 'C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe'
$lines = @()

# 1) 停掉 IDM
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'IDMan*' } |
    ForEach-Object { $lines += "kill $($_.ProcessName) pid=$($_.Id)"; try { $_.Kill() } catch {} }
Start-Sleep -Seconds 4

# 2) 把「旧 b8 版」的备份挪开，避免它冒充 b15 的备份
$bak = Join-Path $d 'IDMan.exe.bak-original'
$b8  = Join-Path $d 'IDMan.exe.bak-b8-643b8'
if (Test-Path $bak) {
    $h = (Get-FileHash $bak -Algorithm SHA256).Hash
    if ($h -eq '74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8') {
        if (Test-Path $b8) { Remove-Item $b8 -Force }
        Move-Item $bak $b8 -Force
        $lines += "MOVED stale b8 backup -> IDMan.exe.bak-b8-643b8"
    } else {
        $lines += "backup is NOT b8 (hash $h) - leaving as is"
    }
} else {
    $lines += "no existing backup"
}

# 3) 跑工具（会自动重新备份 b15 原版并施加 P1..P4）
$lines += "---- IDM-Unlock.py --apply --allow-update ----"
$out = & $py "$w\IDM-Unlock.py" --apply --allow-update 2>&1
$lines += ($out | Out-String)

Set-Content -LiteralPath $log -Value ($lines -join "`n") -Encoding utf8
