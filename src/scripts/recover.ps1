$ErrorActionPreference = 'Continue'
$log = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\recover.txt'
$d   = 'C:\Program Files (x86)\Internet Download Manager'
$lines = @()

# 1) 停 IDM
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'IDMan*' } |
    ForEach-Object { $lines += "kill $($_.ProcessName)"; try { $_.Kill() } catch {} }
Start-Sleep -Seconds 3

# 2) 删掉假序列号（HKLM 32位视图 + 原生 + HKCU）
foreach ($pair in @(@('HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager','HKLM-wow'),
                    @('HKLM:\SOFTWARE\Internet Download Manager','HKLM-native'),
                    @('HKCU:\Software\Internet Download Manager','HKCU'))) {
    $k = $pair[0]
    if (Test-Path $k) {
        foreach ($n in @('Serial','FName','LName','Email')) {
            try { Remove-ItemProperty -Path $k -Name $n -ErrorAction Stop; $lines += "DEL $($pair[1])\$n" } catch {}
        }
    }
}

# 3) 删掉 scansk（IDM 会重新生成）
try {
    Remove-ItemProperty -Path 'HKCU:\Software\DownloadManager' -Name 'scansk' -ErrorAction Stop
    $lines += "DEL HKCU\Software\DownloadManager\scansk"
} catch { $lines += "scansk 删除失败: $($_.Exception.Message)" }

# 4) 还原 IDMan.exe 为官方 b15 原版（消除 P4 补丁这个因素）
$exe = Join-Path $d 'IDMan.exe'
$bak = Join-Path $d 'IDMan.exe.bak-original'
if (Test-Path $bak) {
    Copy-Item -LiteralPath $bak -Destination $exe -Force
    $lines += "RESTORED IDMan.exe <- bak-original"
    $lines += "  sha256 = $((Get-FileHash $exe -Algorithm SHA256).Hash)"
}

# 5) 清掉可能存在的 MData
foreach ($g in @('{a9cb9766-0322-447b-b63a-8b68ebf27b3f}','{E6871B76-C3C8-44DD-B947-ABFFE144860D}')) {
    foreach ($r in @('HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID','HKCU:\Software\Classes\CLSID')) {
        $p = "$r\$g"
        if (Test-Path $p) {
            try { Remove-Item -Path $p -Recurse -Force; $lines += "DEL $p" } catch { $lines += "FAIL del $p" }
        }
    }
}

Set-Content -LiteralPath $log -Value ($lines -join "`n") -Encoding utf8
