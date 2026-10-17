$ErrorActionPreference = 'Continue'
$log = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\hklm-serial.txt'
$lines = @()
try {
    $k = 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager'
    if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
    Set-ItemProperty -Path $k -Name 'Serial' -Value 'DQI64-NGF4D-VQ2KM-8NRZI' -Type String
    Set-ItemProperty -Path $k -Name 'FName'  -Value 'Lo'     -Type String
    Set-ItemProperty -Path $k -Name 'LName'  -Value 'Tester' -Type String
    Set-ItemProperty -Path $k -Name 'Email'  -Value 'lo@example.com' -Type String
    $lines += "WROTE $k"
    Get-ItemProperty $k | Select-Object Serial,FName,LName,Email | Format-List | Out-String | ForEach-Object { $lines += $_ }
} catch { $lines += "FAIL $($_.Exception.Message)" }
$text = $lines -join "`n"
Set-Content -LiteralPath $log -Value $text -Encoding utf8
