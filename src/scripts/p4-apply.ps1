$ErrorActionPreference = 'Continue'
$w  = 'D:\pojie应用\jiesuo\work\idm-6.43b8'
$py = 'C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe'
$out = @()

# 1) 施加补丁（含新的 P4 counterfeit 闸门封堵）
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'IDMan*' } |
    ForEach-Object { try { $_.Kill() } catch {} }
Start-Sleep -Seconds 3
$out += '---- apply ----'
$out += (& $py "$w\IDM-Activator.py" --no-guard 2>&1 | Out-String)

# 2) 核对文件字节
$exe = 'C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$d = [System.IO.File]::ReadAllBytes($exe)
$seg = $d[0x4D252..0x4D257]
$out += '---- file 0x4D252 ----'
$out += ('  ' + (($seg | ForEach-Object { $_.ToString('x2') }) -join ' '))
$out += ('  sha256 = ' + (Get-FileHash $exe -Algorithm SHA256).Hash)

# 3) 决定性测试：删掉全部注册信息 -> 未打补丁时必然触发 counterfeit
$out += '---- 删除注册信息（制造"校验失败"条件）----'
foreach ($k in @('HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager',
                 'HKLM:\SOFTWARE\Internet Download Manager',
                 'HKCU:\Software\Internet Download Manager')) {
    if (Test-Path $k) {
        foreach ($n in @('Serial','FName','LName','Email')) {
            try { Remove-ItemProperty -Path $k -Name $n -ErrorAction Stop; $out += "  DEL $k\$n" } catch {}
        }
    }
}
$out += ('  剩余 Serial = ' + $(if((Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager' -ErrorAction SilentlyContinue).Serial){'仍存在'}else{'已清空'}))

# 4) 顺手清掉可能残留的 MData，保证测试起点干净
function Walk($path,$depth){ if($depth -gt 6){return}
  try{ $kk=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($path,$true) }catch{ return }
  if($null -eq $kk){ return }
  foreach($vn in $kk.GetValueNames()){ if($vn -ieq 'MData'){ try{ $kk.DeleteValue('MData'); $script:out += "  清 MData @ $path" }catch{} } }
  $kk.Close()
  $k2=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($path)
  if($k2){ foreach($sn in $k2.GetSubKeyNames()){ Walk "$path\$sn" ($depth+1) }; $k2.Close() } }
Walk 'Software\Classes\CLSID' 0
Walk 'Software\Classes\Wow6432Node\CLSID' 0

Set-Content -LiteralPath "$w\logs\p4-apply.txt" -Value ($out -join "`n") -Encoding utf8
