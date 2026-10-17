foreach($k in @("HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager","HKLM:\SOFTWARE\Internet Download Manager","HKCU:\Software\Internet Download Manager")){
  if(Test-Path $k){ foreach($n in @("Serial","FName","LName","Email")){ try{ Remove-ItemProperty -Path $k -Name $n -ErrorAction Stop }catch{} } }
}
$s=(Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager" -ErrorAction SilentlyContinue).Serial
Set-Content -LiteralPath "D:\pojie应用\jiesuo\work\idm-6.43b8\logs\del2.txt" -Value ("Serial=" + $(if($s){"[$s] 仍在"}else{"已清空"})) -Encoding utf8
