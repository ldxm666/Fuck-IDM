param(
    [Parameter(Mandatory=$true)][string]$Cmd,
    [string]$Serial = "975aaf17"
)
$a = "C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe"
# Push a script to the device and run it as root, so quoting/UTF-8 in the command
# never gets mangled by sh -c '...' on the way through adb.
$local = Join-Path $env:TEMP ("mk-" + [guid]::NewGuid().ToString("N").Substring(0,8) + ".sh")
Set-Content -Path $local -Value $Cmd -Encoding UTF8
$remote = "/data/local/tmp/mk-run.sh"
& $a -s $Serial push $local $remote | Out-Null
& $a -s $Serial shell "su -c 'sh $remote'"
Remove-Item $local -Force
