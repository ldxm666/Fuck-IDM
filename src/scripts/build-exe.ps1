# build-exe.ps1 — rebuild the single-file IDM unlocker and verify the artifact.
#
# The delivery contract (learned the hard way, do not regress):
#   --noconsole   : EXE Subsystem must be 2 (GUI). With --console the guard task
#                   used to flash a black window every run.
#   --uac-admin   : the tool must elevate to write Program Files + HKLM + hosts.
#   --onefile     : single-file deliverable.
#
# Verifies afterwards: PE subsystem == 2, and prints size + sha256.

param(
    [switch]$KeepWork
)

$ErrorActionPreference = 'Stop'
$w  = 'D:\pojie应用\jiesuo\work\idm-6.43b8'
$py = 'C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe'

$src = Join-Path $w 'IDM-Activator.py'
if (-not (Test-Path $src)) { throw "缺少源码 $src" }

Write-Host "=== 语法自检 ==="
& $py -m py_compile $src
if ($LASTEXITCODE -ne 0) { throw "py_compile 失败" }
Write-Host "  OK"

Write-Host "=== PyInstaller 打包 ==="
# 两个 PS5.1 下的坑（2026-10-17 实测，别改回去）：
#  1) PyInstaller 拒绝在 C:\Windows\system32 作为 CWD 时运行
#     （"ERROR: Do not run pyinstaller from C:\Windows\system32"）。
#     提权子进程（Start-Process -Verb RunAs）的 CWD 就是 system32，
#     所以必须显式切到工程目录再调用。
#  2) PyInstaller 把 INFO 日志写到 **stderr**；PS5.1 会把 native stderr
#     包成 NativeCommandError，配合本脚本顶部的 $ErrorActionPreference='Stop'
#     就变成**终止性错误** —— 表现为脚本在打印完这一行后直接 abort(exit 1)，
#     而同一命令行手工跑却成功。故此处临时放宽 EAP 并把 stderr 并流。
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
Push-Location $w
try {
    & $py -m PyInstaller --onefile --noconsole --uac-admin --name IDM-Activator `
        --distpath (Join-Path $w 'dist') `
        --workpath (Join-Path $w 'build_tmp') `
        --specpath (Join-Path $w 'build_tmp') `
        --noconfirm $src 2>&1 | ForEach-Object { Write-Host $_ }
    $rc = $LASTEXITCODE
} finally {
    Pop-Location
    $ErrorActionPreference = $prevEAP
}
if ($rc -ne 0) { throw "PyInstaller 失败 (exit $rc)" }

$exe = Join-Path $w 'dist\IDM-Activator.exe'
if (-not (Test-Path $exe)) { throw "未生成 $exe" }

Write-Host "=== 产物校验 ==="
$fi = Get-Item $exe
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
Write-Host ("  路径   : {0}" -f $exe)
Write-Host ("  大小   : {0:N0} 字节 ({1:N2} MB)" -f $fi.Length, ($fi.Length / 1MB))
Write-Host ("  sha256 : {0}" -f $hash)

# PE Subsystem 必须在可选头偏移 +68（PE32/PE32+ 相同）
$fs = [System.IO.File]::OpenRead($exe)
try {
    $br = New-Object System.IO.BinaryReader($fs)
    $fs.Position = 0x3C
    $e = $br.ReadInt32()
    $fs.Position = $e + 4 + 20 + 68
    $sub = $br.ReadUInt16()
} finally { $fs.Close() }

Write-Host ("  Subsystem : {0} ({1})" -f $sub, $(if ($sub -eq 2) { 'GUI - 无黑窗' } else { '非 GUI！黑窗会回归' }))
if ($sub -ne 2) { throw "Subsystem 不是 2，--noconsole 未生效" }

if (-not $KeepWork) {
    Remove-Item (Join-Path $w 'build_tmp') -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  已清理 build_tmp"
}
Write-Host "=== 完成 ==="
