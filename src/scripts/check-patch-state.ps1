#Requires -Version 5.1
<#
    check-patch-state.ps1  —  IDM 6.43b8 补丁状态回检（只读）

    作用
      1) 计算 C:\Program Files (x86)\Internet Download Manager\IDMan.exe 的 SHA256，
         与「补丁值 / 原始值」比对，判断补丁是否还在。
      2) 直接读两个补丁点的字节做交叉校验（区分「被我们打过」与「是另一个构建」）。
      3) 读 HKCU\Software\DownloadManager 的更新相关值，算出自动更新门控是否打开
         （LastCheckQU 距今 > 6 天即打开，见 IDMan.exe FUN_00456BC0 @ VA 0x00456BC0）。
      4) 若补丁已丢失，直接打印可复制的重打命令。

    安全性
      本脚本只读：不启动 IDMan.exe，不修改任何文件、注册表项或 ACL。

    退出码
      0 = 补丁在位 (PATCHED)
      2 = 已回退为原始版本 (REVERTED)
      3 = 未知构建（既不是补丁值也不是原始值，patch_idm.py 的偏移很可能失效）
      4 = 找不到 IDMan.exe

    用法
      powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\check-patch-state.ps1
      powershell -ExecutionPolicy Bypass -File work\idm-6.43b8\scripts\check-patch-state.ps1 -Json
#>
[CmdletBinding()]
param(
    [string]$InstallDir     = 'C:\Program Files (x86)\Internet Download Manager',
    [string]$PatchedSha256  = '527E8EDB30DD42038F1C985A135CEA6A7258E6FA9BEB6283E743F49B392BE552',
    [string]$OriginalSha256 = '74F177C8A44A6FEB95A88E1D8B385BC2683B4B87E7EF8BFE333A058C436CC9B8',
    [string]$PatchScript    = '',
    [switch]$Json
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------- paths
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$WorkDir   = Split-Path -Parent $ScriptDir                 # work\idm-6.43b8
$RepoRoot  = Split-Path -Parent (Split-Path -Parent $WorkDir)  # 仓库根

if (-not $PatchScript) {
    $PatchScript = Join-Path $WorkDir 'scripts\patch_idm.py'
}
$PristineExe  = Join-Path $WorkDir 'bin\IDMan.exe.orig'
$PatchedExe   = Join-Path $WorkDir 'bin\IDMan.patched.exe'
$DeployScript = Join-Path $WorkDir 'scripts\deploy.ps1'

$ExePath = Join-Path $InstallDir 'IDMan.exe'

# ---------------------------------------------------------------- patch sites
# 与 scripts\patch_idm.py 的 PATCHES 一一对应（文件偏移 / 原始字节 / 补丁字节）
$PatchSites = @(
    [pscustomobject]@{
        Name     = 'registration_flag_init'
        Va       = 'VA 0x00779CDC (g_registered .data 初始化)'
        Offset   = 0x3782DC
        Original = '01 00 00 00'
        Patched  = '00 00 00 00'
    },
    [pscustomobject]@{
        Name     = 'trial_nag_neutralized'
        Va       = 'VA 0x0047D2C0 (FUN_0047d2c0 试用提示)'
        Offset   = 0x7C6C0
        Original = 'A1 04 89 78 00'
        Patched  = 'E9 38 00 00 00'
    }
)

# ---------------------------------------------------------------- helpers
function Convert-HexToBytes([string]$Hex) {
    $clean = ($Hex -replace '[^0-9A-Fa-f]', '')
    $out = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $out.Length; $i++) {
        $out[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return ,$out
}

function Format-Bytes([byte[]]$Bytes) {
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join ' ')
}

function Test-BytesEqual([byte[]]$A, [byte[]]$B) {
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
    return $true
}

function Get-SiteState([byte[]]$All, [int]$Offset, [string]$OriginalHex, [string]$PatchedHex) {
    $orig = Convert-HexToBytes $OriginalHex
    $pat  = Convert-HexToBytes $PatchedHex
    if ($Offset -lt 0 -or ($Offset + $orig.Length) -gt $All.Length) {
        return [pscustomobject]@{ State = 'out-of-range'; Actual = '' }
    }
    $cur = New-Object byte[] $orig.Length
    [Array]::Copy($All, $Offset, $cur, 0, $orig.Length)
    $state = 'unknown'
    if (Test-BytesEqual $cur $pat) { $state = 'patched' }
    elseif (Test-BytesEqual $cur $orig) { $state = 'original' }
    return [pscustomobject]@{ State = $state; Actual = (Format-Bytes $cur) }
}

# ---------------------------------------------------------------- collect
$result = [ordered]@{
    checkedAt        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    installDir       = $InstallDir
    exePath          = $ExePath
    exists           = $false
    size             = $null
    sha256           = $null
    expectedPatched  = $PatchedSha256.ToUpper()
    expectedOriginal = $OriginalSha256.ToUpper()
    verdict          = 'MISSING'
    exitCode         = 4
    patchSites       = @()
    registry         = [ordered]@{}
    notes            = @()
}

$lines = New-Object System.Collections.Generic.List[string]
function Say([string]$s) { $lines.Add($s) | Out-Null }

Say '=================================================================='
Say ' IDM 6.43b8 补丁状态回检 (check-patch-state.ps1)'
Say '=================================================================='
Say (" 检查时间 : {0}" -f $result.checkedAt)
Say (" 安装目录 : {0}" -f $InstallDir)
Say ''

if (-not (Test-Path -LiteralPath $ExePath)) {
    Say (" [X] 找不到 {0}" -f $ExePath)
    Say '     结论: IDM 未安装或路径不对，无法回检。'
    $result.notes += 'IDMan.exe not found'
    if ($Json) { $result | ConvertTo-Json -Depth 6 }
    else { $lines | ForEach-Object { Write-Host $_ } }
    exit 4
}

$result.exists = $true
$item = Get-Item -LiteralPath $ExePath
$result.size = $item.Length

try {
    $hash = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash.ToUpper()
    $result.sha256 = $hash
}
catch {
    Say (" [X] 读取/哈希失败: {0}" -f $_.Exception.Message)
    Say '     提示: 若 IDMan.exe 正在运行通常也能读；失败多为权限或文件被独占。'
    $result.notes += $_.Exception.Message
    if ($Json) { $result | ConvertTo-Json -Depth 6 }
    else { $lines | ForEach-Object { Write-Host $_ } }
    exit 4
}

Say '--- 1) IDMan.exe 哈希 ---'
Say (" 路径     : {0}" -f $ExePath)
Say (" 大小     : {0}" -f $item.Length)
Say (" 属性     : {0}" -f $item.Attributes)
Say (" 修改时间 : {0}" -f $item.LastWriteTime)
Say (" SHA256   : {0}" -f $hash)
Say (" 期望(补丁): {0}" -f $PatchedSha256.ToUpper())
Say (" 期望(原始): {0}" -f $OriginalSha256.ToUpper())
Say ''

if ($hash -eq $PatchedSha256.ToUpper()) {
    $result.verdict = 'PATCHED'
    $result.exitCode = 0
    Say ' [OK] 哈希 == 补丁值  ->  补丁在位。'
}
elseif ($hash -eq $OriginalSha256.ToUpper()) {
    $result.verdict = 'REVERTED'
    $result.exitCode = 2
    Say ' [!!] 哈希 == 原始值  ->  补丁已被回退（IDM 被更新/重装覆盖）。'
}
else {
    $result.verdict = 'UNKNOWN'
    $result.exitCode = 3
    Say ' [??] 哈希既不是补丁值也不是原始值  ->  未知构建（很可能是新版本）。'
}

# ---------------------------------------------------------------- patch sites
Say ''
Say '--- 2) 补丁点字节交叉校验 ---'
$all = [System.IO.File]::ReadAllBytes($ExePath)
foreach ($site in $PatchSites) {
    $st = Get-SiteState -All $all -Offset $site.Offset -OriginalHex $site.Original -PatchedHex $site.Patched
    $tag = switch ($st.State) {
        'patched'  { '[OK] 已打补丁' }
        'original' { '[!!] 原始字节' }
        default    { '[??] 不认识' }
    }
    Say (" {0}  {1}  @ file 0x{2:X8}  ({3})" -f $tag, $site.Name, $site.Offset, $site.Va)
    Say ("        原始 = {0}" -f $site.Original)
    Say ("        补丁 = {0}" -f $site.Patched)
    Say ("        实测 = {0}" -f $st.Actual)
    $result.patchSites += [pscustomobject]@{
        name    = $site.Name
        offset  = ('0x{0:X8}' -f $site.Offset)
        va      = $site.Va
        state   = $st.State
        actual  = $st.Actual
    }
}

# ---------------------------------------------------------------- registry
Say ''
Say '--- 3) 注册表 HKCU\Software\DownloadManager（自动更新门控）---'
$regPath = 'HKCU:\Software\DownloadManager'
$reg = $null
try { $reg = Get-ItemProperty -LiteralPath $regPath -ErrorAction Stop } catch { $reg = $null }

if ($null -eq $reg) {
    Say (" [??] 读不到 {0}" -f $regPath)
    $result.notes += 'registry key unreadable'
    $result.registry['key'] = $regPath
    $result.registry['readable'] = $false
}
else {
    $result.registry['key'] = $regPath
    $result.registry['readable'] = $true

    $lastRaw = $reg.PSObject.Properties['LastCheckQU']
    if ($null -eq $lastRaw) {
        Say ' LastCheckQU : <缺失>'
        Say '   门控判定  : 打开 —— 值缺失时 FUN_00456BC0 直接返回 true，每次启动都会到期。'
        $result.registry['LastCheckQU'] = $null
        $result.registry['gateOpen'] = $true
        $result.registry['daysSinceLastCheck'] = $null
    }
    else {
        $lastVal = [int64]$lastRaw.Value
        $lastTime = [DateTimeOffset]::FromUnixTimeSeconds($lastVal).ToLocalTime()
        $days = ((Get-Date) - $lastTime.DateTime).TotalDays
        $wholeDays = [math]::Floor($days)
        $gateOpen = ($wholeDays -gt 6)     # FUN_00456BC0: return 6 < (now-last)/86400
        Say (" LastCheckQU : {0}  ->  {1}" -f $lastVal, $lastTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))
        Say ("   距今      : {0} 天" -f [math]::Round($days, 2))
        Say ("   门控判定  : {0}" -f $(if ($gateOpen) {
                '打开 —— 下次启动 IDMan.exe 会挂 UPDATE_TIMER(60s) 自动发起更新检查'
            } else {
                ("关闭 —— 还需约 {0} 天才到期" -f (7 - $wholeDays))
            }))
        Say '   （阈值来自 FUN_00456BC0 @ VA 0x00456BC0：6 < (time(NULL)-LastCheckQU)/86400）'
        $result.registry['LastCheckQU'] = $lastVal
        $result.registry['LastCheckQUTime'] = $lastTime.ToString('yyyy-MM-dd HH:mm:ss zzz')
        $result.registry['daysSinceLastCheck'] = [math]::Round($days, 2)
        $result.registry['gateOpen'] = $gateOpen
    }

    foreach ($name in @('CheckUpdtVM', 'LstCheck', 'idmvers', 'vCOUFP')) {
        $p = $reg.PSObject.Properties[$name]
        $v = if ($null -eq $p) { '<缺失>' } else { [string]$p.Value }
        Say (" {0,-12}: {1}" -f $name, $v)
        $result.registry[$name] = $v
    }
    Say ' 说明: CheckUpdtVM 在 IDMan.exe 内只写不读（唯一 xref = 0x0045A1AC），不能当开关用。'
}

# ---------------------------------------------------------------- verdict
Say ''
Say '--- 4) 结论 ---'
$pythonCmd = 'python "{0}" "{1}" "{2}"' -f $PatchScript, $PristineExe, $PatchedExe
$deployCmd = 'powershell -ExecutionPolicy Bypass -File "{0}" -Patched "{1}"' -f $DeployScript, $PatchedExe

switch ($result.verdict) {
    'PATCHED' {
        Say ' [OK] 补丁在位，IDMan.exe 仍是我们的构建。'
        Say '      提醒: 保持 LastCheckQU 新鲜（每 <=6 天刷成当前 Unix 时间）可让自动更新门控一直关闭：'
        Say '        Set-ItemProperty -Path ''HKCU:\Software\DownloadManager'' -Name LastCheckQU `'
        Say '            -Value ([int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -Type DWord'
    }
    'REVERTED' {
        Say ' [!!] 补丁已被回退：IDMan.exe 现在是原始版本（被 IDM 自动更新/重装覆盖）。'
        Say '      请重新打补丁并部署：'
        Say ("        {0}" -f $pythonCmd)
        Say ("        {0}" -f $deployCmd)
        Say '      重打前建议先关闭 IDMan.exe（部署脚本会自己杀进程）。'
        Say '      并参考 work\idm-6.43b8\patches\update-lockdown.md 第 3 节做防回退。'
    }
    'UNKNOWN' {
        Say ' [??] 未知构建：既不是补丁值也不是原始值。'
        Say '      这通常意味着 IDM 被升级到了新版本，patch_idm.py 里的文件偏移很可能已经失效。'
        Say '      不要盲目重打 —— 先用 --list 复核，再重新定位补丁点：'
        Say ('        python "{0}" --list' -f $PatchScript)
        Say '      然后在 work\idm-6.43b8\patches\update-lockdown.md 记录新版本与新的补丁点。'
        if ($null -ne $result.registry['idmvers']) {
            Say ("      注册表 idmvers = {0}" -f $result.registry['idmvers'])
        }
    }
    default {
        Say ' [X] 无法判定。'
    }
}
Say ''
Say '=================================================================='

# ---------------------------------------------------------------- emit
if ($Json) {
    $result | ConvertTo-Json -Depth 6
}
else {
    $lines | ForEach-Object { Write-Host $_ }
}

exit $result.exitCode
