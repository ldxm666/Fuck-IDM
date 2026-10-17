#Requires -Version 5.1
<#
    lockdown-update.ps1  —  IDM 6.43b8 防回退：冻结自动更新门控

    背景（证据见 work\idm-6.43b8\patches\update-lockdown.md）
      IDMan.exe 的自动更新检查由 FUN_00456BC0 @ VA 0x00456BC0 门控：

          LVar1 = RegQueryValueExA(HKCU\Software\DownloadManager, "LastCheckQU", ...);
          if (LVar1 == 0) { uVar2 = (time(NULL) - LastCheckQU) / 86400; return 6 < uVar2; }
          return true;                       // 值缺失 -> 永远到期

      门控到期时 FUN_004772B0 会在启动 60s 后挂 UPDATE_TIMER(timer id 5)，
      随后自动下载并启动提权更新器 idmupdt.exe —— 那才是会覆盖 IDMan.exe 的东西。
      把 LastCheckQU 保持在最近 6 天内，门控就一直关闭。

    默认动作（不带动作开关）
      立即把 LastCheckQU 刷新为当前 Unix 时间。

    动作开关（互斥，只能给一个）
      -Status        只读：打印 LastCheckQU / 距今天数 / 门控状态 / 自动刷新机制状态
      -InstallTask   安装自动刷新机制，并立即刷新一次：
                     机制 A（首选）计划任务 IDM-Patch-Lockdown，每 3 天、当前用户、RunLevel=Limited；
                     机制 B（兜底）当前用户登录自启项 HKCU\...\Run\IDM-Patch-Lockdown。
                     本机实测：未提权会话下机制 A 会被 "Access is denied" 拒绝，
                     脚本会自动改用机制 B 并明确告知（机制 B 不需要任何管理员权限）。
      -RemoveTask    移除上述两种机制（幂等：都不存在也算成功）
      -Restore       恢复官方默认：删除 LastCheckQU 值 + 移除两种机制
                     （否则机制会在 3 天内把它写回来）

    其它
      -DryRun        预览模式：只打印将要做什么，不做任何修改（等价于 -WhatIf）
      -WhatIf        同 -DryRun（由 CmdletBinding 提供）
      -Quiet         安静模式，供计划任务调用；只输出错误与一行结论
      -RefreshIntervalDays / -TaskName / -RegPath / -ValueName  便于测试与定制

    退出码
      0 = 成功
      1 = 用法错误（动作开关冲突）
      2 = 操作失败（注册表写入 / 计划任务注册或删除失败）
      3 = 环境不满足（HKCU\Software\DownloadManager 不存在，或计划任务模块不可用）

    安全性
      只读写 HKCU 与当前用户的计划任务；不启动 IDMan.exe；不触碰安装目录。
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Status,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [switch]$Restore,
    [switch]$DryRun,
    [switch]$Quiet,

    [ValidateRange(1, 30)]
    [int]$RefreshIntervalDays = 3,

    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'IDM-Patch-Lockdown',

    [ValidateNotNullOrEmpty()]
    [string]$RegPath = 'HKCU:\Software\DownloadManager',

    [ValidateNotNullOrEmpty()]
    [string]$ValueName = 'LastCheckQU'
)

$ErrorActionPreference = 'Continue'

# 预览：-DryRun 或 -WhatIf 任一为真就只打印、不落地
$preview = ([bool]$DryRun) -or ([bool]$WhatIfPreference)

# 与 check-patch-state.ps1 / FUN_00456BC0 保持一致的常量（不 dot-source 那个脚本：
# 它会执行完整回检并 exit，不适合被引入）
$GateDays = 6      # FUN_00456BC0: return 6 < (now - LastCheckQU) / 86400
$SecondsPerDay = 86400

# 无管理员权限时的兜底机制：当前用户的登录自启项（HKCU\...\Run）。
# 实测本机未提权会话下 Register-ScheduledTask / schtasks 均返回 "Access is denied"，
# 而 HKCU 的 Run 项不需要任何管理员权限，且登录时机与 IDM 读 LastCheckQU 的时机一致。
$RunKeyPath   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValueName = 'IDM-Patch-Lockdown'
$RunCommand   = $null      # 在 InstallTask 里按实际脚本路径与宿主填充

# ------------------------------------------------------------------ 输出
$script:ExitCode = 0

function Say {
    param([string]$Text, [switch]$Always)
    if ($Quiet -and -not $Always) { return }
    Write-Host $Text
}
function SayErr([string]$Text) {
    Write-Host $Text -ForegroundColor Red
}

# ------------------------------------------------------------------ 读取
function Get-LastCheckState {
    $key = Get-ItemProperty -LiteralPath $RegPath -ErrorAction SilentlyContinue
    if ($null -eq $key) {
        return [pscustomobject]@{ KeyMissing = $true; Exists = $false; Value = $null }
    }
    $prop = $key.PSObject.Properties[$ValueName]
    if ($null -eq $prop) {
        return [pscustomobject]@{ KeyMissing = $false; Exists = $false; Value = $null }
    }
    return [pscustomobject]@{ KeyMissing = $false; Exists = $true; Value = [int64]$prop.Value }
}

function Get-GateState {
    param([object]$Last)
    if ($Last.KeyMissing) {
        return [pscustomobject]@{ Open = $true; Days = $null; Whole = $null; Time = $null
                                  Reason = 'HKCU\Software\DownloadManager 不存在' }
    }
    if (-not $Last.Exists) {
        return [pscustomobject]@{ Open = $true; Days = $null; Whole = $null; Time = $null
                                  Reason = '值缺失 -> FUN_00456BC0 直接 return true（永远到期）' }
    }
    $t = [DateTimeOffset]::FromUnixTimeSeconds($Last.Value).ToLocalTime()
    $days = ((Get-Date) - $t.DateTime).TotalDays
    $whole = [math]::Floor($days)
    $open = ($whole -gt $GateDays)
    $reason = if ($open) {
        "距今 $whole 天 > $GateDays 天 -> 到期"
    } else {
        "距今 $whole 天 <= $GateDays 天 -> 未到期（还需约 $($GateDays + 1 - $whole) 天）"
    }
    return [pscustomobject]@{ Open = $open; Days = $days; Whole = [int]$whole; Time = $t; Reason = $reason }
}

function Get-TaskState {
    $cmd = Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return [pscustomobject]@{ Available = $false; Exists = $false; Task = $null; Info = $null }
    }
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        return [pscustomobject]@{ Available = $true; Exists = $false; Task = $null; Info = $null }
    }
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue } catch { $info = $null }
    return [pscustomobject]@{ Available = $true; Exists = $true; Task = $task; Info = $info }
}

function Get-RunEntryState {
    $key = Get-ItemProperty -LiteralPath $RunKeyPath -ErrorAction SilentlyContinue
    if ($null -eq $key) {
        return [pscustomobject]@{ KeyMissing = $true; Exists = $false; Command = $null }
    }
    $prop = $key.PSObject.Properties[$RunValueName]
    if ($null -eq $prop) {
        return [pscustomobject]@{ KeyMissing = $false; Exists = $false; Command = $null }
    }
    return [pscustomobject]@{ KeyMissing = $false; Exists = $true; Command = [string]$prop.Value }
}

function Show-State {
    param([switch]$WithHeader)

    $last = Get-LastCheckState
    $gate = Get-GateState -Last $last
    $tsk  = Get-TaskState
    $run  = Get-RunEntryState

    if ($WithHeader) {
        Say '=================================================================='
        Say ' IDM 防回退状态 (lockdown-update.ps1 -Status)'
        Say '=================================================================='
    }
    Say (" 检查时间    : {0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))
    Say (" 注册表       : {0}\{1}" -f $RegPath, $ValueName)

    if ($last.KeyMissing) {
        Say  ' LastCheckQU : <键不存在>'
        SayErr ' 门控         : 打开（无法读取；IDM 可能从未运行过）'
    }
    elseif (-not $last.Exists) {
        Say  ' LastCheckQU : <值缺失>'
        Say  ' 门控         : 打开 —— 值缺失时 FUN_00456BC0 直接返回 true'
        Say  '                说明: 当前处于「官方默认 / 可自动更新」状态。'
    }
    else {
        Say (" LastCheckQU : {0}" -f $last.Value)
        Say ("               {0}" -f $gate.Time.ToString('yyyy-MM-dd HH:mm:ss zzz'))
        Say (" 距今        : {0} 天" -f [math]::Round($gate.Days, 2))
        if ($gate.Open) {
            SayErr (" 门控         : 打开 —— {0}" -f $gate.Reason)
            SayErr  '                下次启动 IDMan.exe 会在 60s 后挂 UPDATE_TIMER，自动下载并启动更新器。'
        } else {
            Say (" 门控         : 关闭 —— {0}" -f $gate.Reason)
            Say  '                本次启动不会自动检查更新。'
        }
    }

    Say (" 阈值         : {0} 天（FUN_00456BC0 @ VA 0x00456BC0）" -f $GateDays)

    if (-not $tsk.Available) {
        Say  ' 计划任务     : 本机没有 ScheduledTasks 模块，无法使用 -InstallTask'
    }
    elseif (-not $tsk.Exists) {
        Say (" 计划任务     : 不存在（{0}）" -f $TaskName)
    }
    else {
        Say (" 计划任务     : 存在（{0}）" -f $TaskName)
        Say ("   状态       : {0}" -f $tsk.Task.State)
        if ($null -ne $tsk.Info) {
            Say ("   上次运行   : {0}" -f $tsk.Info.LastRunTime)
            Say ("   上次结果   : {0}" -f $tsk.Info.LastTaskResult)
            Say ("   下次运行   : {0}" -f $tsk.Info.NextRunTime)
        }
    }

    if ($run.Exists) {
        Say (" 登录自启项   : 存在（{0}\{1}）" -f $RunKeyPath, $RunValueName)
        Say ("   {0}" -f $run.Command)
    } else {
        Say (" 登录自启项   : 不存在（{0}\{1}）" -f $RunKeyPath, $RunValueName)
    }

    if (-not $tsk.Exists -and -not $run.Exists) {
        Say  ' 提醒         : 两种自动刷新机制都没有 —— LastCheckQU 不会自动保持新鲜。'
        Say  '                执行 -InstallTask 安装（本机可能需要管理员权限，脚本会自动兜底）。'
    }
    return [pscustomobject]@{ Last = $last; Gate = $gate; Task = $tsk; Run = $run }
}

# ------------------------------------------------------------------ 动作选择
$actionSwitches = @()
if ($Status)      { $actionSwitches += '-Status' }
if ($InstallTask) { $actionSwitches += '-InstallTask' }
if ($RemoveTask)  { $actionSwitches += '-RemoveTask' }
if ($Restore)     { $actionSwitches += '-Restore' }

if ($actionSwitches.Count -gt 1) {
    SayErr ("[X] 用法错误: 动作开关互斥，只能给一个，收到 {0}" -f ($actionSwitches -join ', '))
    SayErr  '    用法: lockdown-update.ps1 [-Status|-InstallTask|-RemoveTask|-Restore] [-DryRun] [-WhatIf] [-Quiet]'
    exit 1
}

$action = if ($actionSwitches.Count -eq 0) { 'Refresh' } else { $actionSwitches[0].TrimStart('-') }

if ($preview) {
    Say ''
    Say '*** 预览模式（-DryRun / -WhatIf）：不会修改任何注册表项或计划任务 ***' -Always
    Say ''
}

# ------------------------------------------------------------------ 动作: Status
if ($action -eq 'Status') {
    $null = Show-State -WithHeader
    if ((Get-LastCheckState).KeyMissing) { exit 3 }
    exit 0
}

# ------------------------------------------------------------------ 动作: Refresh
if ($action -eq 'Refresh') {
    $last = Get-LastCheckState
    $gateBefore = Get-GateState -Last $last

    if ($last.KeyMissing) {
        SayErr ("[X] 找不到 {0} —— IDM 可能从未运行过，无法刷新。" -f $RegPath)
        SayErr  '    先在当前用户下运行一次 IDM 让它创建该键，或手动指定 -RegPath。'
        exit 3
    }

    $now = [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    Say ''
    Say '--- LastCheckQU 刷新 ---'
    if ($last.Exists) {
        Say (" 旧值 : {0}  ({1}, 距今 {2} 天)" -f $last.Value, $gateBefore.Time.ToString('yyyy-MM-dd HH:mm:ss zzz'), [math]::Round($gateBefore.Days, 2))
        Say (" 旧门控: {0}" -f $(if ($gateBefore.Open) { '打开' } else { '关闭' }))
    } else {
        Say  ' 旧值 : <缺失>（门控打开 = 永远到期）'
    }

    if ($preview) {
        Say (" 新值 : {0}  ({1})" -f $now, [DateTimeOffset]::FromUnixTimeSeconds($now).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz'))
        Say  ' [DRY-RUN] 未写入注册表。'
        Say ''
        Say ' 结论: [PREVIEW] 未做任何修改。' -Always
        exit 0
    }

    try {
        Set-ItemProperty -LiteralPath $RegPath -Name $ValueName -Value $now -Type DWord -ErrorAction Stop
    }
    catch {
        SayErr ("[X] 写入注册表失败: {0}" -f $_.Exception.Message)
        SayErr  '    提示: LastCheckQU 属于 HKCU，正常无需管理员权限；请检查该键是否被策略锁定。'
        exit 2
    }

    $after = Get-LastCheckState
    $gateAfter = Get-GateState -Last $after
    Say (" 新值 : {0}  ({1})" -f $after.Value, $gateAfter.Time.ToString('yyyy-MM-dd HH:mm:ss zzz'))
    Say (" 新门控: {0} —— {1}" -f $(if ($gateAfter.Open) { '打开' } else { '关闭' }), $gateAfter.Reason)

    if ($gateAfter.Open) {
        SayErr '[X] 刷新后门控仍为打开，结果不符合预期，请人工检查。'
        exit 2
    }

    $tsk = Get-TaskState
    Say ''
    if ($tsk.Exists) {
        Say (" 计划任务: 存在（{0}），下次运行 {1}" -f $TaskName, $(if ($null -ne $tsk.Info) { $tsk.Info.NextRunTime } else { '<未知>' }))
    } else {
        Say (" 计划任务: 不存在 —— 门控会在 {0} 天后重新打开；建议执行 -InstallTask 长期保持。" -f ($GateDays + 1))
    }
    Say ''
    Say (" 结论: [OK] LastCheckQU 已刷新，门控关闭（有效约 {0} 天）。" -f ($GateDays + 1)) -Always
    exit 0
}

# ------------------------------------------------------------------ 动作: InstallTask
if ($action -eq 'InstallTask') {
    if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        SayErr '[X] 本机没有 ScheduledTasks 模块（Register-ScheduledTask 不可用），无法注册计划任务。'
        SayErr  '    可退化为手工定期执行: lockdown-update.ps1  （默认动作就是刷新）'
        exit 3
    }

    $self = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $self -or -not (Test-Path -LiteralPath $self)) {
        SayErr '[X] 无法确定脚本自身路径，无法注册计划任务。'
        exit 2
    }
    $self = (Resolve-Path -LiteralPath $self).Path

    # 用当前 powershell 宿主，保证语法版本一致
    $hostExe = $null
    try { $hostExe = (Get-Process -Id $PID).Path } catch { $hostExe = $null }
    if (-not $hostExe -or -not (Test-Path -LiteralPath $hostExe)) {
        foreach ($cand in @((Join-Path $PSHOME 'powershell.exe'), (Join-Path $PSHOME 'pwsh.exe'))) {
            if (Test-Path -LiteralPath $cand) { $hostExe = $cand; break }
        }
    }
    if (-not $hostExe) {
        SayErr '[X] 找不到可用的 powershell 宿主可执行文件。'
        exit 2
    }

    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    # 锚定在本地 03:00；若今天 03:00 已过则从明天 03:00 起算，之后每 N 天一次
    $runAt = (Get-Date).Date.AddHours(3)
    if ($runAt -le (Get-Date)) { $runAt = $runAt.AddDays(1) }

    $script:RunCommand = '"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{1}" -Quiet' -f $hostExe, $self
    $runExisting = Get-RunEntryState

    Say ''
    Say '--- 安装自动刷新机制 ---'
    Say ' 机制 A（首选）: Windows 计划任务'
    Say (" 任务名   : {0}" -f $TaskName)
    Say (" 触发     : 每 {0} 天一次（首次 {1}）" -f $RefreshIntervalDays, $runAt.ToString('yyyy-MM-dd HH:mm:ss'))
    Say (" 身份     : {0}\{1}（交互式登录，RunLevel=Limited，无需最高权限）" -f $env:USERDOMAIN, $env:USERNAME)
    Say (" 已存在   : {0}" -f $(if ($null -ne $existing) { '是（将覆盖）' } else { '否（新建）' }))
    Say ' 机制 B（兜底）: 当前用户登录自启项（不需要管理员权限）'
    Say (" 注册表   : {0}\{1}" -f $RunKeyPath, $RunValueName)
    Say (" 已存在   : {0}" -f $(if ($runExisting.Exists) { '是（将覆盖）' } else { '否（新建）' }))
    Say (" 命令行   : {0}" -f $script:RunCommand)
    Say ' 说明     : 本机实测未提权会话下计划任务会被 "Access is denied" 拒绝；'
    Say '            此时脚本会自动改用机制 B，并明确告知。'
    Say ''

    if ($preview) {
        Say  ' [DRY-RUN] 未注册计划任务，也未写登录自启项。'
        Say  ' [DRY-RUN] 也未执行刷新。'
        Say ''
        Say ' 结论: [PREVIEW] 未做任何修改。' -Always
        exit 0
    }

    $taskOk = $false
    $taskErr = $null
    try {
        $actionObj = New-ScheduledTaskAction -Execute $hostExe `
            -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"{0}`" -Quiet" -f $self)
        $triggerObj = New-ScheduledTaskTrigger -Daily -DaysInterval $RefreshIntervalDays -At $runAt
        $principalObj = New-ScheduledTaskPrincipal -UserId ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) `
            -LogonType Interactive -RunLevel Limited
        $settingsObj = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
        $desc = 'IDM 6.43b8 补丁防回退: 每 ' + $RefreshIntervalDays + ' 天把 HKCU\Software\DownloadManager\LastCheckQU 刷新为当前时间，' +
                '使 IDMan.exe 的自动更新门控（FUN_00456BC0 @ VA 0x00456BC0）保持关闭。'

        Register-ScheduledTask -TaskName $TaskName -Action $actionObj -Trigger $triggerObj `
            -Principal $principalObj -Settings $settingsObj -Description $desc -Force -ErrorAction Stop | Out-Null
        $taskOk = $true
        Say ' [OK] 计划任务已注册/覆盖（机制 A 生效）。'
    }
    catch {
        $taskErr = $_.Exception.Message
        SayErr (" [!] 计划任务注册失败: {0}" -f $taskErr)
        SayErr  '     原因通常是当前会话未提权（写任务库需要管理员权限）。'
        SayErr  '     已自动改用兜底机制 B：当前用户登录自启项（不需要管理员权限）。'
    }

    if (-not $taskOk) {
        try {
            New-ItemProperty -LiteralPath $RunKeyPath -Name $RunValueName -Value $script:RunCommand `
                -PropertyType String -Force -ErrorAction Stop | Out-Null
            $verify = Get-RunEntryState
            if (-not $verify.Exists) { throw '写入后读回校验失败' }
            Say (" [OK] 登录自启项已写入（机制 B 生效）: {0}\{1}" -f $RunKeyPath, $RunValueName)
        }
        catch {
            SayErr (" [X] 兜底机制 B 也失败: {0}" -f $_.Exception.Message)
            SayErr  '     可退化为手工定期执行（默认动作就是刷新）:'
            SayErr ("       powershell -ExecutionPolicy Bypass -File `"{0}`"" -f $self)
            exit 2
        }
    }

    # 装完立刻刷新一次，避免留出最长 7 天的暴露窗口
    $last = Get-LastCheckState
    if ($last.KeyMissing) {
        SayErr ("[!] 计划任务已装好，但 {0} 不存在，无法立即刷新。" -f $RegPath)
        SayErr  '    计划任务运行时会再次尝试；请先运行一次 IDM 让该键出现。'
        exit 2
    }
    $now = [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    try {
        Set-ItemProperty -LiteralPath $RegPath -Name $ValueName -Value $now -Type DWord -ErrorAction Stop
    }
    catch {
        SayErr ("[!] 计划任务已装好，但立即刷新失败: {0}" -f $_.Exception.Message)
        exit 2
    }

    $tsk = Get-TaskState
    $run = Get-RunEntryState
    Say ''
    Say (" 刷新     : LastCheckQU = {0}" -f (Get-LastCheckState).Value)
    if ($taskOk) {
        if ($tsk.Exists -and $null -ne $tsk.Info) {
            Say (" 机制 A   : 计划任务 {0}，下次运行 {1}" -f $TaskName, $tsk.Info.NextRunTime)
        }
    } else {
        Say  ' 机制 A   : 未生效（计划任务注册被拒绝）'
        Say (" 机制 B   : 登录自启项 {0}\{1}（每次登录刷新一次）" -f $RunKeyPath, $RunValueName)
    }
    Say ''
    if ($taskOk) {
        Say (" 结论: [OK] 计划任务 {0} 已安装，门控已关闭。" -f $TaskName) -Always
    } else {
        Say  ' 结论: [OK] 已用登录自启项（机制 B）替代计划任务，门控已关闭。' -Always
        Say  '       如需真正的计划任务，请以管理员身份重跑: -InstallTask'
    }
    exit 0
}

# ------------------------------------------------------------------ 动作: RemoveTask
if ($action -eq 'RemoveTask') {
    $existing = $null
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    $runExisting = Get-RunEntryState

    Say ''
    Say '--- 卸载自动刷新机制 ---'
    Say (" 机制 A 计划任务   : {0}" -f $(if ($null -ne $existing) { '存在' } else { '不存在' }))
    Say (" 机制 B 登录自启项 : {0}" -f $(if ($runExisting.Exists) { '存在' } else { '不存在' }))

    if ($null -eq $existing -and -not $runExisting.Exists) {
        Say ' 状态              : 两者都不存在（幂等，无需删除）'
        Say ''
        Say ' 结论: [OK] 本来就没有安装任何自动刷新机制。' -Always
        exit 0
    }

    if ($preview) {
        Say  ' [DRY-RUN] 未删除计划任务，未删除登录自启项。'
        Say ''
        Say ' 结论: [PREVIEW] 未做任何修改。' -Always
        exit 0
    }

    $fail = $false

    if ($null -ne $existing) {
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            Say (" [OK] 已删除计划任务 {0}" -f $TaskName)
        }
        catch {
            SayErr (" [X] 删除计划任务失败: {0}" -f $_.Exception.Message)
            $fail = $true
        }
    }

    if ($runExisting.Exists) {
        try {
            Remove-ItemProperty -LiteralPath $RunKeyPath -Name $RunValueName -ErrorAction Stop
            if ((Get-RunEntryState).Exists) { throw '删除后读回校验仍存在' }
            Say (" [OK] 已删除登录自启项 {0}\{1}" -f $RunKeyPath, $RunValueName)
        }
        catch {
            SayErr (" [X] 删除登录自启项失败: {0}" -f $_.Exception.Message)
            $fail = $true
        }
    }

    Say ''
    if ($fail) {
        SayErr ' 结论: [!!] 卸载未完全成功，请按上面错误处理。'
        exit 2
    }
    Say ' 结论: [OK] 自动刷新机制已全部移除；LastCheckQU 不再被自动刷新。' -Always
    Say '       注意: 移除后门控会在约 7 天后重新打开 —— 需要长期防回退就保留它。'
    exit 0
}

# ------------------------------------------------------------------ 动作: Restore
if ($action -eq 'Restore') {
    Say ''
    Say '--- 恢复官方默认（可自动更新） ---'
    Say ' 说明: 这会删除 LastCheckQU，并移除全部自动刷新机制（计划任务 + 登录自启项）。'
    Say '       删除该值后 FUN_00456BC0 直接返回 true —— 也就是 IDM 的官方出厂行为：'
    Say '       每次启动 IDMan.exe 都可能自动检查更新。'

    if ($preview) {
        Say  ' [DRY-RUN] 未删除 LastCheckQU，未移除计划任务/登录自启项。'
        Say ''
        Say ' 结论: [PREVIEW] 未做任何修改。' -Always
        exit 0
    }

    $fail = $false

    # 1) 先移除自动刷新机制，否则它会在 3 天内把值写回来
    if (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue) {
        if ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
            try {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
                Say (" [OK] 已删除计划任务 {0}" -f $TaskName)
            }
            catch {
                SayErr (" [X] 删除计划任务失败: {0}" -f $_.Exception.Message)
                $fail = $true
            }
        } else {
            Say (" [--] 计划任务 {0} 不存在" -f $TaskName)
        }
    } else {
        Say  ' [--] 无 ScheduledTasks 模块，跳过计划任务处理'
    }

    if ((Get-RunEntryState).Exists) {
        try {
            Remove-ItemProperty -LiteralPath $RunKeyPath -Name $RunValueName -ErrorAction Stop
            Say (" [OK] 已删除登录自启项 {0}\{1}" -f $RunKeyPath, $RunValueName)
        }
        catch {
            SayErr (" [X] 删除登录自启项失败: {0}" -f $_.Exception.Message)
            $fail = $true
        }
    } else {
        Say (" [--] 登录自启项 {0} 不存在" -f $RunValueName)
    }

    # 2) 删注册表值
    $last = Get-LastCheckState
    if ($last.KeyMissing) {
        SayErr (" [X] {0} 不存在，无需恢复。" -f $RegPath)
        exit 3
    }
    if (-not $last.Exists) {
        Say (" [--] {0} 本来就缺失（已是官方默认状态）" -f $ValueName)
    } else {
        try {
            Remove-ItemProperty -LiteralPath $RegPath -Name $ValueName -ErrorAction Stop
            Say (" [OK] 已删除 {0}\{1}（原值 {2}）" -f $RegPath, $ValueName, $last.Value)
        }
        catch {
            SayErr (" [X] 删除注册表值失败: {0}" -f $_.Exception.Message)
            $fail = $true
        }
    }

    $gate = Get-GateState -Last (Get-LastCheckState)
    Say ''
    Say (" 当前门控 : {0} —— {1}" -f $(if ($gate.Open) { '打开' } else { '关闭' }), $gate.Reason)
    Say ''
    if ($fail) {
        SayErr ' 结论: [!!] 恢复未完全成功，请按上面错误处理。' 
        exit 2
    }
    Say ' 结论: [OK] 已恢复官方默认行为（下次启动 IDMan.exe 会重新具备自动更新能力）。' -Always
    Say '       注意: 这意味着补丁可能被更新覆盖 —— 需要防回退时请重新执行 -InstallTask。'
    exit 0
}

SayErr ("[X] 未知动作: {0}" -f $action)
exit 1
