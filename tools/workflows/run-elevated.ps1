<#
.SYNOPSIS
  以「静默提权」方式运行一个 PowerShell 脚本文件（本机 ConsentPromptBehaviorAdmin=0，无 UAC 弹窗）。

.WHY
  DSH 的 pwsh 工具运行在 Low Mandatory Level 沙箱令牌下：
    · 可写：项目根目录、%TEMP%
    · 拒写：work/**、.agent_work/**、Desktop、C:\Program Files (x86)\Internet Download Manager、C:\Windows\System32\drivers\etc
  凡需要写上述位置（部署 IDMan.exe、改 hosts、把 soak 日志/CSV 落盘到 work/idm-6.43b8/logs/**）
  的操作，都必须经本脚本提权执行。

.HOW
  提权子进程没有控制台，**stdout/stderr 不会回传**。因此被执行的脚本必须自己把结果写入文件
  （建议 `... | Out-File -Encoding UTF8 <日志路径>`，或 `*> <日志>`），父进程只拿到 EXITCODE。

.PARAMETER ScriptPath
  要提权运行的 .ps1 路径。放 %TEMP% 或项目根目录（两者非提权也可写）。

.PARAMETER TimeoutSec
  硬超时；超时则杀掉提权进程并返回 3。

.EXAMPLE
  $s = Join-Path $env:TEMP 'job.ps1'
  Set-Content $s 'whoami /groups | Out-File "D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\g.txt"'
  pwsh .agent_work/workflows/run-elevated.ps1 -ScriptPath $s -TimeoutSec 120

.NOTES
  验证记录（2026-10-17，Lead 实测）：
    · 提权进程 `admin=True`，`work/**` 写入 OK，`C:\Program Files (x86)\Internet Download Manager` 写入 OK。
    · 非提权 pwsh 写上述位置一律 `Access to the path ... is denied`。
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ScriptPath,
  [int]$TimeoutSec = 300
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ScriptPath)) {
  Write-Error "script not found: $ScriptPath"
  exit 2
}

$proc = Start-Process powershell.exe -Verb RunAs -PassThru -ArgumentList @(
  '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath
)

if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
  try { $proc.Kill() } catch { }
  Write-Output "TIMEOUT-${TimeoutSec}s (elevated child killed)"
  exit 3
}

Write-Output "EXITCODE=$($proc.ExitCode)"
exit $proc.ExitCode
