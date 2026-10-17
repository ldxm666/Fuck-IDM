<#
  hosts_toggle.ps1 - CONTROLLED hosts switch for the IDM H2 control experiment.

  ###########################################################################
  #  DO NOT RUN WITHOUT EXPLICIT LEAD + USER AUTHORISATION.                 #
  #  This MODIFIES C:\Windows\System32\drivers\etc\hosts and must run       #
  #  ELEVATED. It is prepared in advance only; prober does not run it.      #
  ###########################################################################

  WHY
    Hypothesis H2 says the counterfeit wording is delivered by the license server.
    With hosts at 6/6 the server is unreachable, so "no popup in 900s" cannot
    distinguish "P7 works" from "server never reachable". The control experiment
    temporarily returns hosts to the state the user had when they took the
    screenshot (www./secure./register. reachable), then restores 6/6.

  MODES
    status   read-only: print the current IDM-related lines. Changes nothing.
    open     make www./secure./register. REACHABLE (comment those 3 lines out);
             the bare internetdownloadmanager.com line stays blocked.
    blocked  force all 4 IDM lines back to 0.0.0.0 (the safe default state).
    restore  restore hosts byte-for-byte from a backup made by this script.

  SAFETY / IDEMPOTENCE
    * A timestamped backup is written BEFORE the first modification.
    * Only lines matching internetdownloadmanager.com are ever touched; every
      other byte of the file is preserved.
    * Each mode is idempotent: running it twice produces the same file.
    * The result is verified by re-reading and counting effective lines.
    * ipconfig /flushdns runs after every change.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('status', 'open', 'blocked', 'restore')]
  [string]$Mode,

  [string]$BackupPath,                                   # required for -Mode restore
  [string]$BackupDir = "$env:ProgramData\idm_probe"
)

$ErrorActionPreference = 'Stop'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$marker = '# IDM-Activator-PermanentFix'
$domains = @('internetdownloadmanager.com', 'www.internetdownloadmanager.com',
             'secure.internetdownloadmanager.com', 'register.internetdownloadmanager.com')
$openDomains = @('www.internetdownloadmanager.com', 'secure.internetdownloadmanager.com',
                 'register.internetdownloadmanager.com')

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "hosts_toggle.ps1 must run ELEVATED (current user is not an administrator)."
  }
}

function Show-IdmLines {
  Write-Output "--- IDM-related lines in $hosts ---"
  $lines = Get-Content -LiteralPath $hosts
  $n = 0
  foreach ($l in $lines) {
    if ($l -match 'internetdownloadmanager\.com') { Write-Output $l; $n++ }
  }
  $effective = @($lines | Where-Object { $_ -match '^\s*[^#\s]' -and $_ -match 'internetdownloadmanager\.com' }).Count
  Write-Output "matched=$n  effective(non-comment)=$effective"
}

function Backup-Hosts {
  if (-not (Test-Path -LiteralPath $BackupDir)) {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
  }
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $dest = Join-Path $BackupDir "hosts.backup-$stamp"
  Copy-Item -LiteralPath $hosts -Destination $dest -Force
  Write-Output "BACKUP: $dest"
  return $dest
}

function Set-HostsState([string]$state) {
  # Rewrite ONLY the IDM lines; keep every other line untouched.
  $lines = Get-Content -LiteralPath $hosts
  $kept = @($lines | Where-Object { $_ -notmatch 'internetdownloadmanager\.com' })

  $canonical = @()
  foreach ($d in $domains) {
    if ($state -eq 'open' -and ($openDomains -contains $d)) {
      $canonical += "# 0.0.0.0 $d $marker   # TEMPORARILY OPEN for H2 control experiment"
    } else {
      $canonical += "0.0.0.0 $d $marker"
    }
  }

  # preserve a single trailing newline
  $out = @()
  $out += $kept
  while ($out.Count -gt 0 -and [string]::IsNullOrWhiteSpace($out[-1])) {
    $out = $out[0..($out.Count - 2)]
  }
  $out += ''
  $out += $canonical
  $out += ''
  Set-Content -LiteralPath $hosts -Value $out -Encoding ASCII
  Write-Output "APPLIED state=$state"
}

function Verify-And-Flush([string]$state) {
  $expected = if ($state -eq 'open') { 1 } else { 4 }
  $lines = Get-Content -LiteralPath $hosts
  $effective = @($lines | Where-Object { $_ -match '^\s*[^#\s]' -and $_ -match 'internetdownloadmanager\.com' }).Count
  Write-Output "VERIFY: effective=$effective expected=$expected"
  if ($effective -ne $expected) {
    Write-Output "WARNING: effective count mismatch - inspect hosts manually."
  }
  ipconfig /flushdns | Out-Null
  Write-Output "FLUSHED dns"
  foreach ($d in @('www.internetdownloadmanager.com', 'secure.internetdownloadmanager.com',
                   'register.internetdownloadmanager.com', 'internetdownloadmanager.com')) {
    $res = try { ([System.Net.Dns]::GetHostAddresses($d) | Select-Object -First 1).IPAddressToString } catch { 'UNRESOLVED' }
    Write-Output ("RESOLVE {0} -> {1}" -f $d, $res)
  }
}

switch ($Mode) {
  'status' {
    Show-IdmLines
  }
  'restore' {
    Assert-Admin
    if (-not $BackupPath -or -not (Test-Path -LiteralPath $BackupPath)) {
      throw "-Mode restore requires -BackupPath pointing at an existing backup file."
    }
    $pre = Backup-Hosts
    Copy-Item -LiteralPath $BackupPath -Destination $hosts -Force
    Write-Output "RESTORED from $BackupPath (pre-restore snapshot: $pre)"
    ipconfig /flushdns | Out-Null
    Show-IdmLines
  }
  default {
    Assert-Admin
    $pre = Backup-Hosts
    Set-HostsState $Mode
    Verify-And-Flush $Mode
    Show-IdmLines
    Write-Output "PRE-CHANGE BACKUP (for -Mode restore): $pre"
  }
}
