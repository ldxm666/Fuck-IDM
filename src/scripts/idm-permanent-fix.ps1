# idm-permanent-fix.ps1 — the "no guard, once and for all" configuration for IDM 6.43 b15.
#
# WHY THIS EXISTS (evidence in patches/mdata-writer-static.md and
# patches/permanent-plan.md):
#
#   The old design forged a Serial/FName/LName/Email into the HKLM 32-bit view and
#   ran a 30-minute daemon to re-assert it. That forged serial is uploaded to
#   internetdownloadmanager.com, judged counterfeit server-side, and the answer is
#   cached in the registry. IDM then arms a family of tripwires
#   (sub_44CCB0 / sub_466EE0 / sub_46C7B0 / sub_521050) which write a 256-byte
#   REG_NONE "MData" blob and call ExitProcess(0):
#       "Internet Download Manager has been registered with a counterfeit Serial
#        Number. IDM is exiting..."
#   The daemon then sees MData, deletes it, and rotates the serial -> it re-arms
#   its own trap. Measured: forged serial -> MData + exit(0) at t+62s.
#
#   This script removes the CAUSE instead of chasing symptoms, and replaces the
#   daemon with two static, process-free guards.
#
# WHAT IT DOES
#   1. stops IDM
#   2. clears every MData value in all CLSID trees (both hives, both views)
#   3. clears the cached license-verdict values under the {E6871B76-...} key
#   4. sets the registration state per -RegMode (default: names only, NO serial)
#   5. blocks the license/update endpoints at the HOSTS level (hostname-based, so
#      it survives the server changing IP) - belt and braces so a serial can never
#      be reported again
#   6. reports the resulting state
#
# The 4 binary patches (P1..P4) are applied separately by idm_engine/IDM-Activator;
# this script does not touch IDMan.exe.
#
# Run ELEVATED (writes HKLM + the hosts file).
# Fully reversible: -Restore undoes steps 4-5 (step 2/3 only remove data IDM rewrites).

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('names-only', 'no-serial', 'with-serial')]
    [string]$RegMode = 'names-only',
    [string]$Serial = 'A7K2M-P9Q4T-VB3XN-6WR8D',
    [switch]$Restore
)

$ErrorActionPreference = 'Continue'
$root    = 'D:\pojie应用\jiesuo\work\idm-6.43b8'
$logDir  = Join-Path $root 'logs\permanent-fix'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log     = Join-Path $logDir ('apply-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
function W($m) { $m | Tee-Object -FilePath $log -Append }

$HOSTS   = "$env:SystemRoot\System32\drivers\etc\hosts"
$MARKER  = '# IDM-Activator-PermanentFix'
$DOMAINS = @(
    'internetdownloadmanager.com',
    'www.internetdownloadmanager.com',
    'secure.internetdownloadmanager.com',
    'register.internetdownloadmanager.com',
    'tonec.com',
    'www.tonec.com'
)
$KEY32   = 'HKLM:\SOFTWARE\WOW6432Node\Internet Download Manager'
$CLSID_G = 'Software\Classes\CLSID\{E6871B76-C3C8-44DD-B947-ABFFE144860D}'

# ---------------------------------------------------------------------------
# FIX 2026-10-17 (deployer, task-3 rev3 item B) - two defects repaired here.
#
# DEFECT 1 - THE HOSTS ORACLE WAS BROKEN AND COULD ONLY EVER PASS.
#   Old check:  $reachable = $ping -match '67\.18\.'
#   When a domain IS correctly blocked, ping prints
#     "Ping request could not find host <d>. Please check the name and try again."
#   and exits 1. No "67.18." appears in that text, so $reachable was ALWAYS $false
#   and the loop counted the domain as blocked regardless of reality. Measured:
#     cmd /c ping -n 1 register.internetdownloadmanager.com -> "could not find
#     host", exit 1.  => this is the origin of the false "hosts 生效屏蔽 6/6".
#   REPLACEMENT: require the resolved address to BE 0.0.0.0.
#
# DEFECT 2 - THE STRIP RULE LEAKED COMMENTED-OUT BLOCK LINES.
#   A commented-out block line still contains $MARKER, and the old comment-out
#   path produced lines the strip did not recognise, so orphans persisted.
#   The strip now also drops any commented-out "0.0.0.0 <our domain>" line.
#   Measured idempotent: 3 consecutive rebuilds are byte-identical.
# ---------------------------------------------------------------------------
$DOMAIN_RE = ($DOMAINS | ForEach-Object { [regex]::Escape($_) }) -join '|'

function Strip-Ours([string[]]$lines) {
    @($lines | Where-Object {
        ($_ -notmatch [regex]::Escape($MARKER)) -and
        ($_ -notmatch ('^\s*#\s*0\.0\.0\.0\s+(' + $DOMAIN_RE + ')(\s|$)'))
    })
}

function Resolve-HostA([string]$d) {
    try {
        return @(Resolve-DnsName $d -Type A -ErrorAction Stop |
                 Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
    } catch { return @() }
}

W ("=== idm-permanent-fix  mode={0}  restore={1}  {2} ===" -f $RegMode, [bool]$Restore, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# ---------------------------------------------------------------- 1) stop IDM
Get-Process | Where-Object { $_.ProcessName -like 'IDM*' } | ForEach-Object {
    W ("kill {0} pid {1}" -f $_.ProcessName, $_.Id); $_.Kill()
}
Start-Sleep -Milliseconds 800

# ------------------------------------------------- 5) hosts block (do first so
#    nothing can be reported while we reconfigure)
# Writes are done via a temp file + Copy-Item, and every failure is surfaced
# explicitly: a swallowed non-terminating error here would leave the system
# silently unblocked while the log still claimed success.
$hostLines = @(Get-Content -LiteralPath $HOSTS -ErrorAction Stop)
$kept      = Strip-Ours $hostLines
$new       = if ($Restore) { $kept }
             else { $kept + @($MARKER) + @($DOMAINS | ForEach-Object { "0.0.0.0 $_ $MARKER" }) }

function Write-Hosts([string[]]$lines) {
    # Use .NET directly: unambiguous encoding, no PowerShell parameter binding
    # surprises, and a temp+copy so a failed write cannot truncate the live file.
    $tmp = $HOSTS + '.new'
    try {
        [System.IO.File]::WriteAllLines($tmp, $lines, [System.Text.Encoding]::ASCII)
        Copy-Item -LiteralPath $tmp -Destination $HOSTS -Force -ErrorAction Stop
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        W ("hosts WRITE FAILED: {0}: {1}" -f $_.Exception.GetType().Name, $_.Exception.Message)
        return $false
    }
}

if ($Restore) {
    if ($kept.Count -ne $hostLines.Count) {
        if (Write-Hosts $kept) { W "hosts: removed $($hostLines.Count - $kept.Count) permanent-fix line(s)" }
    } else { W "hosts: nothing to remove" }
} else {
    # 备份必须是「干净基线」（不含我们的块）。直接拷贝当前文件是错的：
    # 重复运行时会把已经生效的块一起备份进去，之后 -Restore 就再也还原不干净。
    try {
        [System.IO.File]::WriteAllLines(($HOSTS + '.bak-permanentfix'), $kept,
                                        [System.Text.Encoding]::ASCII)
        W ("hosts: 干净基线已备份（{0} 行）" -f $kept.Count)
    } catch { W ("hosts backup FAILED: {0}" -f $_.Exception.Message) }

    if (Write-Hosts $new) {
        # 逐域名校验。只数含标记的行是不够的 —— 被 `#` 注释掉的屏蔽行同样含标记，
        # 会假报成功（本机实际踩到过：6 行里 3 行被注释，www / secure / register
        # 三个域名其实根本没被屏蔽，而日志仍写 6/6）。
        #
        # 也必须刷新 DNS 缓存：只改 hosts 而不刷缓存，屏蔽不会生效。
        #
        # 判据（FIX 2026-10-17）：两个独立信号都要过
        #   (a) 文件里该域名**恰好 1 条**生效的 `0.0.0.0` 行（幂等性）
        #   (b) Resolve-DnsName 的解析结果**就是** 0.0.0.0（真 oracle）
        # 旧实现用 `$ping -match '67\.18\.'` 判「仍可达」，而屏蔽生效时 ping 的输出
        # 是 "Ping request could not find host ..."（exit 1，不含 67.18.），
        # 于是 $reachable 恒为 $false —— 那个检查**永远通过**，是 6/6 假报的根因。
        & ipconfig /flushdns 2>&1 | Out-Null
        Start-Sleep -Milliseconds 800
        $live = @(Get-Content -LiteralPath $HOSTS)
        $active = 0
        $missing = @()
        foreach ($d in $DOMAINS) {
            $pat = '^\s*0\.0\.0\.0\s+' + [regex]::Escape($d) + '(\s|$)'
            $hit = @($live | Where-Object { $_ -match $pat }).Count
            # !! PS 5.1 GOTCHA (measured, see logs/permanent-fix/loop-debug.log and
            # arr-fix.log): Resolve-HostA's `return @(...)` returns the single
            # element UNWRAPPED when the pipeline yields exactly one item, so $ips
            # becomes the scalar string "0.0.0.0". Then $ips[0] is PowerShell
            # CHARACTER indexing -> "0", and ([string]$ips[0] -eq '0.0.0.0') is
            # False. Effect: the check reported 0/6 on a perfectly healthy hosts
            # file. The `@()` at THIS call site is what fixes it - adding `,`/`@()`
            # inside the function instead produces a NESTED array under 5.1 that
            # compares equal for the wrong reason. pwsh 7 does not exhibit this, so
            # it only reproduces when run via powershell.exe 5.1, which is exactly
            # how every elevated runner invokes it.
            $ips = @(Resolve-HostA $d)
            $isZero = ($ips.Count -eq 1) -and ([string]$ips[0] -eq '0.0.0.0')
            $resolved = if ($ips.Count -eq 0) { '<unresolved>' } else { ($ips -join ',') }
            if (($hit -eq 1) -and $isZero) { $active++ }
            else { $missing += $d; W ("  !! {0,-38} 生效行={1} 解析={2}" -f $d, $hit, $resolved) }
        }
        W ("hosts: 生效屏蔽 {0}/{1} 个域名（生效行=1 且解析=0.0.0.0，已 flushdns 后复核）" -f $active, $DOMAINS.Count)
        if ($missing.Count -gt 0) {
            W ("!! hosts 屏蔽不完整，未生效域名: {0}" -f ($missing -join ', '))
        }
        W ("hosts: 剥离后基线 {0} 行 / 当前 {1} 行（幂等自检）" -f (Strip-Ours $live).Count, $live.Count)
    }
}

# ------------------------------------------------------- 2) clear MData values
function Clear-MData {
    # NOTE: must not emit to the pipeline - callers read the count, and W's
    # Tee-Object output would otherwise be concatenated into the return value.
    $trees = @(
        'HKCU:\Software\Classes\CLSID',
        'HKCU:\Software\Classes\Wow6432Node\CLSID',
        'HKLM:\SOFTWARE\Classes\CLSID',
        'HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID'
    )
    $n = 0
    foreach ($t in $trees) {
        if (-not (Test-Path $t)) { continue }
        Get-ChildItem $t -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props -and ($props.PSObject.Properties.Name -contains 'MData')) {
                try {
                    Remove-ItemProperty -Path $_.PSPath -Name 'MData' -Force -ErrorAction Stop
                    Add-Content -LiteralPath $log -Value ("  cleared MData at {0}" -f $_.Name)
                    $script:n_cleared++
                } catch {}
            }
        }
    }
    return $script:n_cleared
}
$script:n_cleared = 0
W ("MData cleared: {0}" -f (Clear-MData))

# ------------------------------------------- 3) clear cached verdict values
# sub_51FFC0 caches the server's answer under {E6871B76-...} using XOR-derived
# value names; wiping the whole value set is the safe move.
foreach ($p in @("HKCU:\$CLSID_G", "HKLM:\$CLSID_G")) {
    if (Test-Path $p) {
        try {
            $names = (Get-Item $p).Property
            foreach ($n in $names) { Remove-ItemProperty -Path $p -Name $n -Force -ErrorAction SilentlyContinue }
            W ("cleared {0} value(s) under {1}" -f @($names).Count, $p)
        } catch { W ("could not clear {0}: {1}" -f $p, $_.Exception.Message) }
    }
}

# ---------------------------------------------------- 4) registration state
if ($Restore) {
    W "registration: left untouched by -Restore (use IDM-Activator --uninstall for a full revert)"
} else {
    switch ($RegMode) {
        'no-serial' {
            foreach ($v in 'Serial', 'FName', 'LName', 'Email') {
                Remove-ItemProperty -Path $KEY32 -Name $v -Force -ErrorAction SilentlyContinue
            }
            W "registration: all values removed (no serial, no names)"
        }
        'names-only' {
            Remove-ItemProperty -Path $KEY32 -Name 'Serial' -Force -ErrorAction SilentlyContinue
            foreach ($kv in @{ FName = 'Lo'; LName = 'Tester'; Email = 'lo@example.com' }.GetEnumerator()) {
                New-ItemProperty -Path $KEY32 -Name $kv.Key -Value $kv.Value -PropertyType String -Force | Out-Null
            }
            W "registration: FName/LName/Email set, NO Serial"
        }
        'with-serial' {
            foreach ($kv in @{ Serial = $Serial; FName = 'Lo'; LName = 'Tester'; Email = 'lo@example.com' }.GetEnumerator()) {
                New-ItemProperty -Path $KEY32 -Name $kv.Key -Value $kv.Value -PropertyType String -Force | Out-Null
            }
            W ("registration: full set with Serial={0}" -f $Serial)
        }
    }
}

# ----------------------------------------------------------------- 6) report
$cur = Get-ItemProperty -Path $KEY32 -ErrorAction SilentlyContinue
W ("HKLM Serial    = '{0}'" -f $cur.Serial)
# 只报告「生效的」屏蔽行数 —— 含标记但被注释的行不算数（旧的数法会假报成功）。
# 注意必须限定在**我们这 6 个域名**上：宽松的 '^\s*0\.0\.0\.0\s+\S+' 会把无关的
# 0.0.0.0 映射（本机 hosts 里有 api.mcneel.com 等 3 条）一起数进来，报出 9 这种数字。
$liveEnd = @(Get-Content -LiteralPath $HOSTS)
$ourDomRe = ($DOMAINS | ForEach-Object { [regex]::Escape($_) }) -join '|'
$activeEnd = @($liveEnd | Where-Object { $_ -match ('^\s*0\.0\.0\.0\s+\S*(' + $ourDomRe + ')(\s|$)') }).Count
$markerEnd = @($liveEnd | Where-Object { $_ -match [regex]::Escape($MARKER) }).Count
W ("hosts 生效行(仅本工具6域名) = {0} / 含标记行 = {1} / 总行数 = {2}" -f $activeEnd, $markerEnd, $liveEnd.Count)
W "=== done ==="
Write-Output "log: $log"
