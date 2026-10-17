# repair-hosts-block.ps1 — repair ONLY the hosts block, leaving registration alone.
#
# Why this exists: `idm-permanent-fix.ps1` does hosts + registration + MData in one
# pass, which is too coarse when a soak is running. This touches hosts only.
#
# Two defects it fixes:
#   1. Some block lines had been commented out with `#`, so
#      www / secure / register.internetdownloadmanager.com were NOT actually
#      blocked (they still resolved to 67.18.60.145 / 67.18.140.140). The old
#      verification only counted lines containing the marker, and a commented-out
#      line still contains it -- so it reported success.
#   2. The `.bak-permanentfix` backup had been taken AFTER the block was applied,
#      so restoring from it would not remove the block. The backup must be the
#      clean baseline (all marker lines stripped).
#
# Run ELEVATED.

$ErrorActionPreference = 'Continue'
$HOSTS  = "$env:SystemRoot\System32\drivers\etc\hosts"
$BACKUP = $HOSTS + '.bak-permanentfix'
$MARKER = '# IDM-Activator-PermanentFix'
$DOMAINS = @(
    'internetdownloadmanager.com',
    'www.internetdownloadmanager.com',
    'secure.internetdownloadmanager.com',
    'register.internetdownloadmanager.com',
    'tonec.com',
    'www.tonec.com'
)
$log = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\permanent-fix\repair-hosts.log'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
function W($m) { $m | Tee-Object -FilePath $log -Append }

# ---------------------------------------------------------------------------
# FIX 2026-10-17 (deployer, task-3 rev3 item B) - two defects repaired here.
#
# DEFECT 1 - THE VERIFICATION ORACLE WAS BROKEN AND COULD ONLY EVER PASS.
#   Old check:  $reachable = $ping -match '67\.18\.'
#   When a domain IS correctly blocked, ping prints
#     "Ping request could not find host <d>. Please check the name and try again."
#   and exits 1. That text contains no "67.18." at all, so $reachable was ALWAYS
#   $false and the check reported OK for every domain, blocked or not. Measured:
#     cmd /c ping -n 1 register.internetdownloadmanager.com
#       -> "could not find host", exit 1
#   It also only recognised 67.18.x.x, so any other answer (proxy, sinkhole,
#   changed IP) scored OK too.
#   REPLACEMENT: resolve the name and require the answer to BE 0.0.0.0. That is
#   the only form of the test that can both pass and fail.
#   NOTE: the old comment here claimed Resolve-DnsName "may give a false pass".
#   That is backwards - the false pass was produced by the ping regex.
#
# DEFECT 2 - THE STRIP RULE LEAKED COMMENTED-OUT BLOCK LINES.
#   Old: keep = lines NOT containing the marker. A commented-out block line
#   ("#0.0.0.0 www... # IDM-Activator-PermanentFix") could survive or be orphaned
#   so it was never cleaned up. The strip now also drops any commented-out
#   "0.0.0.0 <our domain>" line, so a commented line cannot accumulate.
#   Measured idempotent: three consecutive rebuilds are byte-identical
#   (logs/permanent-fix/hosts-fix-simulation.log).
# ---------------------------------------------------------------------------
$DOMAIN_RE = ($DOMAINS | ForEach-Object { [regex]::Escape($_) }) -join '|'

function Strip-Ours([string[]]$lines) {
    @($lines | Where-Object {
        ($_ -notmatch [regex]::Escape($MARKER)) -and
        ($_ -notmatch ('^\s*#\s*0\.0\.0\.0\s+(' + $DOMAIN_RE + ')(\s|$)'))
    })
}

function Get-ActiveBlockDomains([string[]]$lines) {
    # Only a live "0.0.0.0 <domain>" line counts; commented lines never do.
    $ok = @()
    foreach ($d in $DOMAINS) {
        $pat = '^\s*0\.0\.0\.0\s+' + [regex]::Escape($d) + '(\s|$)'
        if (@($lines | Where-Object { $_ -match $pat }).Count -ge 1) { $ok += $d }
    }
    return $ok
}

function Resolve-HostA([string]$d) {
    try {
        return @(Resolve-DnsName $d -Type A -ErrorAction Stop |
                 Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
    } catch { return @() }
}

W ("=== repair-hosts-block {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

$lines = @(Get-Content -LiteralPath $HOSTS)
$kept  = Strip-Ours $lines
W ("原文件 {0} 行，剥离本工具的块（含被注释的孤儿行）后干净基线 {1} 行" -f $lines.Count, $kept.Count)

# 1) 干净基线备份
[System.IO.File]::WriteAllLines($BACKUP, $kept, [System.Text.Encoding]::ASCII)
W ("已写入干净基线备份 {0}" -f $BACKUP)

# 2) 重新追加完整屏蔽块（全部不带 `#`）
$new = $kept + @($MARKER) + @($DOMAINS | ForEach-Object { "0.0.0.0 $_ $MARKER" })
$tmp = $HOSTS + '.new'
[System.IO.File]::WriteAllLines($tmp, $new, [System.Text.Encoding]::ASCII)
Copy-Item -LiteralPath $tmp -Destination $HOSTS -Force
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
W "已重写 hosts"

# 3) 刷新 DNS 缓存 —— **必须做**。只改 hosts 而不刷缓存，屏蔽不会生效。
#    （旧注释称「本机实测 ping 仍解析到 67.18.x.x」，那是「只改文件没刷缓存」时的
#      现象；缓存刷掉之后 ping 会直接报 "could not find host"。两者都不该用
#      ping 的文本去判成败，见上面 DEFECT 1。）
& ipconfig /flushdns 2>&1 | Out-Null
Start-Sleep -Milliseconds 800
W "已执行 ipconfig /flushdns"

# 4) 逐域名校验：两个独立信号，都必须过
#    (a) 文件内容：该域名有且仅有 1 条生效的 `0.0.0.0` 行（幂等性由它保证）
#    (b) 解析结果：Resolve-DnsName 必须**就是** 0.0.0.0（真正的 oracle）
$live = @(Get-Content -LiteralPath $HOSTS)
$bad  = @()
foreach ($d in $DOMAINS) {
    $pat = '^\s*0\.0\.0\.0\s+' + [regex]::Escape($d) + '(\s|$)'
    $n   = @($live | Where-Object { $_ -match $pat }).Count
    # See idm-permanent-fix.ps1 for the full note. PS 5.1 unwraps a one-element
    # `return @(...)`, so $ips would be the scalar string "0.0.0.0"; $ips[0] then
    # does CHARACTER indexing -> "0" and the comparison silently fails (measured:
    # this reported 0/6 on a correct file). The `@()` HERE is the fix.
    $ips = @(Resolve-HostA $d)
    $resolved = if ($ips.Count -eq 0) { '<unresolved>' } else { ($ips -join ',') }
    $isZero   = ($ips.Count -eq 1) -and ([string]$ips[0] -eq '0.0.0.0')
    $ok = ($n -eq 1) -and $isZero
    if (-not $ok) { $bad += $d }
    W ('  {0,-40} 生效行={1}  解析={2}  {3}' -f $d, $n, $resolved, $(if ($ok) { 'OK' } else { '!! 未生效' }))
}
if ($bad.Count -eq 0) {
    W "全部 6 个域名屏蔽生效（生效行=1 且解析=0.0.0.0，已 flushdns 后复核）"
} else {
    W ('!! 仍有域名未生效: {0}' -f ($bad -join ', '))
}
# 5) 幂等性自检：把刚写出的文件再跑一遍剥离，行数必须不变
$reStripped = Strip-Ours @(Get-Content -LiteralPath $HOSTS)
W ("幂等自检：剥离后基线 {0} 行（应与本次备份行数一致）；当前总行数 {1}" -f `
   $reStripped.Count, @(Get-Content -LiteralPath $HOSTS).Count)
W "=== done ==="
