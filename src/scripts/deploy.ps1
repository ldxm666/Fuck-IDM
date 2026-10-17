param(
    [Parameter(Mandatory=$true)][string]$Patched,
    [string]$InstallDir = "C:\Program Files (x86)\Internet Download Manager",
    [string]$Log = ""
)
# Stop IDM, back up the pristine IDMan.exe once, install the patched build, drop the test copy.
$ErrorActionPreference = "Continue"
$lines = @()
try {
    $target = Join-Path $InstallDir "IDMan.exe"
    $bak    = Join-Path $InstallDir "IDMan.exe.bak-original"

    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "IDMan*" } | ForEach-Object {
        $lines += "stopping $($_.ProcessName) pid=$($_.Id)"
        try { $_.Kill() } catch { $lines += "  kill failed: $($_.Exception.Message)" }
    }
    Start-Sleep -Seconds 4

    if (-not (Test-Path -LiteralPath $bak)) {
        Copy-Item -LiteralPath $target -Destination $bak -Force
        $lines += "BACKUP  $bak"
        $lines += "        sha256 $((Get-FileHash -LiteralPath $bak -Algorithm SHA256).Hash)"
    } else {
        $lines += "BACKUP  already present (left untouched)"
        $lines += "        sha256 $((Get-FileHash -LiteralPath $bak -Algorithm SHA256).Hash)"
    }

    Copy-Item -LiteralPath $Patched -Destination $target -Force
    $lines += "DEPLOY  $target"
    $lines += "        sha256 $((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash)"
    $lines += "        size   $((Get-Item -LiteralPath $target).Length)"

    $t = Join-Path $InstallDir "IDMan_test.exe"
    if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force; $lines += "CLEANUP removed $t" }
} catch {
    $lines += "FAIL $($_.Exception.Message)"
}
$text = $lines -join "`n"
Write-Output $text
if ($Log) { Set-Content -LiteralPath $Log -Value $text -Encoding utf8 }
