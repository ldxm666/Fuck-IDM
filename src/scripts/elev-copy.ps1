param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Dest,
    [string]$Log = ""
)
$ErrorActionPreference = "Stop"
$lines = @()
try {
    Copy-Item -LiteralPath $Source -Destination $Dest -Force
    $h = (Get-FileHash -LiteralPath $Dest -Algorithm SHA256).Hash
    $lines += ("ELEVATED_COPY_OK dest={0} size={1} sha256={2}" -f $Dest, (Get-Item -LiteralPath $Dest).Length, $h)
} catch {
    $lines += ("ELEVATED_COPY_FAIL {0}" -f $_.Exception.Message)
}
$text = $lines -join "`n"
Write-Output $text
if ($Log) { Set-Content -LiteralPath $Log -Value $text -Encoding utf8 }
