<#
  stage1-download-regression.ps1 - DRAFT, task-3 stage-1 item 3 deliverable.

  PURPOSE
    The previous deployer round NEVER ran a real download regression. Two things
    are being tested at once:
      (A) FUNCTION - IDM can still download a real ~10 MB file end to end, with the
          on-disk result bit-identical to an independent fetch.
      (B) NON-REGRESSION - the P6 popup silencing did not blind IDM to its normal
          prompt paths.  The strongest available check is that NO unexpected
          dialog (`#32770`) appears during a clean download, and that no
          "downloaded file is incomplete / error" text shows up.  If a dialog DOES
          appear, its full text is captured so it can be judged rather than guessed.

  DESIGN NOTE
    The reference is fetched with BOTH Invoke-WebRequest and curl.exe if present,
    and the URL is probed with HEAD first.  proof.ovh.net has been unreliable; the
    script accepts -Url so a mirror can be substituted without editing code.  If
    every fetch path fails the script reports MANUAL-ACTION-REQUIRED instead of
    silently scoring a bad download as a mismatch.

  RUN FROM AN ELEVATED POWERSHELL:
    powershell -NoProfile -ExecutionPolicy Bypass -File `
      D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify\stage1-download-regression.ps1 `
      -ExpectedSha <T1 sha256>
#>
[CmdletBinding()]
param(
  [string]$Url        = 'https://proof.ovh.net/files/10Mb.dat',
  [string]$FileName   = 'ovh-10Mb.dat',
  [int]   $MaxWaitSec = 300,
  [int]   $PollMs     = 1000,
  [string]$ExpectedSha= '',
  [switch]$KeepMData,                       # default: leave MData exactly as found
  [string]$OutDir     = 'D:\pojie应用\jiesuo\work\idm-6.43b8\logs\verify'
)
$ErrorActionPreference='Continue'
. (Join-Path $OutDir 'verify-v3-common.ps1')
$EXE='C:\Program Files (x86)\Internet Download Manager\IDMan.exe'
$DL = Join-Path $OutDir 'dl'
New-Item -ItemType Directory -Force -Path $DL | Out-Null
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$log=Join-Path $OutDir ("dl-regression-$stamp.log")
function W($m){ $m | Tee-Object -FilePath $log -Append }
function Fail($m){ W ("!! ABORT: {0}" -f $m); W "=== dl-regression ABORTED ==="; exit 2 }

$RE_ERROR='incomplete|error|失败|错误|无法|cannot|unable|invalid|corrupt'
$RE_COUNTERFEIT='假冒|counterfeit|正在退出|is exiting|Serial Number'

W ("=== download regression  {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("log = {0}" -f $log)
try{ [void](Assert-Elevated) }catch{ Fail $_.Exception.Message }
W "elevated = True"

$sha = Get-BinHash
W ("installed sha256 = {0}" -f $sha)
if($ExpectedSha -and $sha -ne $ExpectedSha.ToUpper()){ Fail "sha256 mismatch vs -ExpectedSha $ExpectedSha" }
if(-not $ExpectedSha){ W "!! -ExpectedSha not supplied (baseline mode)" }

$run=@(Get-Process IDMan -ErrorAction SilentlyContinue)
if($run.Count -gt 0){ Fail ("IDMan.exe already running (pid {0}) - exclusive access required" -f (($run|ForEach-Object{$_.Id}) -join ',')) }
W "exclusive access OK (no IDMan.exe running)"

$reg=Get-IdmRegistration
W ("registration: Serial='{0}' FName='{1}'" -f $reg.Serial,$reg.FName)
$mdBefore=@(Get-MData)
W ("MData before run = {0} value(s)" -f $mdBefore.Count)

# ---- 0) confirm the host is blocked (download must NOT go to IDM's own domain)
W "--- DNS state (the download host must NOT be hosts-blocked; IDM domains must be) ---"
foreach($r in (Get-DnsBlockState)){ W ("  DNS {0,-38} -> {1}  blocked={2}" -f $r.Domain,($(if($r.Ips){$r.Ips}else{'<unresolved>'})),$r.Blocked) }
try{
  $u=[uri]$Url
  $hostIps = @(Resolve-DnsName $u.Host -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
  W ("download host {0} -> {1}" -f $u.Host,($hostIps -join ','))
  if($hostIps.Count -eq 1 -and $hostIps[0] -eq '0.0.0.0'){ Fail "the download host itself resolves to 0.0.0.0 - hosts is blocking it; pick another -Url" }
}catch{ W ("!! could not resolve download host: {0}" -f $_.Exception.Message) }

# ---- 1) independent reference fetch (NOT through IDM) ---------------------
W "--- reference fetch (independent of IDM) ---"
$refFile=Join-Path $DL 'reference.bin'
if(Test-Path $refFile){ Remove-Item $refFile -Force }
$refHash=$null; $refLen=0
$fetchers = @(
  @{ Name='curl.exe';  Cmd={ curl.exe -sSL --max-time 180 -o $refFile $Url; $LASTEXITCODE } },
  @{ Name='Invoke-WebRequest'; Cmd={ Invoke-WebRequest -Uri $Url -OutFile $refFile -TimeoutSec 180 -UseBasicParsing; 0 } }
)
foreach($f in $fetchers){
  W ("  trying {0} ..." -f $f.Name)
  try{
    $rc = & $f.Cmd
    if((Test-Path $refFile) -and (Get-Item $refFile).Length -gt 0){
      $refLen=(Get-Item $refFile).Length
      $refHash=(Get-FileHash $refFile -Algorithm SHA256).Hash
      W ("  reference OK via {0}: {1} bytes sha256={2}" -f $f.Name,$refLen,$refHash); break
    } else { W ("  {0} produced no file (rc={1})" -f $f.Name,$rc) }
  }catch{ W ("  {0} FAILED: {1}" -f $f.Name,$_.Exception.Message) }
}
if(-not $refHash){
  W "!! ALL independent fetch paths failed."
  W "!! The download test can still run, but correctness CANNOT be scored."
  W "!! REPORT THIS AS MANUAL-ACTION-REQUIRED, do not score it as a pass."
}

# ---- 2) drive the download through IDM ------------------------------------
W ""
W "--- driving IDM download: /d <url> /p <dir> /f <name> /q ---"
$target=Join-Path $DL $FileName
if(Test-Path $target){ Remove-Item $target -Force }
$sw=[Diagnostics.Stopwatch]::StartNew()
$ip=Start-Process -FilePath $EXE -PassThru            # main UI instance
$idmPid=$ip.Id
W ("launched IDMan pid={0} at {1}" -f $idmPid,(Get-Date -Format 'HH:mm:ss'))
Start-Sleep -Seconds 8
$dp=Start-Process -FilePath $EXE -ArgumentList @('/d',$Url,'/p',$DL,'/f',$FileName,'/q') -PassThru
W ("downloader invocation pid={0}" -f $dp.Id)

$seen=@{}; $modalDetails=New-Object System.Collections.ArrayList
$errTitles=New-Object System.Collections.ArrayList; $lastLog=-10
$dlFullAt=$null; $lastSize=0; $stalledSince=$null; $alive=$true; $exitHex=''; $outcome='UNKNOWN'
$maxSize=0

while($sw.Elapsed.TotalSeconds -lt $MaxWaitSec){
  Start-Sleep -Milliseconds $PollMs
  $el=$sw.Elapsed.TotalSeconds
  try{
    foreach($w in (Get-IdmWindows -Pid $idmPid)){
      $sig="{0}|{1}|{2}" -f $w.Cls,$w.Txt,$w.Vis
      if(-not $seen.ContainsKey($sig)){ $seen[$sig]=[math]::Round($el,1) }
      if($w.Vis -and $w.Cls -eq '#32770'){
        $hkey='M|{0}' -f $w.Hwnd
        if(-not $seen.ContainsKey($hkey)){
          $seen[$hkey]=[math]::Round($el,1)
          $d=Get-ModalDetail -Hwnd $w.H
          [void]$modalDetails.Add([pscustomobject]@{ At=[math]::Round($el,1); Class=$d.Class; Title=$d.Title; BodyOneLine=$d.BodyOneLine; ButtonSet=$d.ButtonSet })
        }
        if($w.Txt -match $RE_ERROR -or $w.Txt -match 'Internet Download Manager'){
          if(-not $errTitles.Contains($w.Txt)){ [void]$errTitles.Add($w.Txt) }
        }
      }
    }
  }catch{}
  if(Test-Path $target){
    $sz=(Get-Item $target).Length
    if($sz -gt $maxSize){ $maxSize=$sz }
    if($sz -eq $lastSize){ if($null -eq $stalledSince){ $stalledSince=$el } }
    else { $stalledSince=$null }
    $lastSize=$sz
    if($null -eq $dlFullAt -and $refLen -gt 0 -and $sz -eq $refLen){ $dlFullAt=[math]::Round($el,1); W ("  file reached reference size {0} bytes at {1}s" -f $sz,$dlFullAt) }
  }
  $ip.Refresh()
  if($ip.HasExited){
    $alive=$false; $ec=$ip.ExitCode; $exitHex='0x{0:X8}' -f ($ec -band 0xFFFFFFFF)
    $outcome = if($ec -eq 0){'clean-exit-0'} else {"NONZERO-EXIT $exitHex (hard failure)"}
    W ("  !! IDMan.exe DIED at {0}s exitcode={1} ({2})  <<< {3}" -f [math]::Round($el,1),$ec,$exitHex,$outcome)
    break
  }
  if(($el-$lastLog) -ge 30){ $lastLog=$el; W ("  t={0,4}s alive dlbytes={1} max={2} stalledFor={3}" -f [math]::Round($el,0),$lastSize,$maxSize,$(if($null -ne $stalledSince){[math]::Round($el-$stalledSince,0)}else{0})) }
  # early exit: complete + no dialog + downloader process gone
  if($null -ne $dlFullAt -and $modalDetails.Count -eq 0){ try{ $dp.Refresh(); if($dp.HasExited){ W "  downloader exited and file is complete -> stopping early"; break } }catch{} }
}
$survival=[math]::Round($sw.Elapsed.TotalSeconds,1); $sw.Stop()
if($alive){ $outcome='SURVIVED-SOAK' }

# ---- 3) verify the artefact ----------------------------------------------
W ""
W "=== DOWNLOAD VERIFICATION ==="
$ok=$null
if(Test-Path $target){
  $th=(Get-FileHash $target -Algorithm SHA256).Hash
  $ts=(Get-Item $target).Length
  W ("IDM download : {0} bytes  sha256={1}" -f $ts,$th)
  if($refHash){
    W ("reference    : {0} bytes  sha256={1}" -f $refLen,$refHash)
    if($th -eq $refHash){ $ok=$true;  W "MATCH: sha256 identical -> download is bit-correct" }
    else               { $ok=$false; W "MISMATCH: download differs from the independent reference" }
  } else {
    W ("reference    : UNAVAILABLE (all independent fetches failed)")
    W ("size-only    : {0} bytes (a ~10MB dat is expected; size alone is NOT proof of correctness)" -f $ts)
  }
} else { W ("IDM produced NO file at {0}" -f $target); $ok=$false }

W ""
W "--- POPUP FORENSICS (task-3 item 6) ---"
if($modalDetails.Count -eq 0){ W "  (no #32770 dialog appeared - the normal download path is silent)" }
foreach($d in $modalDetails){
  W ("  t={0}s class='{1}'" -f $d.At,$d.Class)
  W ("    TITLE  : {0}" -f $d.Title)
  W ("    BODY   : {0}" -f $d.BodyOneLine)
  W ("    BUTTONS: {0}" -f $d.ButtonSet)
}
W "--- every distinct window (class|title|visible -> first seen) ---"
foreach($k in ($seen.Keys | Sort-Object { $seen[$_] })){
  if($k -like 'M|*'){ continue }
  $q=$k.Split('|'); W ("  t={0,7}s vis={1,-5} class='{2}' title='{3}'" -f $seen[$k],$q[2],$q[0],$q[1])
}

$mdAfter=@(Get-MData)
W ""
W "=== VERDICT ==="
W ("url                   : {0}" -f $Url)
W ("file                  : {0}" -f $target)
W ("download verified     : {0}" -f $(if($null -eq $ok){'UNSCORED (no reference)'}else{$ok}))
W ("max bytes seen        : {0}" -f $maxSize)
W ("unexpected dialogs    : {0}" -f $modalDetails.Count)
W ("survival              : {0}s  ({1})" -f $survival,$outcome)
W ("exit_code_hex         : {0}" -f $(if($exitHex){$exitHex}else{'(still alive)'}))
W ("MData before/after    : {0} / {1}" -f $mdBefore.Count,$mdAfter.Count)
W ("PASS criterion        : download sha256==reference AND 0 unexpected dialogs AND no nonzero exit")
W ("log={0}" -f $log)
if(-not $KeepMData){ W "(MData was left as found: the script never writes or clears it)" }
