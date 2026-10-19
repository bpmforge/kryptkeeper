<#
W26-13: run ON each Windows target, elevated. Machine-context GPO autoenrollment
evidence: no manual enrollment is performed, only a policy refresh and a pulse.
Usage:  .\collect-client.ps1 -HubCaSubject 'CN=Kryptkeeper Root CA' [-EvidenceRoot .\evidence] [-TimeoutSeconds 120]
-HubCaSubject is a substring matched against the issued certificate's Issuer.
#>
param(
  [Parameter(Mandatory)][string]$HubCaSubject,
  [string]$EvidenceRoot = (Join-Path $PSScriptRoot 'evidence'),
  [int]$TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'run from an elevated PowerShell'
}
$hostName = $env:COMPUTERNAME.ToLower()
$dir = Join-Path $EvidenceRoot $hostName
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$log = Join-Path $dir 'client.txt'
function Say($m) { $m | Tee-Object -FilePath $log -Append }

$os = Get-CimInstance Win32_OperatingSystem
Say "host=$hostName os='$($os.Caption)' version=$($os.Version) build=$($os.BuildNumber) time=$(Get-Date -Format o)"

function Get-HubCerts { Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like "*$HubCaSubject*" } }
$before = @(Get-HubCerts | ForEach-Object Thumbprint)
Say "hub-issued certs before: $($before.Count)"
$start = Get-Date

# Drop the 8 h policy cache so the pulse sees current policy (runbook trap).
certutil -f -PolicyServer * -PolicyCache delete | Out-Null
gpupdate /force /target:computer | ForEach-Object { Say $_ }
certutil -pulse | ForEach-Object { Say $_ }

$new = $null
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline -and -not $new) {
  $new = Get-HubCerts | Where-Object { $before -notcontains $_.Thumbprint } | Select-Object -First 1
  if (-not $new) { Start-Sleep -Seconds 5 }
}
if ($new) {
  $tpl = ($new.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' } | ForEach-Object { $_.Format($false) }) -join ';'
  Say "RESULT enrolled=true seconds=$([int]((Get-Date) - $start).TotalSeconds)"
  Say "thumbprint=$($new.Thumbprint) subject='$($new.Subject)' issuer='$($new.Issuer)'"
  Say "templateExtension(1.3.6.1.4.1.311.21.7)='$tpl' notBefore=$($new.NotBefore.ToString('o')) notAfter=$($new.NotAfter.ToString('o'))"
} else {
  Say "RESULT enrolled=false after ${TimeoutSeconds}s"
}

# Event logs. Channel names vary slightly by build; export whichever exist.
$channels = wevtutil el | Where-Object { $_ -match 'CertificateServicesClient-(Lifecycle-System|CertEnroll)' }
if (-not $channels) { Say 'WARN no CertificateServicesClient-* channels found on this build' }
foreach ($c in $channels) {
  $file = Join-Path $dir ("events-{0}.evtx" -f ($c -replace '[\\/]', '_'))
  if (Test-Path $file) { Remove-Item $file -Force }
  wevtutil epl $c $file
  Say "exported $c -> $file sha256=$((Get-FileHash $file -Algorithm SHA256).Hash)"
}
Say "done. Next: capture.ps1 stop, then hub-checks.sh $hostName on the operator box."
if (-not $new) { exit 1 }
