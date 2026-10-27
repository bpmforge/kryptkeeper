<#
Key-usage regression check, run ON a Windows target, elevated. Pulses machine
autoenrollment and then reports what Windows accepted into LocalMachine\My:
key usage, EKU, key algorithm, private-key presence, template extension, and
the result of `certutil -verify -urlfetch` on the new certificate.

Usage:  .\ku-check.ps1 -HubCaSubject 'KK UAT Lab Root CA' [-TimeoutSeconds 120]
Over WinRM run Set-ExecutionPolicy -Scope Process Bypass -Force first.
Exit 1 when no new hub certificate appears or the chain does not validate.
#>
param(
  [Parameter(Mandatory)][string]$HubCaSubject,
  [int]$TimeoutSeconds = 120
)
$ErrorActionPreference = 'Continue'
function Get-HubCerts { Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like "*$HubCaSubject*" } }
$os = Get-CimInstance Win32_OperatingSystem
"host=$($env:COMPUTERNAME) os='$($os.Caption)' build=$($os.BuildNumber) time=$(Get-Date -Format o)"
$before = @(Get-HubCerts | ForEach-Object Thumbprint)
"hub-issued certs before: $($before.Count) $($before -join ',')"
$start = Get-Date
certutil -f -PolicyServer * -PolicyCache delete | Out-Null
gpupdate /force /target:computer | Out-Null
certutil -pulse | Out-Null
$new = $null
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline -and -not $new) {
  $new = Get-HubCerts | Where-Object { $before -notcontains $_.Thumbprint } | Select-Object -First 1
  if (-not $new) { Start-Sleep -Seconds 5 }
}
if (-not $new) { "RESULT enrolled=false after ${TimeoutSeconds}s"; exit 1 }
"RESULT enrolled=true seconds=$([int]((Get-Date) - $start).TotalSeconds) store=Cert:\LocalMachine\My"
$ku = ($new.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' } | ForEach-Object { $_.Format($false) }) -join ';'
$eku = ($new.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object { $_.Format($false) }) -join ';'
$tpl = ($new.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' } | ForEach-Object { $_.Format($false) }) -join ';'
"thumbprint=$($new.Thumbprint) subject='$($new.Subject)' issuer='$($new.Issuer)'"
"keyAlgorithm=$($new.PublicKey.Oid.FriendlyName) keyBits=$($new.PublicKey.Key.KeySize) hasPrivateKey=$($new.HasPrivateKey)"
"keyUsage='$ku'"
"eku='$eku'"
"templateExtension='$tpl'"
"notBefore=$($new.NotBefore.ToString('o')) notAfter=$($new.NotAfter.ToString('o'))"
"keyEnciphermentPresent=$($ku -match 'Key Encipherment')"
$cer = Join-Path $env:TEMP 'kk-ku-check.cer'
[IO.File]::WriteAllBytes($cer, $new.RawData)
$v = certutil -verify -urlfetch $cer 2>&1
$v | Select-String 'Verified|Revocation|revocation|passed|failed|ERROR|Leaf|Chain|completed|CRL|OCSP|Issuer:|Cert is' | ForEach-Object { "verify: $($_.Line.Trim())" }
Remove-Item $cer -Force -ErrorAction SilentlyContinue
$chainOk = [bool]($v | Select-String 'CertUtil: -verify command completed successfully')
"RESULT chainValid=$chainOk"
if (-not $chainOk) { exit 1 }
