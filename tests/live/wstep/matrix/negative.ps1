<#
W26-13: negative checks, run ON the Windows target, elevated, AFTER a successful
enrollment. WARNING: test (b) skews the clock +10 minutes and always restores it
with w32tm /resync in a finally block. A skewed VM breaks the lab for the next target.
Usage:  .\negative.ps1 -XcepUrl https://lab-hub.corp.example.test:8443/xcep -HubCaSubject 'CN=Kryptkeeper Root CA' [-SkewMinutes 10]
(a) template filter: machine context lists only machine templates; save the
    user-context list separately (run the same certutil line in a user session
    and diff) into evidence\<host>\templates-user.txt.
(b) skew > 5 min: expect NO new cert; hub side expects a denied row
    (hub-checks.sh <host> --skew-denied).
Do not use SkewMinutes below 6: the hub backdates NotBefore by 5 min, so smaller skews still work.
#>
param(
  [Parameter(Mandatory)][string]$XcepUrl,
  [Parameter(Mandatory)][string]$HubCaSubject,
  [string]$EvidenceRoot = (Join-Path $PSScriptRoot 'evidence'),
  [ValidateRange(6, 60)][int]$SkewMinutes = 10
)
$ErrorActionPreference = 'Stop'
$hostName = $env:COMPUTERNAME.ToLower()
$dir = Join-Path $EvidenceRoot $hostName
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$log = Join-Path $dir 'negative.txt'
function Say($m) { $m | Tee-Object -FilePath $log -Append }
function Get-HubCerts { Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like "*$HubCaSubject*" } }

# (a) template filter
Say "== (a) templates offered to the machine context =="
$machineList = certutil -v -PolicyServer $XcepUrl -Kerberos -Template
$machineList | Set-Content (Join-Path $dir 'templates-machine.txt')
$machineList | ForEach-Object { Say $_ }
Say "Compare with templates-user.txt (same command in a user session): the user template must be absent here."

# (b) clock skew
Say "== (b) Kerberos clock skew +$SkewMinutes min =="
$before = @(Get-HubCerts | ForEach-Object Thumbprint)
$orig = Get-Date
$skewed = $false
try {
  w32tm /config /manualpeerlist:"" /syncfromflags:manual | Out-Null
  Set-Date $orig.AddMinutes($SkewMinutes) | Out-Null
  $skewed = $true
  Say "clock now $(Get-Date -Format o) (was $($orig.ToString('o')))"
  certutil -f -PolicyServer * -PolicyCache delete | Out-Null
  certutil -pulse | ForEach-Object { Say $_ }
  Start-Sleep -Seconds 30
}
finally {
  # Mandatory restore. Re-point w32tm at the domain hierarchy, then resync.
  w32tm /config /syncfromflags:domhier /update | Out-Null
  w32tm /resync /force | ForEach-Object { Say $_ }
  Say "clock restored to $(Get-Date -Format o) (skewed=$skewed)"
}
$new = @(Get-HubCerts | Where-Object { $before -notcontains $_.Thumbprint })
if ($new.Count -eq 0) { Say 'RESULT skew-refused=true (no new certificate in LocalMachine\My)' }
else { Say "RESULT skew-refused=false new=$($new.Thumbprint -join ',')"; exit 1 }
Say "Now run on the operator box: hub-checks.sh $hostName --skew-denied"
