<#
W26-13: packet capture on the Windows target with built-in pktmon (Windows 10
1809+, Server 2019+). Elevated.
Usage:  .\capture.ps1 start | stop  [-EvidenceRoot .\evidence]
stop also writes wstep.pcapng via 'pktmon etl2pcap' and prints SHA-256 of both files.
Capture before collect-client.ps1 start, stop after it finishes.
#>
param(
  [Parameter(Mandatory, Position = 0)][ValidateSet('start', 'stop')][string]$Action,
  [string]$EvidenceRoot = (Join-Path $PSScriptRoot 'evidence')
)
$ErrorActionPreference = 'Stop'
$dir = Join-Path $EvidenceRoot $env:COMPUTERNAME.ToLower()
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$etl = Join-Path $dir 'wstep.etl'
$pcap = Join-Path $dir 'wstep.pcapng'
switch ($Action) {
  'start' {
    # cmd /c: a native stderr line ("not running") is a terminating error under ErrorActionPreference=Stop, notably over WinRM.
    cmd /c 'pktmon stop >nul 2>&1'
    cmd /c 'pktmon filter remove >nul 2>&1'
    pktmon start --capture --comp nics -f $etl
  }
  'stop' {
    pktmon stop
    pktmon etl2pcap $etl --out $pcap
    foreach ($f in $etl, $pcap) {
      if (Test-Path $f) { "{0} sha256={1}" -f $f, (Get-FileHash $f -Algorithm SHA256).Hash }
    }
  }
}
