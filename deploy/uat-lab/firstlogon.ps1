# Runs once at first logon of a KK UAT lab Windows VM (from autounattend.xml).
# Role-specific tail is appended per VM: dc01 promotes a forest, win11 joins it.
$ErrorActionPreference = 'Continue'
Start-Transcript -Path C:\kk-firstlogon.log -Append
# QEMU guest agent from the virtio-win CD, so the hypervisor can report the VM's IP.
# The agent talks over a VirtIO serial port, so the driver bundle goes in first;
# the agent alone installs but stays "not running" to the hypervisor.
function Find-OnCd($rel) { Get-PSDrive -PSProvider FileSystem | ForEach-Object { Join-Path $_.Root $rel } | Where-Object { Test-Path $_ } | Select-Object -First 1 }
foreach ($rel in 'virtio-win-gt-x64.msi', 'guest-agent\qemu-ga-x86_64.msi') {
  $msi = Find-OnCd $rel
  if ($msi) { Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait }
}
# WinRM is how the lab is driven after install (lab LAN only).
Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
Enable-PSRemoting -Force -SkipNetworkProfileCheck
