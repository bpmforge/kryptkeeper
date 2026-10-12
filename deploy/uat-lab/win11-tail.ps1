# win11: point DNS at the lab DC and join corp.example.test, then reboot into the domain.
Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses '__DC_IP__'
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', (ConvertTo-SecureString '__ADMIN_PW__' -AsPlainText -Force))
for ($i = 0; $i -lt 20; $i++) {
  if (Resolve-DnsName corp.example.test -ErrorAction SilentlyContinue) { break }
  Start-Sleep -Seconds 15
}
Add-Computer -DomainName 'corp.example.test' -Credential $cred -Restart -Force
