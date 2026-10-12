# dc01: promote a new forest for the lab. Reboots on completion.
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
$dsrm = ConvertTo-SecureString '__DSRM_PW__' -AsPlainText -Force
Install-ADDSForest -DomainName 'corp.example.test' -DomainNetbiosName 'CORP' -InstallDns `
  -SafeModeAdministratorPassword $dsrm -NoRebootOnCompletion:$false -Force
