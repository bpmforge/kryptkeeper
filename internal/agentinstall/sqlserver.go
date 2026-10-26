// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// W35-02: Microsoft SQL Server (Windows, over WinRM).
//
// SQL Server does not read the certificate store on every handshake. The
// thumbprint of the certificate it presents is the "Certificate" value under
// the instance's SuperSocketNetLib registry key, read when the service starts:
//
//	HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<instance id>\MSSQLServer\SuperSocketNetLib\Certificate
//
// where <instance id> is the MSSQL<major>.<name> value mapped from the plain
// instance name under "Instance Names\SQL" (MSSQL15.MSSQLSERVER for a default
// 2019 install, MSSQL16.* for 2022). The value is the thumbprint without
// spaces. Source: Microsoft Learn, "Encrypt Connections by Importing a
// Certificate", https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-sql-server-encryption
// ("Extra procedure for failover cluster instances" and "Certificate
// precedence"). The same page requires the SERVICE ACCOUNT to have read on the
// certificate's private key -- "Failure to do so can cause the SQL Server
// service restart to fail" -- which is why the key ACL step precedes the
// restart and why a restart failure rolls the registry back and starts the
// service again.
//
// Casing: before SQL Server 2022 CU22 / 2025 Configuration Manager only
// lists a registry-configured certificate whose thumbprint matches exactly, so
// the value is written lowercase, the form Configuration Manager itself writes.
//
// TLS for SQL Server is negotiated inside TDS PRELOGIN, so the verify step is
// not a plain TLS dial: bootstrap supplies NewTDSVerifier (the scanner's
// PRELOGIN-framed handshake) as the Verifier.

// SQLServerInstallRequest describes one renewed certificate for one instance.
type SQLServerInstallRequest struct {
	// Instance is the plain instance name; empty means MSSQLSERVER.
	Instance string

	CertPEM []byte
	KeyPEM  []byte

	// VerifyHostPort is the instance's TDS endpoint (host:port); with
	// ExpectedFingerprint (SHA-256 of the leaf) it gates the install.
	VerifyHostPort      string
	ExpectedFingerprint string
}

// SQLServerInstaller installs a certificate for a SQL Server instance.
type SQLServerInstaller struct {
	exec      Executor
	verify    Verifier
	stageRoot string
}

// NewSQLServerInstaller returns an installer backed by exec. The default
// verifier is the TDS-aware one.
func NewSQLServerInstaller(exec Executor) *SQLServerInstaller {
	return &SQLServerInstaller{exec: exec, verify: NewTDSVerifier(), stageRoot: defaultWinStageRoot}
}

// WithVerifier overrides the verifier (tests, or the hub's injected one).
func (in *SQLServerInstaller) WithVerifier(v Verifier) *SQLServerInstaller {
	in.verify = v
	return in
}

// WithTempDir overrides the staging root (tests).
func (in *SQLServerInstaller) WithTempDir(dir string) *SQLServerInstaller {
	in.stageRoot = dir
	return in
}

// sqlInstanceNamePattern is what SQL Server allows in an instance name
// (up to 16 characters: letters, digits, _, $, #, @).
var (
	sqlInstanceNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_$#@]{0,15}$`)
	sqlInstanceIDPattern   = regexp.MustCompile(`^MSSQL[0-9]{1,2}\.[A-Za-z][A-Za-z0-9_$#@]{0,15}$`)
	sqlServiceNamePattern  = regexp.MustCompile(`^(MSSQLSERVER|MSSQL\$[A-Za-z][A-Za-z0-9_$#@]{0,15})$`)
)

// sqlInstance is what the host says about the instance.
type sqlInstance struct {
	id      string // MSSQL16.MSSQLSERVER
	service string // MSSQLSERVER or MSSQL$NAME
	account string // service logon account
}

func (i sqlInstance) regPath() string {
	return `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\` + i.id + `\MSSQLServer\SuperSocketNetLib`
}

func validateSQLServerRequest(req SQLServerInstallRequest) (instance string, err error) {
	if len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return "", fmt.Errorf("sqlserver install: cert PEM and key PEM are required")
	}
	instance = req.Instance
	if instance == "" {
		instance = "MSSQLSERVER"
	}
	if !sqlInstanceNamePattern.MatchString(instance) {
		return "", fmt.Errorf("sqlserver install: instance name %q is not a valid SQL Server instance name", instance)
	}
	return instance, nil
}

// Install imports the certificate, grants the service account read on its key,
// points the instance at it, restarts the instance and verifies the served
// leaf. After the registry value changes, any failure restores the previous
// value and restarts the service again.
func (in *SQLServerInstaller) Install(ctx context.Context, req SQLServerInstallRequest) (InstallResult, error) {
	name, err := validateSQLServerRequest(req)
	if err != nil {
		return InstallResult{}, err
	}

	inst, err := in.resolveInstance(ctx, name)
	if err != nil {
		err = elevationHint("reading the SQL Server instance configuration", err)
		return InstallResult{Outcome: OutcomeConfigFailed, Detail: err.Error()}, fmt.Errorf("sqlserver install: %w", err)
	}
	prior, err := in.readCertificateValue(ctx, inst)
	if err != nil {
		return InstallResult{Outcome: OutcomeConfigFailed, Detail: err.Error()}, fmt.Errorf("sqlserver install: read current thumbprint: %w", err)
	}

	thumbprint, err := importPFXToMachineStore(ctx, in.exec, in.stageRoot, req.CertPEM, req.KeyPEM)
	if err != nil {
		err = elevationHint("writing to the LocalMachine certificate store", err)
		return InstallResult{Outcome: OutcomeCertImportFailed, Detail: err.Error()}, fmt.Errorf("sqlserver install: cert import failed: %w", err)
	}
	if err := grantKeyRead(ctx, in.exec, thumbprint, inst.account); err != nil {
		err = elevationHint("changing the private key ACL", err)
		return InstallResult{Installed: true, Outcome: OutcomeKeyACLFailed, Detail: err.Error()}, fmt.Errorf("sqlserver install: key access for %s failed: %w", inst.account, err)
	}

	if err := in.setCertificateValue(ctx, inst, strings.ToLower(thumbprint)); err != nil {
		err = elevationHint("writing the instance registry key", err)
		return InstallResult{Installed: true, Outcome: OutcomeConfigFailed, Detail: err.Error()}, fmt.Errorf("sqlserver install: set certificate: %w", err)
	}

	if err := in.restart(ctx, inst); err != nil {
		rolledBack, detail := in.rollback(ctx, inst, prior, thumbprint, err.Error())
		return InstallResult{Installed: true, RolledBack: rolledBack, RollbackFailed: !rolledBack, Outcome: OutcomeReloadFailed, Detail: detail},
			fmt.Errorf("sqlserver install: restart failed: %w", err)
	}

	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, detail, ok := verifyServed(ctx, in.verify, req.VerifyHostPort, req.ExpectedFingerprint)
		if !ok {
			rolledBack, rbDetail := in.rollback(ctx, inst, prior, thumbprint, detail)
			return InstallResult{Installed: true, Reloaded: true, RolledBack: rolledBack, RollbackFailed: !rolledBack,
					ServedFingerprint: served, Outcome: OutcomeVerifyFailed, Detail: rbDetail},
				fmt.Errorf("sqlserver install: verify failed (%s), rolled back=%t", detail, rolledBack)
		}
		return InstallResult{Installed: true, Reloaded: true, Verified: true, ServedFingerprint: served, Outcome: OutcomeInstalledVerified}, nil
	}
	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}

// resolveInstance maps the instance name to its registry instance id, service
// and logon account in one round trip. Everything it returns is reused as an
// argument later, so it is pinned to the shapes Windows produces first.
func (in *SQLServerInstaller) resolveInstance(ctx context.Context, name string) (sqlInstance, error) {
	out, err := winPowerShell(ctx, in.exec, nil,
		`$id = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $args[0]).($args[0]); `+
			`if ($args[0] -eq 'MSSQLSERVER') { $svc = 'MSSQLSERVER' } else { $svc = 'MSSQL$' + $args[0] }; `+
			`$s = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $svc + "'"); `+
			`if ($null -eq $s) { throw ('service ' + $svc + ' not found') }; `+
			`'ID=' + $id; 'SERVICE=' + $s.Name; 'ACCOUNT=' + $s.StartName`,
		name)
	if err != nil {
		return sqlInstance{}, fmt.Errorf("resolve instance %q: %w", name, err)
	}
	var inst sqlInstance
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ID="):
			inst.id = strings.TrimPrefix(line, "ID=")
		case strings.HasPrefix(line, "SERVICE="):
			inst.service = strings.TrimPrefix(line, "SERVICE=")
		case strings.HasPrefix(line, "ACCOUNT="):
			inst.account = strings.TrimPrefix(line, "ACCOUNT=")
		}
	}
	if !sqlInstanceIDPattern.MatchString(inst.id) {
		return sqlInstance{}, fmt.Errorf("instance %q reported an unexpected registry id", name)
	}
	if !sqlServiceNamePattern.MatchString(inst.service) {
		return sqlInstance{}, fmt.Errorf("instance %q reported an unexpected service name", name)
	}
	inst.account = mapSQLAccount(inst.account)
	if !winAccountPattern.MatchString(inst.account) && !winSIDRefPattern.MatchString(inst.account) {
		return sqlInstance{}, fmt.Errorf("instance %q runs as an account with an unexpected name shape", name)
	}
	return inst, nil
}

// mapSQLAccount turns the Win32_Service StartName spellings of the built-in
// accounts into SID references, since "LocalSystem" and "NT AUTHORITY\..." are
// either not translatable by NTAccount or localized. LocalSystem already has
// full key access, so granting it again is harmless.
func mapSQLAccount(start string) string {
	switch strings.ToLower(strings.TrimSpace(start)) {
	case "localsystem":
		return `*S-1-5-18`
	case `nt authority\networkservice`:
		return sidNetworkService
	case `nt authority\localservice`:
		return `*S-1-5-19`
	}
	return strings.TrimSpace(start)
}

func (in *SQLServerInstaller) readCertificateValue(ctx context.Context, inst sqlInstance) (string, error) {
	out, err := winPowerShell(ctx, in.exec, nil,
		`$v = (Get-ItemProperty -LiteralPath $args[0] -Name Certificate -ErrorAction SilentlyContinue).Certificate; if ($v) { $v }`,
		inst.regPath())
	if err != nil {
		return "", err
	}
	out = strings.TrimSpace(out)
	if out != "" && !thumbprintPattern.MatchString(out) {
		return "", fmt.Errorf("existing Certificate value is not a thumbprint")
	}
	return out, nil
}

// setCertificateValue writes the thumbprint; an empty value removes it, which
// is how a prior state of "no certificate configured" is restored.
func (in *SQLServerInstaller) setCertificateValue(ctx context.Context, inst sqlInstance, thumbprint string) error {
	if thumbprint == "" {
		_, err := winPowerShell(ctx, in.exec, nil,
			`Remove-ItemProperty -LiteralPath $args[0] -Name Certificate -ErrorAction SilentlyContinue`, inst.regPath())
		return err
	}
	if !thumbprintPattern.MatchString(thumbprint) {
		return fmt.Errorf("thumbprint is not 40 hex characters")
	}
	_, err := winPowerShell(ctx, in.exec, nil,
		`Set-ItemProperty -LiteralPath $args[0] -Name Certificate -Value $args[1] -Type String`, inst.regPath(), thumbprint)
	return err
}

// restart restarts the instance service. Restart-Service -Force also stops
// dependents (SQL Server Agent) but starts only the named service, so the
// dependents that were running are started again.
func (in *SQLServerInstaller) restart(ctx context.Context, inst sqlInstance) error {
	_, err := winPowerShell(ctx, in.exec, nil,
		`$deps = @(Get-Service -Name $args[0] -DependentServices | Where-Object { $_.Status -eq 'Running' }); `+
			`Restart-Service -Name $args[0] -Force; `+
			`$deps | ForEach-Object { Start-Service -Name $_.Name }`,
		inst.service)
	return err
}

// rollback restores the previous registry value and restarts the instance so
// it serves the previous certificate again. It reports whether that worked;
// a host left on the new value or with the service down must not be reported
// as rolled back.
func (in *SQLServerInstaller) rollback(ctx context.Context, inst sqlInstance, prior, newThumb, detail string) (bool, string) {
	if err := in.setCertificateValue(ctx, inst, prior); err != nil {
		return false, detail + "; ROLLBACK FAILED (the instance registry value could not be restored): " + err.Error()
	}
	if err := in.restart(ctx, inst); err != nil {
		return false, detail + "; ROLLBACK FAILED (the previous value is restored but the service did not restart): " + err.Error()
	}
	return true, detail + removeRolledBackCert(ctx, in.exec, "My", newThumb, prior)
}
