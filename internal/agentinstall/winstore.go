// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// Shared Windows machine-store plumbing for the SQL Server and RDP install
// modes (W35-02, W35-04). Both follow the IIS installer's shape -- everything
// goes through Executor so a Linux hub drives a Windows host over WinRM -- but
// neither has a binding command like netsh: the certificate is wired in by a
// registry value (SQL Server) or a CIM property (RDP), and the service
// account that will use it must be able to read the private key. Those two
// steps are the same for both, so they live here.
//
// Every value that reaches PowerShell does so as a positional argument
// (bound to $args by encodeInlinePowerShell and psQuote'd there), never
// spliced into the script text, so an operator-supplied or host-reported
// string cannot become code. Strings that came FROM the host are additionally
// pinned to the shape Windows produces before they are reused as arguments.

// defaultWinStageRoot is where the ACL-locked staging directory for the PFX
// is created; see createLockedStageDir for why it is not C:\Windows\Temp.
const defaultWinStageRoot = `C:\ProgramData\Kryptkeeper\win-stage`

// Outcomes shared by the two modes beyond the IIS ones in iis.go.
const (
	// OutcomeKeyACLFailed: the certificate is imported but the service
	// account could not be given read on its private key. Nothing live was
	// changed, so there is nothing to roll back.
	OutcomeKeyACLFailed = "key_acl_failed"
	// OutcomeConfigFailed: pointing the service at the new certificate
	// (registry value / CIM property) failed before any restart.
	OutcomeConfigFailed = "config_failed"
)

const (
	// Well-known SIDs, used instead of names so icacls and the SID lookup
	// behave the same on a localized Windows.
	sidNetworkService = `*S-1-5-20`
)

var (
	thumbprintPattern = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	winAccountPattern = regexp.MustCompile(`^[A-Za-z0-9 ._$@\\-]{1,128}$`)
	winSIDRefPattern  = regexp.MustCompile(`^\*S-1-[0-9-]{1,100}$`)
)

// winPowerShell runs a script with positional arguments through Executor.
// The try/catch mirrors WinRMExecutor.powershell: a thrown exception becomes a
// non-zero exit, and the innermost HResult is printed because the message is
// localized prose while 0x80070005 (access denied) is not -- elevationRequired
// keys on that code.
func winPowerShell(ctx context.Context, exec Executor, redact []string, script string, args ...string) (string, error) {
	wrapped := `try { ` + script + ` } catch { ` +
		`$e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }; ` +
		`"$_"; ('HRESULT 0x{0:X8}' -f $e.HResult); exit 1 }`
	cmdArgs := append([]string{"-NonInteractive", "-NoProfile", "-Command", wrapped}, args...)
	out, err := exec.Run(ctx, "powershell", cmdArgs...)
	text := strings.TrimSpace(string(out))
	if err != nil {
		// The one-time PFX password travels as an argument; a host that
		// echoes its command line into an error must not carry it into our
		// logs or audit rows.
		return redactSecrets(text, redact), redactErr(err, redact)
	}
	return text, nil
}

func redactSecrets(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

func redactErr(err error, secrets []string) error {
	msg := err.Error()
	red := redactSecrets(msg, secrets)
	if red == msg {
		return err
	}
	return fmt.Errorf("%s", red)
}

// importPFXToMachineStore builds a password-protected PFX on the hub, stages
// only that file in a fresh ACL-locked directory, imports it into
// Cert:\LocalMachine\My and returns the SHA-1 thumbprint (uppercase hex).
// The private key therefore never sits on the host unencrypted, and the
// random password exists only in this call.
func importPFXToMachineStore(ctx context.Context, exec Executor, stageRoot string, certPEM, keyPEM []byte) (string, error) {
	certDER, err := certDERFromPEM(certPEM)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	keyDER, _, err := normalizeKeyToPKCS8(keyPEM)
	if err != nil {
		return "", err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	thumbprint := thumbprintSHA1(certDER)

	token, err := randomToken(8)
	if err != nil {
		return "", fmt.Errorf("generate staging token: %w", err)
	}
	password, err := randomToken(16)
	if err != nil {
		return "", fmt.Errorf("generate pfx password: %w", err)
	}
	// LegacyDES: the encoding every Windows PowerShell 5.1 import accepts,
	// FIPS-mode hosts included (same choice as IISInstaller.importCert).
	pfxBytes, err := pkcs12.LegacyDES.Encode(privateKey, cert, nil, password)
	if err != nil {
		return "", fmt.Errorf("build pfx: %w", err)
	}

	stageDir := winJoin(stageRoot, "kk-win-stage-"+token)
	if err := createLockedStageDir(ctx, exec, stageDir); err != nil {
		return "", err
	}
	defer func() { _, _ = exec.Run(ctx, "cmd", "/C", "rmdir", "/S", "/Q", stageDir) }()

	pfxPath := winJoin(stageDir, "bundle.pfx")
	if err := exec.WriteFile(pfxPath, pfxBytes, 0o600); err != nil {
		return "", fmt.Errorf("stage pfx: %w", err)
	}

	got, err := winPowerShell(ctx, exec, []string{password},
		`$p = ConvertTo-SecureString -String $args[1] -AsPlainText -Force; `+
			`$c = Import-PfxCertificate -FilePath $args[0] -CertStoreLocation 'Cert:\LocalMachine\My' -Password $p; `+
			`$c.Thumbprint`,
		pfxPath, password)
	if err != nil {
		return "", fmt.Errorf("import pfx: %w", err)
	}
	if !strings.EqualFold(lastLine(got), thumbprint) {
		return "", fmt.Errorf("import pfx: host stored thumbprint %q, expected %s", lastLine(got), thumbprint)
	}
	return thumbprint, nil
}

// removeRolledBackCert deletes the certificate this install imported once the
// service has been put back on its previous one (W39 live R1: a failed verify
// used to leave the unused leaf, with its private key, in LocalMachine\My).
// It is a no-op when the new certificate IS the restored one (re-install of the
// same leaf), and it is only called after a successful restore so a binding
// can never be left pointing at a deleted certificate. Failure is reported in
// the returned detail, not as a rollback failure: the service is already back.
func removeRolledBackCert(ctx context.Context, exec Executor, store, newThumb string, priorThumbs ...string) string {
	if !thumbprintPattern.MatchString(newThumb) {
		return ""
	}
	for _, p := range priorThumbs {
		if strings.EqualFold(p, newThumb) {
			return ""
		}
	}
	if store == "" {
		store = "My"
	}
	if !iisStoreNamePattern.MatchString(store) {
		return ""
	}
	_, err := winPowerShell(ctx, exec, nil,
		`$p = Join-Path 'Cert:\LocalMachine' $args[0]; Remove-Item -LiteralPath (Join-Path $p $args[1]) -DeleteKey -ErrorAction Stop`,
		store, strings.ToUpper(newThumb))
	if err != nil {
		return "; the rolled-back certificate " + strings.ToUpper(newThumb) + " could not be removed from the machine store: " + err.Error()
	}
	return ""
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

// grantKeyRead gives account read on the private key of the machine-store
// certificate with the given thumbprint. account is a Windows account name or
// a "*S-1-..." SID reference. A certificate's key lives in a file under
// ProgramData\Microsoft\Crypto -- CNG keys in Keys, legacy CAPI keys in
// RSA\MachineKeys -- so the script finds the file from the key's unique name
// and edits its ACL with icacls (grant, never replace: the existing
// SYSTEM/Administrators entries stay).
func grantKeyRead(ctx context.Context, exec Executor, thumbprint, account string) error {
	if !thumbprintPattern.MatchString(thumbprint) {
		return fmt.Errorf("thumbprint is not 40 hex characters")
	}
	if !winAccountPattern.MatchString(account) && !winSIDRefPattern.MatchString(account) {
		return fmt.Errorf("service account %q has an unexpected shape", account)
	}
	script := `$c = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $args[0]); ` +
		`$k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c); ` +
		`if ($null -eq $k) { $k = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c) }; ` +
		`if ($null -eq $k) { throw 'the certificate has no usable private key' }; ` +
		`if ($k -is [System.Security.Cryptography.RSACng] -or $k -is [System.Security.Cryptography.ECDsaCng]) { $n = $k.Key.UniqueName } ` +
		`else { $n = $k.CspKeyContainerInfo.UniqueKeyContainerName }; ` +
		`$root = Join-Path $env:ProgramData 'Microsoft\Crypto'; ` +
		`$f = @((Join-Path $root 'Keys'), (Join-Path $root 'RSA\MachineKeys')) | ForEach-Object { Join-Path $_ $n } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1; ` +
		`if ($null -eq $f) { throw 'private key file not found in the machine key store' }; ` +
		`if ($args[1].StartsWith('*')) { $sid = $args[1].Substring(1) } ` +
		`else { $sid = (New-Object System.Security.Principal.NTAccount($args[1])).Translate([System.Security.Principal.SecurityIdentifier]).Value }; ` +
		`& icacls.exe $f /grant ('*' + $sid + ':(R)') | Out-Null; ` +
		`if ($LASTEXITCODE -ne 0) { throw ('icacls exit ' + $LASTEXITCODE) }`
	_, err := winPowerShell(ctx, exec, nil, script, thumbprint, account)
	return err
}

// createLockedStageDir creates dir and strips its inherited permissions so
// only SYSTEM and Administrators can read it, BEFORE any file is written into
// it. Shared with IISInstaller.createLockedStageDir.
func createLockedStageDir(ctx context.Context, exec Executor, dir string) error {
	if _, err := exec.Run(ctx, "cmd", "/C", "mkdir", dir); err != nil {
		return fmt.Errorf("create stage dir: %w", err)
	}
	if _, err := exec.Run(ctx, "icacls", dir, "/inheritance:r",
		"/grant:r", sidLocalSystem+":(OI)(CI)F", sidAdministrators+":(OI)(CI)F"); err != nil {
		if _, rmErr := exec.Run(ctx, "cmd", "/C", "rmdir", "/S", "/Q", dir); rmErr != nil {
			return fmt.Errorf("restrict stage dir acl: %w (and the unrestricted directory %s could not be removed: %v)", err, dir, rmErr)
		}
		return fmt.Errorf("restrict stage dir acl: %w", err)
	}
	return nil
}

// verifyServed compares the fingerprint served at hostPort with the expected
// one. detail is empty on a match.
func verifyServed(ctx context.Context, verify Verifier, hostPort, expected string) (served, detail string, ok bool) {
	served, err := verify(ctx, hostPort)
	if err != nil {
		return "", err.Error(), false
	}
	if normalizeFingerprint(served) != normalizeFingerprint(expected) {
		return served, "served fingerprint does not match renewed cert", false
	}
	return served, "", true
}
