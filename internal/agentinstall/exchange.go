// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

// Microsoft Exchange (on-premises) install mode.
//
// Exchange keeps no cert file and no HTTP.sys binding of its own to edit: the
// certificate has to be in the machine store and then ENABLED for the Exchange
// services (Enable-ExchangeCertificate), which rewrites the IIS binding and
// the transport receive connectors' TLS certificate together. So this installer
// reuses the IIS installer's PFX import (random one-time password, locked
// staging directory, certutil) and replaces only the "bind" step.
//
// The Exchange cmdlets are loaded with Add-PSSnapin
// Microsoft.Exchange.Management.PowerShell.SnapIn inside the WinRM-launched
// powershell.exe, i.e. on the Exchange server itself, as the WinRM account.
// The alternative -- a remote session to http://<server>/PowerShell/ with
// -ConfigurationName Microsoft.Exchange -Authentication Kerberos -- needs the
// account's credential again inside the script (a second hop), which would put
// a password into a script body, and Microsoft documents that
// Get-ExchangeCertificate does not fully support remote PowerShell
// (learn.microsoft.com/powershell/exchange/connect-to-exchange-servers-using-remote-powershell).
// RBAC still applies to the snap-in path: the account needs the Exchange
// Certificates management role (Organization Management or Server Management).
// Enable-ExchangeCertificate semantics (-Thumbprint, -Services IIS/SMTP/IMAP/
// POP, -Force suppresses the "replace the existing SMTP certificate" prompt,
// -DoNotRequireSsl) are from
// learn.microsoft.com/powershell/module/exchangepowershell/enable-exchangecertificate.
//
// The snap-in load, the on-server execution context and the prior-certificate
// heuristic below could not be exercised against a licensed Exchange host in
// this session; docs/ops/WINRM_ENABLEMENT.md lists what a live run must prove.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/logging"
)

// exchangeStore is fixed: Exchange only reads LocalMachine\My.
const exchangeStore = "My"

// exchangeServices is the set Enable-ExchangeCertificate is allowed to be
// driven with here, in the canonical order used on the command line.
// Federation and UM are deliberately absent: Microsoft says federation
// certificates are managed through the federation trust cmdlets, and UM
// services refuse a certificate unless TLS startup mode is set.
var exchangeServices = []string{"IIS", "SMTP", "IMAP", "POP"}

// DefaultExchangeServices is what a target gets when it configures none.
var DefaultExchangeServices = []string{"IIS", "SMTP"}

// exchangeSnapIn loads the Exchange cmdlets on the server itself.
const exchangeSnapIn = "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn\n"

// exchangePriorScript prints, per requested service, the thumbprint of the
// non-expired certificate currently enabled for it. $args[0] is the
// comma-separated service list (validated against exchangeServices).
// Exchange can leave the IIS flag on more than one certificate, so when
// several qualify the longest-lived wins; that is a heuristic for the
// rollback target, not a statement of what IIS serves.
const exchangePriorScript = `$ErrorActionPreference = 'Stop'
` + exchangeSnapIn + `foreach ($svc in ($args[0] -split ',')) {
  $c = Get-ExchangeCertificate | Where-Object { $_.NotAfter -gt (Get-Date) -and (($_.Services.ToString() -split ',\s*') -contains $svc) } | Sort-Object NotAfter -Descending | Select-Object -First 1
  if ($c) { Write-Output ('KKPRIOR:' + $svc + ':' + $c.Thumbprint) } else { Write-Output ('KKPRIOR:' + $svc + ':') }
}
`

// exchangeEnableScript enables $args[0] (thumbprint) for $args[1]
// (comma-separated services). -Force answers the SMTP "replace the existing
// certificate" prompt, which a WinRM shell could never answer. For IIS,
// Enable-ExchangeCertificate would otherwise also switch "Require SSL" on for
// the default web site; a certificate renewal must not change site settings,
// so -DoNotRequireSsl is passed.
const exchangeEnableScript = `$ErrorActionPreference = 'Stop'
` + exchangeSnapIn + `$svc = $args[1] -split ','
if ($svc -contains 'IIS') {
  Enable-ExchangeCertificate -Thumbprint $args[0] -Services $svc -Force -DoNotRequireSsl | Out-Null
} else {
  Enable-ExchangeCertificate -Thumbprint $args[0] -Services $svc -Force | Out-Null
}
`

var exchangeThumbprintPattern = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)

// ExchangeInstallRequest describes a renewed cert/key to import into an
// Exchange server and enable for its services.
type ExchangeInstallRequest struct {
	// Services to enable the certificate for; nil means IIS and SMTP.
	Services []string

	CertPEM []byte
	KeyPEM  []byte

	// VerifyHostPort is the HTTPS endpoint (OWA) probed for the new leaf.
	VerifyHostPort string
	// SMTPVerifyHostPorts are probed with STARTTLS when SMTP is among the
	// services (normally host:25 and host:587). A port that does not answer
	// is skipped (not every server listens on 587); a port that answers with
	// a different leaf fails the install, and at least one must answer.
	SMTPVerifyHostPorts []string
	// ExpectedFingerprint is the leaf's SHA-256; without it nothing is verified.
	ExpectedFingerprint string
}

// ExchangeInstaller imports a renewed certificate onto an Exchange server over
// an Executor and enables it, rolling back to the previously enabled
// certificate when verification fails. The old certificate is never deleted.
type ExchangeInstaller struct {
	stager     *IISInstaller // PFX build + locked staging + certutil import
	exec       Executor
	verify     Verifier
	smtpVerify Verifier
}

// NewExchangeInstaller returns an installer whose verification dials go
// through the hub egress policy.
func NewExchangeInstaller(exec Executor) *ExchangeInstaller {
	return &ExchangeInstaller{
		stager: NewIISInstaller(exec), exec: exec,
		verify: HubVerifier, smtpVerify: SMTPHubVerifier,
	}
}

// WithVerifiers overrides the HTTPS and SMTP STARTTLS verifiers (tests, and
// the hub's own test seam).
func (in *ExchangeInstaller) WithVerifiers(https, smtp Verifier) *ExchangeInstaller {
	if https != nil {
		in.verify = https
	}
	if smtp != nil {
		in.smtpVerify = smtp
	}
	return in
}

// WithTempDir overrides the staging root (tests).
func (in *ExchangeInstaller) WithTempDir(dir string) *ExchangeInstaller {
	in.stager.WithTempDir(dir)
	return in
}

// NormalizeExchangeServices validates and canonicalizes a service list. The
// values become a PowerShell argument, so only the fixed names pass.
func NormalizeExchangeServices(in []string) ([]string, error) {
	if len(in) == 0 {
		return append([]string(nil), DefaultExchangeServices...), nil
	}
	want := map[string]bool{}
	for _, s := range in {
		u := strings.ToUpper(strings.TrimSpace(s))
		ok := false
		for _, a := range exchangeServices {
			ok = ok || a == u
		}
		if !ok {
			return nil, fmt.Errorf("exchange install: service %q is not one of IIS, SMTP, IMAP, POP", s)
		}
		want[u] = true
	}
	var out []string
	for _, a := range exchangeServices {
		if want[a] {
			out = append(out, a)
		}
	}
	return out, nil
}

// Install imports the certificate, enables it for the services, reloads IIS
// when it is among them, and verifies the new leaf is served. Failures before
// the enable touch nothing live; failures after it restore the previously
// enabled certificate(s).
func (in *ExchangeInstaller) Install(ctx context.Context, req ExchangeInstallRequest) (InstallResult, error) {
	if len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return InstallResult{}, errors.New("exchange install: cert PEM and key PEM are required")
	}
	services, err := NormalizeExchangeServices(req.Services)
	if err != nil {
		return InstallResult{}, err
	}
	svcCSV := strings.Join(services, ",")

	prior, err := in.priorCertificates(ctx, svcCSV)
	if err != nil {
		return InstallResult{}, fmt.Errorf("exchange install: %w", exchangeHint("reading the enabled certificates", err))
	}

	thumbprint, err := in.stager.importCert(ctx, exchangeStore, req.CertPEM, req.KeyPEM)
	if err != nil {
		err = elevationHint("writing to the LocalMachine certificate store", err)
		return InstallResult{Outcome: OutcomeCertImportFailed, Detail: err.Error()},
			fmt.Errorf("exchange install: cert import failed: %w", err)
	}

	if err := in.enable(ctx, thumbprint, svcCSV); err != nil {
		err = exchangeHint("enabling the certificate", err)
		// The enable may have applied to some services before failing, so
		// restore whatever was captured.
		rolledBack, detail := in.rollback(ctx, prior, services, thumbprint, err.Error())
		return InstallResult{Installed: true, RolledBack: rolledBack, Outcome: OutcomeBindingFailed, Detail: detail},
			fmt.Errorf("exchange install: enable failed: %w", err)
	}

	if contains(services, "IIS") {
		if _, err := in.exec.Run(ctx, "iisreset", "/noforce"); err != nil {
			rolledBack, detail := in.rollback(ctx, prior, services, thumbprint, err.Error())
			return InstallResult{Installed: true, RolledBack: rolledBack, Outcome: OutcomeReloadFailed, Detail: detail},
				fmt.Errorf("exchange install: reload failed: %w", err)
		}
	}

	if req.ExpectedFingerprint == "" {
		return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
	}
	served, verr := in.verifyServed(ctx, req, services)
	if verr != nil {
		rolledBack, detail := in.rollback(ctx, prior, services, thumbprint, verr.Error())
		return InstallResult{Installed: true, Reloaded: true, RolledBack: rolledBack, ServedFingerprint: served, Outcome: OutcomeVerifyFailed, Detail: detail},
			fmt.Errorf("exchange install: verify failed: %w", verr)
	}
	return InstallResult{Installed: true, Reloaded: true, Verified: true, ServedFingerprint: served, Outcome: OutcomeInstalledVerified}, nil
}

// priorCertificates maps each requested service to the thumbprint enabled for
// it before this install ("" when none). Values read back from the host are
// reused as script arguments, so they are pinned to 40 hex digits first.
func (in *ExchangeInstaller) priorCertificates(ctx context.Context, svcCSV string) (map[string]string, error) {
	out, err := in.runPS(ctx, exchangePriorScript, svcCSV)
	if err != nil {
		return nil, err
	}
	prior := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "KKPRIOR:")
		if !ok {
			continue
		}
		svc, tp, _ := strings.Cut(rest, ":")
		if tp != "" && !exchangeThumbprintPattern.MatchString(tp) {
			return nil, fmt.Errorf("the host reported a malformed thumbprint for %s", svc)
		}
		prior[svc] = strings.ToUpper(tp)
	}
	return prior, nil
}

func (in *ExchangeInstaller) enable(ctx context.Context, thumbprint, svcCSV string) error {
	_, err := in.runPS(ctx, exchangeEnableScript, thumbprint, svcCSV)
	return err
}

func (in *ExchangeInstaller) runPS(ctx context.Context, script string, args ...string) ([]byte, error) {
	cmd := append([]string{"-NoProfile", "-NonInteractive", "-Command", script}, args...)
	return in.exec.Run(ctx, "powershell", cmd...)
}

// verifyServed checks every enabled service that has a probe and returns the
// served HTTPS fingerprint when one was checked.
func (in *ExchangeInstaller) verifyServed(ctx context.Context, req ExchangeInstallRequest, services []string) (string, error) {
	var served string
	if req.VerifyHostPort != "" && contains(services, "IIS") {
		fp, err := in.verify(ctx, req.VerifyHostPort)
		if err != nil {
			return "", fmt.Errorf("https %s: %w", req.VerifyHostPort, err)
		}
		served = fp
		if normalizeFingerprint(fp) != normalizeFingerprint(req.ExpectedFingerprint) {
			return fp, fmt.Errorf("https %s served %s, want %s", req.VerifyHostPort, fp, req.ExpectedFingerprint)
		}
	}
	if contains(services, "SMTP") && len(req.SMTPVerifyHostPorts) > 0 {
		answered := 0
		var unreachable []string
		for _, hp := range req.SMTPVerifyHostPorts {
			fp, err := in.smtpVerify(ctx, hp)
			if err != nil {
				if errors.Is(err, errSMTPUnreachable) {
					unreachable = append(unreachable, hp)
					continue
				}
				return served, fmt.Errorf("smtp starttls %s: %w", hp, err)
			}
			answered++
			if normalizeFingerprint(fp) != normalizeFingerprint(req.ExpectedFingerprint) {
				return served, fmt.Errorf("smtp starttls %s served %s, want %s", hp, fp, req.ExpectedFingerprint)
			}
		}
		if answered == 0 {
			return served, fmt.Errorf("no SMTP verify port answered (%s)", strings.Join(unreachable, ", "))
		}
	}
	return served, nil
}

// rollback re-enables the previously enabled certificate for each service it
// was captured for. RolledBack is only reported when something was restored
// and every restore succeeded; services with no prior certificate have nothing
// to go back to, and the new certificate stays enabled for them.
func (in *ExchangeInstaller) rollback(ctx context.Context, prior map[string]string, services []string, newThumb, detail string) (bool, string) {
	byThumb := map[string][]string{}
	var order []string
	for _, s := range services {
		tp := prior[s]
		if tp == "" {
			continue
		}
		if _, seen := byThumb[tp]; !seen {
			order = append(order, tp)
		}
		byThumb[tp] = append(byThumb[tp], s)
	}
	if len(order) == 0 {
		return false, detail + "; no previously enabled certificate was found, so nothing was restored"
	}
	for _, tp := range order {
		if err := in.enable(ctx, tp, strings.Join(byThumb[tp], ",")); err != nil {
			return false, detail + "; ROLLBACK FAILED (the services may serve neither certificate): " + err.Error()
		}
	}
	if contains(services, "IIS") {
		// Best effort: the enable already restored the binding; the reset only
		// makes IIS present it on new handshakes sooner.
		_, _ = in.exec.Run(ctx, "iisreset", "/noforce") //nolint:errcheck // outcome does not depend on it
	}
	// Only when every requested service had a prior certificate to go back to:
	// otherwise the new one is still enabled for some service and must stay.
	if len(prior) > 0 && allHavePrior(services, prior) {
		priors := make([]string, 0, len(prior))
		for _, p := range prior {
			priors = append(priors, p)
		}
		detail += removeRolledBackCert(ctx, in.exec, exchangeStore, newThumb, priors...)
	}
	return true, detail
}

// exchangeHint decorates the two failures an operator can fix: not elevated,
// and not holding an Exchange role that exposes the certificate cmdlets.
// Matching is on non-localized tokens (exception class names, Win32 codes)
// because the prose is translated; it only decorates the message.
func exchangeHint(op string, err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "PSSnapInException") || strings.Contains(s, "No snap-ins have been registered"):
		return fmt.Errorf("%w (the Exchange Management snap-in is not installed on this host: is it an Exchange server?)", err)
	case strings.Contains(s, "CommandNotFoundException"):
		return fmt.Errorf("%w (%s failed: the account has no Exchange role exposing the certificate cmdlets; add it to the Organization Management or Server Management role group)", err, op)
	}
	return elevationHint(op, err)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// errSMTPUnreachable marks a probe that could not connect or did not get an
// SMTP greeting, as opposed to one that connected and presented a certificate.
var errSMTPUnreachable = errors.New("smtp port did not answer")

// SMTPHubVerifier is the hub-side STARTTLS probe: connect, read the 220
// greeting, EHLO, STARTTLS, handshake, and return the leaf's SHA-256. It
// dials through the same egress policy as HubVerifier. It is separate from
// discovery's ScanSTARTTLS on purpose: that one belongs to the scanner's own
// dial policy and result model, and importing it would pull the discovery
// stack into the installer for a 30-line exchange.
func SMTPHubVerifier(ctx context.Context, hostPort string) (string, error) {
	return smtpVerifierWithPolicy(egress.PolicyFromEnv(egress.Policy{AllowPrivate: true}))(ctx, hostPort)
}

func smtpVerifierWithPolicy(p egress.Policy) Verifier {
	return func(ctx context.Context, hostPort string) (string, error) {
		d := &net.Dialer{Timeout: 5 * time.Second, Control: p.DialControl()}
		conn, err := d.DialContext(ctx, "tcp", hostPort)
		if err != nil {
			if errors.Is(err, egress.ErrBlockedDestination) {
				return "", errors.New("verify address is not permitted")
			}
			logging.Warnf("agentinstall: smtp verify dial %s failed: %v", hostPort, err)
			return "", errSMTPUnreachable
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck // best-effort bound; the dialer timeout still applies
		return smtpStartTLSFingerprint(conn, hostPort)
	}
}

// smtpStartTLSFingerprint runs the STARTTLS exchange over conn.
func smtpStartTLSFingerprint(conn net.Conn, hostPort string) (string, error) {
	tp := textproto.NewConn(conn)
	if _, _, err := tp.ReadResponse(220); err != nil {
		return "", errSMTPUnreachable
	}
	if err := tp.PrintfLine("EHLO kryptkeeper.verify"); err != nil {
		return "", errSMTPUnreachable
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		return "", fmt.Errorf("ehlo refused")
	}
	if err := tp.PrintfLine("STARTTLS"); err != nil {
		return "", errSMTPUnreachable
	}
	if _, _, err := tp.ReadResponse(220); err != nil {
		return "", errors.New("starttls refused")
	}
	host, _, _ := net.SplitHostPort(hostPort)
	return tlsLeafFingerprint(conn, host)
}

// tlsLeafFingerprint handshakes over an already-negotiated STARTTLS stream and
// returns the served leaf's SHA-256. The chain is not validated: the caller
// compares the fingerprint, which is the actual check (same as the verifier).
func tlsLeafFingerprint(conn net.Conn, serverName string) (string, error) {
	tc := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec // fingerprint compared by caller
	if err := tc.Handshake(); err != nil {
		return "", errors.New("tls handshake after starttls failed")
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certificate served after starttls")
	}
	return FingerprintSHA256(certs[0].Raw), nil
}

func allHavePrior(services []string, prior map[string]string) bool {
	for _, s := range services {
		if prior[s] == "" {
			return false
		}
	}
	return true
}
