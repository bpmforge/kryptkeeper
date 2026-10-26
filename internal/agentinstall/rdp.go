// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// W35-04: the RDP listener certificate (Windows, over WinRM).
//
// The Remote Desktop listener presents the certificate whose SHA-1 hash is the
// SSLCertificateSHA1Hash property of Win32_TSGeneralSetting for the RDP-Tcp
// terminal, in namespace root\cimv2\TerminalServices. The property is
// read/write and holds "the SHA1 hash in hexadecimal format of the SSL
// certificate for the target server to use"; SSLCertificateSHA1HashType
// reports its state (0 not valid, 1 default self-signed, 2 default group
// policy enforced, 3 custom). Source: Microsoft Learn, Win32_TSGeneralSetting
// class, https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting
//
// The listener runs as NETWORK SERVICE, so that account needs read on the
// private key. A group-policy-enforced certificate (type 2) overrides this
// property, so the install refuses up front rather than "succeeding" into a
// listener that keeps serving the policy's certificate.
//
// The listener is NOT restarted: restarting TermService would drop every
// interactive session, and the property is read when a connection negotiates.
// Verification (an X.224 negotiation followed by TLS, via the scanner's RDP
// probe) is what proves the new leaf is served; if it is not, the install is
// rolled back rather than assumed to need a restart.

const (
	// rdpWinStationKey is the registry location behind the WMI class
	// (the class's ClassContext is
	// HKLM\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations).
	rdpWinStationKey = `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`

	rdpHashTypeGroupPolicy = 2
)

// RDPInstallRequest describes one renewed certificate for the RDP listener.
type RDPInstallRequest struct {
	CertPEM []byte
	KeyPEM  []byte

	// VerifyHostPort is the RDP endpoint (host:3389); with ExpectedFingerprint
	// (SHA-256 of the leaf) it gates the install.
	VerifyHostPort      string
	ExpectedFingerprint string
}

// RDPInstaller installs a certificate for the RDP listener.
type RDPInstaller struct {
	exec      Executor
	verify    Verifier
	stageRoot string
}

// NewRDPInstaller returns an installer backed by exec with the X.224-aware
// verifier.
func NewRDPInstaller(exec Executor) *RDPInstaller {
	return &RDPInstaller{exec: exec, verify: NewRDPVerifier(), stageRoot: defaultWinStageRoot}
}

// WithVerifier overrides the verifier (tests, or the hub's injected one).
func (in *RDPInstaller) WithVerifier(v Verifier) *RDPInstaller {
	in.verify = v
	return in
}

// WithTempDir overrides the staging root (tests).
func (in *RDPInstaller) WithTempDir(dir string) *RDPInstaller {
	in.stageRoot = dir
	return in
}

// rdpPrior is the listener's certificate setting before the install.
type rdpPrior struct {
	hash     string // empty when the listener uses its default certificate
	hashType int
}

// Install imports the certificate, grants NETWORK SERVICE read on its key,
// sets the listener's hash and verifies the served leaf. A verify failure
// restores the previous hash (or, when there was none, removes the setting so
// the listener returns to its default certificate).
func (in *RDPInstaller) Install(ctx context.Context, req RDPInstallRequest) (InstallResult, error) {
	if len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return InstallResult{}, fmt.Errorf("rdp install: cert PEM and key PEM are required")
	}

	prior, err := in.readPrior(ctx)
	if err != nil {
		err = elevationHint("reading the Remote Desktop certificate setting", err)
		return InstallResult{Outcome: OutcomeConfigFailed, Detail: err.Error()}, fmt.Errorf("rdp install: %w", err)
	}
	if prior.hashType == rdpHashTypeGroupPolicy {
		err := fmt.Errorf("the RDP certificate is enforced by group policy (SSLCertificateSHA1HashType 2); change the policy's certificate template instead, a local setting would be ignored")
		return InstallResult{Outcome: OutcomeConfigFailed, Detail: err.Error()}, fmt.Errorf("rdp install: %w", err)
	}

	thumbprint, err := importPFXToMachineStore(ctx, in.exec, in.stageRoot, req.CertPEM, req.KeyPEM)
	if err != nil {
		err = elevationHint("writing to the LocalMachine certificate store", err)
		return InstallResult{Outcome: OutcomeCertImportFailed, Detail: err.Error()}, fmt.Errorf("rdp install: cert import failed: %w", err)
	}
	if err := grantKeyRead(ctx, in.exec, thumbprint, sidNetworkService); err != nil {
		err = elevationHint("changing the private key ACL", err)
		return InstallResult{Installed: true, Outcome: OutcomeKeyACLFailed, Detail: err.Error()}, fmt.Errorf("rdp install: key access for NETWORK SERVICE failed: %w", err)
	}

	if err := in.setHash(ctx, thumbprint); err != nil {
		err = elevationHint("setting SSLCertificateSHA1Hash", err)
		return InstallResult{Installed: true, Outcome: OutcomeConfigFailed, Detail: err.Error()}, fmt.Errorf("rdp install: set certificate: %w", err)
	}

	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, detail, ok := verifyServed(ctx, in.verify, req.VerifyHostPort, req.ExpectedFingerprint)
		if !ok {
			rolledBack, rbDetail := in.rollback(ctx, prior, thumbprint, detail)
			return InstallResult{Installed: true, Reloaded: true, RolledBack: rolledBack, RollbackFailed: !rolledBack,
					ServedFingerprint: served, Outcome: OutcomeVerifyFailed, Detail: rbDetail},
				fmt.Errorf("rdp install: verify failed (%s), rolled back=%t", detail, rolledBack)
		}
		return InstallResult{Installed: true, Reloaded: true, Verified: true, ServedFingerprint: served, Outcome: OutcomeInstalledVerified}, nil
	}
	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}

const rdpGetSetting = `$s = Get-CimInstance -Namespace 'root/cimv2/TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'"; ` +
	`if ($null -eq $s) { throw 'the RDP-Tcp terminal setting was not found (Remote Desktop Session Host WMI provider missing?)' }; `

func (in *RDPInstaller) readPrior(ctx context.Context) (rdpPrior, error) {
	out, err := winPowerShell(ctx, in.exec, nil,
		rdpGetSetting+`'HASH=' + $s.SSLCertificateSHA1Hash; 'TYPE=' + $s.SSLCertificateSHA1HashType`)
	if err != nil {
		return rdpPrior{}, err
	}
	var p rdpPrior
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "HASH="):
			p.hash = strings.TrimPrefix(line, "HASH=")
		case strings.HasPrefix(line, "TYPE="):
			n, err := strconv.Atoi(strings.TrimPrefix(line, "TYPE="))
			if err != nil {
				return rdpPrior{}, fmt.Errorf("the host reported an unreadable certificate hash type")
			}
			p.hashType = n
		}
	}
	if p.hash != "" && !thumbprintPattern.MatchString(p.hash) {
		return rdpPrior{}, fmt.Errorf("the host reported a certificate hash that is not 40 hex characters")
	}
	return p, nil
}

func (in *RDPInstaller) setHash(ctx context.Context, thumbprint string) error {
	if !thumbprintPattern.MatchString(thumbprint) {
		return fmt.Errorf("thumbprint is not 40 hex characters")
	}
	_, err := winPowerShell(ctx, in.exec, nil,
		rdpGetSetting+`Set-CimInstance -InputObject $s -Property @{ SSLCertificateSHA1Hash = $args[0] }`,
		strings.ToUpper(thumbprint))
	return err
}

// rollback puts the previous setting back. With no previous hash the listener
// was on its default certificate, which is restored by removing the value the
// property is stored in.
func (in *RDPInstaller) rollback(ctx context.Context, prior rdpPrior, newThumb, detail string) (bool, string) {
	var err error
	if prior.hash != "" {
		err = in.setHash(ctx, prior.hash)
	} else {
		_, err = winPowerShell(ctx, in.exec, nil,
			`Remove-ItemProperty -LiteralPath $args[0] -Name SSLCertificateSHA1Hash -ErrorAction SilentlyContinue`, rdpWinStationKey)
	}
	if err != nil {
		return false, detail + "; ROLLBACK FAILED (the listener may still serve the new certificate): " + err.Error()
	}
	return true, detail + removeRolledBackCert(ctx, in.exec, "My", newThumb, prior.hash)
}
