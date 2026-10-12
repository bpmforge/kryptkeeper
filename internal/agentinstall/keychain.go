// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

// macOS keeps machine identities and trust in the System keychain, which
// only Apple's `security` tool (or the Security framework) can write. Like
// iis.go, this installer drives the target host entirely through an
// Executor, so a Linux hub installs to a remote Mac over SSH and there is no
// darwin build tag: the code runs on the hub, not on the Mac.
//
// The renewed key travels as a PKCS#12 bundle with a random per-install
// password, staged in a directory mktemp creates 0700 before any key bytes
// are written, and removed on every exit path. `security import -x` marks
// the key non-extractable. Residual, stated as in iis.go: the bundle
// password rides argv (the Executor has no stdin-fed Run); it protects a
// file that exists for seconds in a 0700 directory, and it is redacted from
// every error this file returns because the SSH executor's errors quote the
// full command line.
//
// Trust: each self-signed CA in the chain is added to the admin trust domain
// with `security add-trusted-cert -d -r trustRoot`, then `security
// verify-cert` proves the leaf now chains to a trusted root. Recent macOS
// can refuse admin-domain trust changes without an interactive
// authorization; that surfaces as OutcomeTrustFailed with the identity
// already placed, never as a silent success.

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// OutcomeTrustFailed means the identity was placed in the keychain but its
// CA could not be trusted (or the leaf does not verify against it).
const OutcomeTrustFailed = "trust_failed"

const (
	defaultSystemKeychain = "/Library/Keychains/System.keychain"
	securityTool          = "/usr/bin/security"
	keychainStagePrefix   = "/tmp/kk-keychain."
)

var keychainStageDir = regexp.MustCompile(`^/tmp/kk-keychain\.[A-Za-z0-9]{8}$`)

// KeychainInstallRequest is a renewed identity for a macOS keychain.
type KeychainInstallRequest struct {
	// CertPEM is the leaf certificate followed by its issuing chain.
	CertPEM []byte
	KeyPEM  []byte
	// Keychain defaults to the System keychain.
	Keychain string

	// Optional verify-after-install, same contract as InstallRequest.
	VerifyHostPort      string
	ExpectedFingerprint string
}

// KeychainInstaller places an identity in a macOS keychain and trusts its
// CA, with every privileged step going through sudo on the target.
type KeychainInstaller struct {
	exec   Executor
	verify Verifier
}

// NewKeychainInstaller returns a KeychainInstaller backed by exec and the
// default TLS-dial verifier.
func NewKeychainInstaller(exec Executor) *KeychainInstaller {
	return &KeychainInstaller{exec: exec, verify: defaultVerifier}
}

// WithVerifier overrides the verifier (used in tests).
func (in *KeychainInstaller) WithVerifier(v Verifier) *KeychainInstaller {
	in.verify = v
	return in
}

// Install imports the identity, trusts the chain's roots, and proves both:
// the leaf's SHA-256 is in the keychain and `security verify-cert` accepts
// it. Nothing is rolled back on a trust failure: the identity is reported as
// installed and the trust gap as the outcome, so the operator sees exactly
// which half is missing.
func (in *KeychainInstaller) Install(ctx context.Context, req KeychainInstallRequest) (InstallResult, error) {
	keychain := req.Keychain
	if keychain == "" {
		keychain = defaultSystemKeychain
	}
	leaf, chain, key, err := parseIdentity(req.CertPEM, req.KeyPEM)
	if err != nil {
		return InstallResult{}, fmt.Errorf("keychain install: %w", err)
	}

	password, err := randomToken(16)
	if err != nil {
		return InstallResult{}, fmt.Errorf("keychain install: generate bundle password: %w", err)
	}
	bundle, err := pkcs12.LegacyDES.Encode(key, leaf, chain, password)
	if err != nil {
		return InstallResult{}, fmt.Errorf("keychain install: build PKCS#12: %w", err)
	}

	stage, err := in.createStageDir(ctx)
	if err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, fmt.Errorf("keychain install: %w", err)
	}
	defer func() { _, _ = in.exec.Run(context.WithoutCancel(ctx), "rm", "-rf", stage) }()

	bundlePath := stage + "/identity.p12"
	if err := in.exec.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, fmt.Errorf("keychain install: stage bundle: %w", err)
	}
	if _, err := in.exec.Run(ctx, "sudo", "-n", securityTool, "import", bundlePath,
		"-k", keychain, "-f", "pkcs12", "-P", password, "-x"); err != nil {
		err = redact(err, password)
		return InstallResult{Outcome: OutcomeCertImportFailed, Detail: err.Error()}, fmt.Errorf("keychain install: import: %w", err)
	}
	if err := in.confirmPresent(ctx, keychain, leaf); err != nil {
		return InstallResult{Outcome: OutcomeCertImportFailed, Detail: err.Error()}, fmt.Errorf("keychain install: %w", err)
	}

	if detail, err := in.trust(ctx, stage, keychain, leaf, chain); err != nil {
		return InstallResult{Installed: true, Outcome: OutcomeTrustFailed, Detail: detail},
			fmt.Errorf("keychain install: %w", err)
	}

	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, err := in.verify(ctx, req.VerifyHostPort)
		if err != nil {
			return InstallResult{Installed: true, Outcome: OutcomeVerifyFailed, Detail: err.Error()},
				fmt.Errorf("keychain install: verify failed: %w", err)
		}
		if normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			return InstallResult{Installed: true, ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
					Detail: "served fingerprint does not match the installed certificate"},
				fmt.Errorf("keychain install: verify mismatch (served %s, want %s)", served, req.ExpectedFingerprint)
		}
		return InstallResult{Installed: true, Verified: true, ServedFingerprint: served, Outcome: OutcomeInstalledVerified}, nil
	}
	return InstallResult{Installed: true, Outcome: OutcomeInstalled}, nil
}

// createStageDir makes a fresh private directory on the target. mktemp -d
// creates it 0700 and owned by the SSH user, so the bundle is never readable
// by anyone else, even for the moment before sudo reads it.
func (in *KeychainInstaller) createStageDir(ctx context.Context) (string, error) {
	out, err := in.exec.Run(ctx, "mktemp", "-d", keychainStagePrefix+"XXXXXXXX")
	if err != nil {
		return "", fmt.Errorf("create stage dir: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	// rm -rf runs on this path later: refuse anything mktemp did not make.
	if !keychainStageDir.MatchString(dir) {
		return "", fmt.Errorf("create stage dir: unexpected mktemp output %q", dir)
	}
	return dir, nil
}

// confirmPresent proves the import landed: the leaf's SHA-256 must appear in
// the keychain's certificate listing.
func (in *KeychainInstaller) confirmPresent(ctx context.Context, keychain string, leaf *x509.Certificate) error {
	out, err := in.exec.Run(ctx, "sudo", "-n", securityTool, "find-certificate", "-a", "-Z", keychain)
	if err != nil {
		return fmt.Errorf("list keychain certificates: %w", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "SHA-256 hash:"); ok && strings.EqualFold(strings.TrimSpace(rest), want) {
			return nil
		}
	}
	return fmt.Errorf("certificate %s not found in %s after import", want, keychain)
}

// trust adds each root in the chain to the admin trust domain, then checks
// the leaf verifies. The returned detail is meant for the operator.
func (in *KeychainInstaller) trust(ctx context.Context, stage, keychain string, leaf *x509.Certificate, chain []*x509.Certificate) (string, error) {
	roots := 0
	for i, c := range chain {
		if !isSelfSigned(c) {
			continue
		}
		roots++
		path := fmt.Sprintf("%s/root-%d.pem", stage, i)
		if err := in.exec.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o644); err != nil {
			return "staging CA certificate failed: " + err.Error(), err
		}
		if _, err := in.exec.Run(ctx, "sudo", "-n", securityTool, "add-trusted-cert", "-d", "-r", "trustRoot", "-k", keychain, path); err != nil {
			return "the identity is in the keychain, but trusting its root CA (" + c.Subject.CommonName + ") was refused: " + err.Error() +
				". macOS can require an interactive or MDM-authorized trust change; deploy the root with a configuration profile.", err
		}
	}
	if roots == 0 {
		return "the chain carries no root CA to trust", errors.New("no self-signed root in the supplied chain")
	}

	leafPath := stage + "/leaf.pem"
	if err := in.exec.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o644); err != nil {
		return "staging leaf certificate failed: " + err.Error(), err
	}
	if out, err := in.exec.Run(ctx, securityTool, "verify-cert", "-c", leafPath, "-k", keychain); err != nil {
		return "the root was added but the leaf does not verify: " + strings.TrimSpace(string(out)), fmt.Errorf("verify-cert: %w", err)
	}
	return "", nil
}

// parseIdentity splits CertPEM into leaf and chain, and checks the key is
// the leaf's: a mismatched pair would import as two unrelated items.
func parseIdentity(certPEM, keyPEM []byte) (leaf *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey, err error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse certificate: %w", err)
		}
		if leaf == nil {
			leaf = c
		} else {
			chain = append(chain, c)
		}
	}
	if leaf == nil {
		return nil, nil, nil, errors.New("no CERTIFICATE PEM block found")
	}
	keyDER, _, err := normalizeKeyToPKCS8(keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	pub, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, nil, nil, fmt.Errorf("unsupported key type %T", key)
	}
	if eq, ok := pub.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(leaf.PublicKey) {
		return nil, nil, nil, errors.New("private key does not match the leaf certificate")
	}
	return leaf, chain, key, nil
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

// redact removes secret from err's text; the SSH executor quotes the whole
// command line, password argument included, in its errors.
func redact(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "[redacted]"))
}
