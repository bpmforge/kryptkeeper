// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

// W27-07 (FR-P26): the Tomcat install target. Tomcat reads a Java keystore
// (PKCS#12 or JKS) at connector start; there is no graceful reload, so the
// flow is build-hub-side -> atomic place -> `catalina.sh configtest` ->
// `systemctl restart` -> verify, with the previous keystore restored on any
// failure. The keystore password is only ever a function argument and an
// encoder input: it is never placed in a command line, an error or a Detail.

const (
	// Keystore formats accepted in InstallRequest.KeystoreFormat.
	KeystoreFormatPKCS12       = "pkcs12"        // default; pkcs12.Modern2023 (OpenSSL 3 / Java 12+ readable)
	KeystoreFormatPKCS12Legacy = "pkcs12-legacy" // pkcs12.LegacyDES fallback for old JREs (Java 8 before 8u301)
	KeystoreFormatJKS          = "jks"

	defaultTomcatHome    = "/opt/tomcat"
	defaultTomcatService = "tomcat"
	defaultTomcatAlias   = "tomcat"

	// minKeystorePasswordLen mirrors keytool's own minimum.
	minKeystorePasswordLen = 6
)

// buildKeystore assembles one keystore holding the key and its certificate
// chain (leaf first) under alias. Errors never include the password.
func buildKeystore(format, alias, password string, certChainPEM, keyPEM []byte) ([]byte, error) {
	if format == "" {
		format = KeystoreFormatPKCS12
	}
	if alias == "" {
		alias = defaultTomcatAlias
	}
	if len(password) < minKeystorePasswordLen {
		return nil, fmt.Errorf("keystore password must be at least %d characters", minKeystorePasswordLen)
	}
	certs, err := parseCertChainPEM(certChainPEM)
	if err != nil {
		return nil, err
	}
	keyDER, _, err := normalizeKeyToPKCS8(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("keystore build: %w", err)
	}

	switch format {
	case KeystoreFormatPKCS12, KeystoreFormatPKCS12Legacy:
		key, err := x509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			return nil, fmt.Errorf("keystore build: parse key: %w", err)
		}
		enc := pkcs12.Modern2023
		if format == KeystoreFormatPKCS12Legacy {
			enc = pkcs12.LegacyDES
		}
		ks, err := enc.Encode(key, certs[0], certs[1:], password)
		if err != nil {
			return nil, errors.New("keystore build: pkcs12 encode failed")
		}
		return ks, nil
	case KeystoreFormatJKS:
		chain := make([]keystore.Certificate, 0, len(certs))
		for _, c := range certs {
			chain = append(chain, keystore.Certificate{Type: "X.509", Content: c.Raw})
		}
		pw := []byte(password)
		defer zeroBytes(pw)
		store := keystore.New(keystore.WithMinPasswordLen(minKeystorePasswordLen))
		if err := store.SetPrivateKeyEntry(alias, keystore.PrivateKeyEntry{
			CreationTime: certs[0].NotBefore, PrivateKey: keyDER, CertificateChain: chain,
		}, pw); err != nil {
			return nil, errors.New("keystore build: jks entry failed")
		}
		var buf bytes.Buffer
		if err := store.Store(&buf, pw); err != nil {
			return nil, errors.New("keystore build: jks store failed")
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported keystore format %q (want pkcs12, pkcs12-legacy or jks)", format)
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func parseCertChainPEM(chainPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := chainPEM
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
			return nil, fmt.Errorf("keystore build: parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("keystore build: no CERTIFICATE block in chain PEM")
	}
	return certs, nil
}

// checkKeystoreLeaf parses a freshly built keystore back and confirms its
// leaf is the first certificate of the renewed chain. `catalina.sh configtest`
// validates server.xml, not keystore contents, so this is the only
// pre-restart proof the file Tomcat will load is the right one.
func checkKeystoreLeaf(format, alias, password string, ks, certChainPEM []byte) error {
	want, err := parseCertChainPEM(certChainPEM)
	if err != nil {
		return err
	}
	var gotRaw []byte
	switch format {
	case KeystoreFormatJKS:
		pw := []byte(password)
		defer zeroBytes(pw)
		store := keystore.New()
		if err := store.Load(bytes.NewReader(ks), pw); err != nil {
			return errors.New("keystore verify: jks does not reload with the password")
		}
		chain, err := store.GetPrivateKeyEntryCertificateChain(alias)
		if err != nil || len(chain) == 0 {
			return errors.New("keystore verify: jks has no key entry for alias")
		}
		if _, err := store.GetPrivateKeyEntry(alias, pw); err != nil {
			return errors.New("keystore verify: jks key entry does not decrypt")
		}
		gotRaw = chain[0].Content
	default:
		key, leaf, _, err := pkcs12.DecodeChain(ks, password)
		if err != nil || key == nil {
			return errors.New("keystore verify: pkcs12 does not reload with the password")
		}
		gotRaw = leaf.Raw
	}
	if !bytes.Equal(gotRaw, want[0].Raw) {
		return errors.New("keystore verify: built keystore leaf does not match the renewed certificate")
	}
	return nil
}

// installTomcat is the Tomcat-specific install flow.
func (in *Installer) installTomcat(ctx context.Context, req InstallRequest) (InstallResult, error) {
	switch {
	case req.CertPath == "":
		return InstallResult{}, errors.New("tomcat install: keystore path (cert path) is required")
	case len(req.CertPEM) == 0:
		return InstallResult{}, errors.New("tomcat install: certificate PEM is required")
	case len(req.KeyPEM) == 0:
		return InstallResult{}, errors.New("tomcat install: key PEM is required (the keystore holds the private key)")
	case req.KeystorePassword == "":
		return InstallResult{}, errors.New("tomcat install: keystore_password is required (store it in the ssh_key credential)")
	}
	format := req.KeystoreFormat
	switch format {
	case "":
		format = KeystoreFormatPKCS12
	case KeystoreFormatPKCS12, KeystoreFormatPKCS12Legacy, KeystoreFormatJKS:
	default:
		return InstallResult{}, fmt.Errorf("tomcat install: keystore format %q not supported (pkcs12, pkcs12-legacy, jks)", format)
	}
	if req.ReloadMethod == "binary" {
		return InstallResult{}, fmt.Errorf("tomcat install: reload method %q not supported — Tomcat has no graceful reload; the service is restarted via systemctl", req.ReloadMethod)
	}
	alias := req.KeystoreAlias
	if alias == "" {
		alias = defaultTomcatAlias
	}
	home := strings.TrimRight(req.TomcatHome, "/")
	if home == "" {
		home = defaultTomcatHome
	}
	service := req.ServiceName
	if service == "" {
		service = defaultTomcatService
	}

	// Build and prove the keystore hub-side before touching the target.
	ks, err := buildKeystore(format, alias, req.KeystorePassword, req.CertPEM, req.KeyPEM)
	if err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, fmt.Errorf("tomcat install: %w", err)
	}
	if err := checkKeystoreLeaf(format, alias, req.KeystorePassword, ks, req.CertPEM); err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, fmt.Errorf("tomcat install: %w", err)
	}

	// 1. Snapshot the live keystore (0600: it holds the private key).
	backups := []fileBackup{in.snapshot(ctx, req.CertPath, 0o600)}
	if err := snapshotError(backups); err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, err
	}

	// 2. Atomic place.
	if err := in.place(req.CertPath, ks, 0o600, backups[0]); err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed}, fmt.Errorf("tomcat install: write keystore: %w", err)
	}

	// 3. Config test (server.xml; keystore contents were proven above).
	if out, err := in.exec.Run(ctx, home+"/bin/catalina.sh", "configtest"); err != nil {
		in.rollback(ctx, backups, req)
		return InstallResult{RolledBack: true, Outcome: OutcomeConfigTestFailed, Detail: string(out)},
			fmt.Errorf("tomcat install: config test failed, rolled back: %w", err)
	}

	// 4. Restart: the connector reads the keystore at start.
	restart := []string{"restart", service}
	if out, err := in.exec.Run(ctx, "systemctl", restart...); err != nil {
		in.rollback(ctx, backups, req)
		_, _ = in.exec.Run(ctx, "systemctl", restart...) // best-effort restart on the restored keystore; primary error already returned
		return InstallResult{Installed: true, RolledBack: true, Outcome: OutcomeReloadFailed, Detail: string(out)},
			fmt.Errorf("tomcat install: restart failed, rolled back: %w", err)
	}

	// 5. Verify, same contract as haproxy.
	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, err := in.verifyUntilMatchOrExhausted(ctx, req.VerifyHostPort, req.ExpectedFingerprint)
		if err != nil {
			in.rollback(ctx, backups, req)
			_, _ = in.exec.Run(ctx, "systemctl", restart...) // best-effort restart on the restored keystore; primary error already returned
			return InstallResult{Installed: true, Reloaded: true, RolledBack: true, Outcome: OutcomeVerifyFailed, Detail: err.Error()},
				fmt.Errorf("tomcat install: verify failed, rolled back: %w", err)
		}
		if normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			in.rollback(ctx, backups, req)
			_, _ = in.exec.Run(ctx, "systemctl", restart...) // best-effort restart on the restored keystore; primary error already returned
			return InstallResult{
					Installed: true, Reloaded: true, RolledBack: true,
					ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
					Detail: "served fingerprint does not match renewed cert",
				},
				fmt.Errorf("tomcat install: verify mismatch (served %s, want %s), rolled back",
					served, req.ExpectedFingerprint)
		}
		return InstallResult{
			Installed: true, Reloaded: true, Verified: true,
			ServedFingerprint: served, Outcome: OutcomeInstalledVerified,
		}, nil
	}

	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}
