// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/logging"
)

// tlsListenerSource is the ca.IssuedCertificateRecorder source label for the
// hub's own self-issued listener certificate -- W19-21: this cert bypassed
// bootstrap.CertificateProvider entirely (no inventory row, no lineage),
// the same seam W18-16/W18-18 closed for ACME/EST/SCEP/CMP.
const tlsListenerSource = "tls-listener"

// W19-14/UAT W19-05: the hub previously had no TLS listener at all, so every
// protocol client (and EST, which RFC 7030 mandates TLS for) spoke cleartext
// to a PKI. tlsSelfIssuedValidity/tlsSelfIssuedRenewBefore control the
// bootstrap listener certificate the hub can issue from its own default CA
// when the operator hasn't supplied one.
const (
	tlsSelfIssuedValidity    = 90 * 24 * time.Hour
	tlsSelfIssuedRenewBefore = 30 * 24 * time.Hour
)

// resolveTLSMode decides how the hub serves HTTP, in priority order:
//
//  1. KRYPTKEEPER_TLS_DISABLE=true -- explicit plain HTTP.
//  2. KRYPTKEEPER_TLS_CERT_FILE/KEY_FILE -- an operator-supplied pair.
//  3. KRYPTKEEPER_TLS_SELF_ISSUE=true -- issue+persist a listener cert from
//     the hub's own default CA.
//  4. Neither set: self-issue when a CA engine exists (this is a PKI
//     product; defaulting to cleartext when we could issue our own
//     certificate would repeat the exact gap UAT W19-05 found), otherwise
//     fall back to plain HTTP with a loud, returned warning rather than
//     refusing to start (many deployments run APP_CERTIFICATE_PROVIDER
//     other than "ca" and have no engine to issue from).
//
// A nil returned *tls.Config means plain HTTP.
func resolveTLSMode(needsCrypto bool, caEngine ca.Service, recorder ca.IssuedCertificateRecorder, defaultCAID, dataDir, bindAddr string) (*tls.Config, string, error) {
	disable := strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_TLS_DISABLE")), "true")
	certFile := strings.TrimSpace(os.Getenv("KRYPTKEEPER_TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("KRYPTKEEPER_TLS_KEY_FILE"))
	selfIssue := strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_TLS_SELF_ISSUE")), "true")

	switch {
	case disable:
		if certFile != "" || keyFile != "" || selfIssue {
			return nil, "", fmt.Errorf("KRYPTKEEPER_TLS_DISABLE=true conflicts with KRYPTKEEPER_TLS_CERT_FILE/KRYPTKEEPER_TLS_KEY_FILE/KRYPTKEEPER_TLS_SELF_ISSUE -- choose one")
		}
		return nil, "", nil

	case certFile != "" || keyFile != "":
		if certFile == "" || keyFile == "" {
			return nil, "", fmt.Errorf("KRYPTKEEPER_TLS_CERT_FILE and KRYPTKEEPER_TLS_KEY_FILE must both be set")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("loading TLS cert/key: %w", err)
		}
		return baseTLSConfig(cert), "", nil

	case selfIssue:
		if !needsCrypto || caEngine == nil {
			return nil, "", fmt.Errorf("KRYPTKEEPER_TLS_SELF_ISSUE=true requires APP_CERTIFICATE_PROVIDER=ca (no CA engine to issue the listener certificate from)")
		}
		if defaultCAID == "" {
			return nil, "", fmt.Errorf("KRYPTKEEPER_TLS_SELF_ISSUE=true needs a CA to issue the listener certificate, but none exists yet (first-run mode): create the root CA, then restart")
		}
		cert, err := selfIssuedTLSCertificate(caEngine, recorder, defaultCAID, dataDir, tlsSANs())
		if err != nil {
			return nil, "", fmt.Errorf("self-issuing TLS listener certificate: %w", err)
		}
		return baseTLSConfig(*cert), "", nil

	default:
		if needsCrypto && caEngine != nil && defaultCAID == "" {
			// First-run mode: no CA exists to issue the listener certificate
			// from. Never fall back to plain HTTP (the bootstrap token and the
			// first login cross this listener): serve an ephemeral in-memory
			// self-signed certificate until the operator creates the root and
			// restarts. Never refuse to start, that is the point of first-run
			// onboarding.
			cert, err := ephemeralSelfSignedTLSCertificate(tlsSANs(), time.Now())
			if err != nil {
				return nil, "", fmt.Errorf("first-run mode: generating ephemeral TLS listener certificate: %w", err)
			}
			// The ephemeral certificate is its own trust anchor: publish its
			// public half as ca.pem so the compose dashboard's nginx and the
			// hub's healthcheck can verify the listener (W33-02). The key stays
			// in memory. The CA-issued bundle replaces this on the next restart.
			tlsDir := filepath.Join(dataDir, "tls")
			if err := os.MkdirAll(tlsDir, 0o700); err != nil {
				return nil, "", fmt.Errorf("first-run mode: creating %s: %w", tlsDir, err)
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
			if err := writeTrustBundle(tlsDir, pemBytes); err != nil {
				return nil, "", fmt.Errorf("first-run mode: publishing ephemeral trust anchor: %w", err)
			}
			return baseTLSConfig(*cert), "first-run mode: no CA exists yet to self-issue the listener certificate -- serving an ephemeral self-signed certificate until a root CA is created and the hub is restarted (or set KRYPTKEEPER_TLS_CERT_FILE/KEY_FILE)", nil
		}
		if needsCrypto && caEngine != nil {
			cert, err := selfIssuedTLSCertificate(caEngine, recorder, defaultCAID, dataDir, tlsSANs())
			if err != nil {
				return nil, "", fmt.Errorf("self-issuing TLS listener certificate: %w", err)
			}
			return baseTLSConfig(*cert), "", nil
		}
		// A PKI product must not silently default to cleartext (UAT
		// W19-05) -- but with no CA engine to self-issue from, refusing
		// to start would break every non-"ca" certificate-provider
		// deployment. Say so loudly instead.
		return nil, "no KRYPTKEEPER_TLS_* configured and no CA engine available to self-issue a listener certificate -- serving plain HTTP. Set KRYPTKEEPER_TLS_CERT_FILE/KEY_FILE, KRYPTKEEPER_TLS_SELF_ISSUE=true (requires APP_CERTIFICATE_PROVIDER=ca), or KRYPTKEEPER_TLS_DISABLE=true to silence this warning", nil
	}
}

// baseTLSConfig applies the fixed policy every TLS mode shares: TLS 1.2
// floor (RFC 7030 EST and every other protocol client here tolerate 1.2+)
// and HTTP/2 advertised via ALPN -- net/http auto-configures h2 handling
// when NextProtos lists it and TLSConfig is set before ListenAndServeTLS.
// CipherSuites is left unset deliberately: crypto/tls's own default order
// already excludes weak suites, and hand-picking one here risks encoding a
// list that ages worse than the standard library's.
//
// Client certificates are requested only when
// KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true, for the WSTEP TLS renewal path
// non-Windows clients use (D-110). Windows never uses it, and the request
// costs: WinHTTP's revocation fetch fails against it and browsers show a
// certificate picker (W20-13). When on, certificates are requested but not
// verified in the handshake: WSTEP verifies a hub-issued one itself, and any
// Verify* mode would fail every other endpoint for a client offering an
// unrelated certificate. Nothing else treats PeerCertificates as verified.
func baseTLSConfig(cert tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	if requestClientCertFromEnv() {
		cfg.ClientAuth = tls.RequestClientCert
	}
	return cfg
}

func requestClientCertFromEnv() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT")), "true")
}

// tlsSANs resolves the SAN list for a self-issued listener certificate:
// KRYPTKEEPER_TLS_SANS (CSV) when set, else localhost+127.0.0.1 plus the
// host of KRYPTKEEPER_BASE_URL when that's configured (the address clients
// actually dial has to be a SAN, or their TLS verification fails even
// though the cert chains to a CA they trust).
func tlsSANs() []string {
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_TLS_SANS")); raw != "" {
		var out []string
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	sans := []string{"localhost", "127.0.0.1"}
	if base := strings.TrimSpace(os.Getenv("KRYPTKEEPER_BASE_URL")); base != "" {
		if u, err := url.Parse(base); err == nil && u.Hostname() != "" {
			sans = append(sans, u.Hostname())
		}
	}
	return sans
}

// selfIssuedTLSCertificate loads a previously self-issued listener
// certificate from KRYPTKEEPER_DATA_DIR/tls/ when it's still valid for more
// than tlsSelfIssuedRenewBefore and its SANs match what's wanted now,
// otherwise issues a fresh one from the hub's own default CA and persists
// it -- so a restart reuses the same cert/key instead of forcing every
// protocol client to re-pin on every boot.
func selfIssuedTLSCertificate(caEngine ca.Service, recorder ca.IssuedCertificateRecorder, defaultCAID, dataDir string, sans []string) (*tls.Certificate, error) {
	tlsDir := filepath.Join(dataDir, "tls")
	certPath := filepath.Join(tlsDir, "tls.crt")
	keyPath := filepath.Join(tlsDir, "tls.key")

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
			if time.Until(leaf.NotAfter) > tlsSelfIssuedRenewBefore && sameSANs(leaf, sans) {
				// W19-23: write/refresh ca.pem on every reuse too, not just on
				// (re)issue -- this function runs once per process start, so
				// this is the restart-time refresh: if the default CA was
				// rotated while the leaf listener cert is still within its
				// own validity window, the next restart's reuse path is what
				// picks up the new chain rather than serving a stale bundle
				// indefinitely. It does not refresh ca.pem for a CA rotated
				// while the hub keeps running -- that requires a restart.
				if err := writeCAChainBundle(caEngine, defaultCAID, tlsDir); err != nil {
					logging.Infof("tls: writing %s: %v", filepath.Join(tlsDir, "ca.pem"), err)
				}
				return &cert, nil
			}
		}
		// Expired/expiring soon, or the operator changed KRYPTKEEPER_TLS_SANS
		// -- fall through and re-issue.
	}

	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", tlsDir, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating listener key: %w", err)
	}
	dns, ips := splitTLSSANs(sans)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: primarySAN(sans)},
		DNSNames:    dns,
		IPAddresses: ips,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("building listener CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}

	issued, err := caEngine.IssueCertificate(defaultCAID, ca.IssuanceRequest{
		CSR:         csr,
		Validity:    tlsSelfIssuedValidity,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dns,
		IPAddresses: ips,
	})
	if err != nil {
		return nil, fmt.Errorf("issuing listener certificate from CA %q: %w", defaultCAID, err)
	}

	// W19-21: record into the hub's inventory the same way ACME/EST/SCEP/CMP
	// do -- this cert previously bypassed bootstrap.CertificateProvider
	// entirely, so it had no inventory row and no lineage even though it's a
	// real certificate this CA issued. Best-effort, logged only: the
	// listener already has its cert/key on disk above, so a recorder
	// failure must never block the hub from starting.
	if recorder != nil {
		if err := recorder.RecordIssuedCertificate(context.Background(), defaultCAID, issued.Certificate, issued.CertPEM, tlsListenerSource); err != nil {
			logging.Infof("tls: self-issued listener certificate not recorded: %v", err)
		}
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// 0600: this is the listener's own unencrypted leaf key, generated
	// fresh here -- CLAUDE.md: private key material never leaves its
	// boundary, and it must never be logged (it isn't, above or below).
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, issued.CertPEM, 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", certPath, err)
	}

	// W19-23: persist the issuing CA's chain alongside the leaf so every
	// in-stack client (the compose healthcheck binary, dashboard's nginx
	// proxy_ssl_trusted_certificate) can verify this listener cert without
	// ever touching key material -- only certificates are written here.
	if err := writeCAChainBundle(caEngine, defaultCAID, tlsDir); err != nil {
		return nil, fmt.Errorf("writing ca.pem: %w", err)
	}

	cert, err := tls.X509KeyPair(issued.CertPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	logging.Infof("[TLS] self-issued listener certificate from CA %s, valid until %s (SANs: %s)",
		defaultCAID, issued.Certificate.NotAfter.Format(time.RFC3339), strings.Join(sans, ","))
	return &cert, nil
}

// writeCAChainBundle writes tlsDir/ca.pem: the full certificate chain (leaf
// CA first, root last -- ca.GetCAChain's order) from the CA that issues the
// listener certificate up to its root, concatenated as PEM. It contains no
// key material (W19-23: previously nothing wrote a CA bundle here, so the
// compose healthcheck binary and dashboard's nginx had no way to trust a
// self-issued listener cert and the stack was pinned to
// KRYPTKEEPER_TLS_DISABLE=true instead).
//
// When KRYPTKEEPER_TLS_TRUST_EXPORT_DIR is set, the same bundle is also
// written there. tlsDir (KRYPTKEEPER_DATA_DIR/tls/) also holds tls.key --
// CLAUDE.md's private-key-boundary rule means that directory must never be
// mounted, even read-only, into another container. The compose stack
// instead gives the hub a second, dedicated volume mounted at this export
// path and shares *that* volume -- containing only ca.pem, never a key --
// with the dashboard and healthcheck's cross-container consumers.
func writeCAChainBundle(caEngine ca.Service, defaultCAID, tlsDir string) error {
	chain, err := caEngine.GetCAChain(defaultCAID)
	if err != nil {
		return fmt.Errorf("resolving CA chain for %q: %w", defaultCAID, err)
	}
	var buf []byte
	for _, c := range chain {
		buf = append(buf, c.CertPEM...)
	}
	return writeTrustBundle(tlsDir, buf)
}

// writeTrustBundle writes the public trust anchor bytes to tlsDir/ca.pem and,
// when KRYPTKEEPER_TLS_TRUST_EXPORT_DIR is set, to the export directory too.
func writeTrustBundle(tlsDir string, buf []byte) error {
	if err := os.WriteFile(filepath.Join(tlsDir, "ca.pem"), buf, 0o644); err != nil {
		return err
	}

	if exportDir := strings.TrimSpace(os.Getenv("KRYPTKEEPER_TLS_TRUST_EXPORT_DIR")); exportDir != "" {
		if err := os.MkdirAll(exportDir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", exportDir, err)
		}
		if err := os.WriteFile(filepath.Join(exportDir, "ca.pem"), buf, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", filepath.Join(exportDir, "ca.pem"), err)
		}
	}
	return nil
}

// sameSANs reports whether cert's SANs match the wanted set exactly --
// used to force re-issuance if the operator changes KRYPTKEEPER_TLS_SANS or
// KRYPTKEEPER_BASE_URL between restarts instead of silently keeping a
// listener cert that no longer covers the advertised host.
func sameSANs(cert *x509.Certificate, sans []string) bool {
	dns, ips := splitTLSSANs(sans)
	if len(cert.DNSNames) != len(dns) || len(cert.IPAddresses) != len(ips) {
		return false
	}
	dnsSet := make(map[string]bool, len(cert.DNSNames))
	for _, d := range cert.DNSNames {
		dnsSet[d] = true
	}
	for _, d := range dns {
		if !dnsSet[d] {
			return false
		}
	}
	ipSet := make(map[string]bool, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipSet[ip.String()] = true
	}
	for _, ip := range ips {
		if !ipSet[ip.String()] {
			return false
		}
	}
	return true
}

func splitTLSSANs(sans []string) (dns []string, ips []net.IP) {
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, s)
	}
	return dns, ips
}

func primarySAN(sans []string) string {
	if len(sans) > 0 {
		return sans[0]
	}
	return "localhost"
}

// ephemeralSelfSignedTLSCertificate mints an in-memory, self-signed P-256
// listener certificate for first-run mode (W33-32). It is never written to
// disk and is replaced by the CA-issued certificate on the first restart
// after a root CA exists.
func ephemeralSelfSignedTLSCertificate(sans []string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kryptkeeper first-run (ephemeral)"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, san)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
