// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// AcmeRenewer uses the ACME protocol (RFC 8555) to renew certificates
// against the Kryptkeeper Hub's built-in ACME endpoint.
type AcmeRenewer struct {
	HubURL     string
	HTTPClient *http.Client
}

// NewAcmeRenewer returns an AcmeRenewer targeting the given Hub. rootCAs is
// the same pool built by HubCACertPoolFromEnv and passed to New -- the ACME
// directory/order/challenge calls are Hub calls like any other and must
// trust the same CA the rest of the client does (W19-32); nil keeps system
// roots.
func NewAcmeRenewer(hubURL string, rootCAs *x509.CertPool) *AcmeRenewer {
	return &AcmeRenewer{
		HubURL: strings.TrimRight(hubURL, "/"),
		HTTPClient: &http.Client{
			Timeout:   60 * time.Second,
			Transport: hubTransport(rootCAs),
		},
	}
}

// RenewResult holds the renewed certificate PEM and private key PEM.
type RenewResult struct {
	CertPEM []byte
	KeyPEM  []byte
}

// Renew requests a new certificate for identifiers via ACME HTTP-01
// challenge. identifiers[0] becomes the CSR's CommonName; all of identifiers
// become the CSR's DNSNames/order identifiers. Callers must never pass a
// certificate's raw Subject RDN string here (e.g. "CN=localhost") -- it is
// not a DNS name and can never satisfy HTTP-01 (W19-13, UAT W19-04).
//
// If webRoot is non-empty, the challenge token file is written to
// webRoot/.well-known/acme-challenge/<token> (suitable when nginx/apache
// serves that directory). Otherwise a temporary HTTP listener is started on
// :80 for the duration of the challenge (requires CAP_NET_BIND_SERVICE or root).
func (r *AcmeRenewer) Renew(ctx context.Context, identifiers []string, webRoot string) (*RenewResult, error) {
	if len(identifiers) == 0 {
		return nil, fmt.Errorf("no DNS identifiers to renew")
	}
	acmeDir := r.HubURL + "/acme/directory"

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: acmeDir,
		HTTPClient:   r.HTTPClient,
	}

	acct := &acme.Account{Contact: []string{"mailto:agent@kryptkeeper.local"}}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		if !isACMEConflict(err) {
			return nil, fmt.Errorf("acme register: %w", err)
		}
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(identifiers...))
	if err != nil {
		return nil, fmt.Errorf("acme authorize order: %w", err)
	}

	for _, authURL := range order.AuthzURLs {
		if err := r.satisfyAuthz(ctx, client, authURL, webRoot); err != nil {
			return nil, err
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate cert key: %w", err)
	}
	csr, err := buildCSR(identifiers, certKey)
	if err != nil {
		return nil, fmt.Errorf("build csr: %w", err)
	}

	derChain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("acme finalize order: %w", err)
	}

	certPEM := encodeCertChain(derChain)
	keyPEM, err := encodeECKey(certKey)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	return &RenewResult{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func (r *AcmeRenewer) satisfyAuthz(ctx context.Context, client *acme.Client, authURL, webRoot string) error {
	authz, err := client.GetAuthorization(ctx, authURL)
	if err != nil {
		return fmt.Errorf("acme get authz %s: %w", authURL, err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}

	var ch *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			ch = c
			break
		}
	}
	if ch == nil {
		return fmt.Errorf("no http-01 challenge in authorization for %s", authURL)
	}

	keyAuth, err := client.HTTP01ChallengeResponse(ch.Token)
	if err != nil {
		return fmt.Errorf("compute key authorization: %w", err)
	}

	cleanup, err := serveChallenge(ctx, ch.Token, keyAuth, webRoot)
	if err != nil {
		return fmt.Errorf("serve http-01 challenge: %w", err)
	}
	defer cleanup()

	if _, err := client.Accept(ctx, ch); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authURL); err != nil {
		return fmt.Errorf("wait authorization: %w", err)
	}
	return nil
}

// serveChallenge makes the ACME HTTP-01 token reachable at /.well-known/acme-challenge/<token>.
// Returns a cleanup function that removes the file or stops the listener.
func serveChallenge(ctx context.Context, token, keyAuth, webRoot string) (func(), error) {
	if webRoot != "" {
		dir := filepath.Join(webRoot, ".well-known", "acme-challenge")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
		path := filepath.Join(dir, token)
		if err := os.WriteFile(path, []byte(keyAuth), 0o644); err != nil {
			return nil, fmt.Errorf("write challenge file: %w", err)
		}
		return func() { _ = os.Remove(path) }, nil
	}

	// Start a temporary HTTP listener on :80.
	mux := http.NewServeMux()
	challengePath := "/.well-known/acme-challenge/" + token
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, keyAuth) // no recovery path once the challenge response has started
	})
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return nil, fmt.Errorf("listen :80 for acme challenge: %w", err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return func() { _ = srv.Shutdown(ctx) }, nil
}

// isACMEConflict returns true when account already exists (registration is idempotent).
func isACMEConflict(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "already exists") ||
		strings.Contains(s, "accountDoesNotExist") ||
		strings.Contains(s, "conflict")
}

// buildCSR constructs a DER-encoded certificate signing request for
// identifiers. identifiers[0] is used as the CommonName; all of identifiers
// go into DNSNames.
func buildCSR(identifiers []string, key crypto.Signer) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: identifiers[0]},
		DNSNames: identifiers,
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

// encodeCertChain converts a DER certificate chain to concatenated PEM blocks.
func encodeCertChain(derChain [][]byte) []byte {
	var buf bytes.Buffer
	for _, der := range derChain {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return buf.Bytes()
}

// encodeECKey converts an ECDSA private key to PKCS#8 PEM.
func encodeECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
