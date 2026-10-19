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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"

	"kryptkeeper/internal/logging"
)

// AcmeRenewer uses the ACME protocol (RFC 8555) to renew certificates
// against the Kryptkeeper Hub's built-in ACME endpoint.
type AcmeRenewer struct {
	HubURL     string
	HTTPClient *http.Client

	// HTTP01Addr is where the temporary HTTP-01 listener binds when no web
	// root is configured. Empty means ":80" (IPv4 and IPv6 both), the only port a CA validates.
	HTTP01Addr string
}

const defaultHTTP01Addr = ":80"

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

	if webRoot == "" {
		// Fail before any ACME order exists: a blocked :80 otherwise surfaces
		// only after the order, as an opaque challenge failure.
		addr := r.http01Addr()
		logging.Infof("acme: http-01 challenge will listen on %s", addr)
		lns, err := listenHTTP01(addr)
		if err != nil {
			return nil, err
		}
		closeAll(lns)
	}

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

	cleanup, err := serveChallenge(ctx, ch.Token, keyAuth, webRoot, r.http01Addr())
	if err != nil {
		return fmt.Errorf("serve http-01 challenge: %w", err)
	}
	defer cleanup()

	if _, err := client.Accept(ctx, ch); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authURL); err != nil {
		return fmt.Errorf("wait authorization: %w", describeAuthzError(err))
	}
	return nil
}

// serveChallenge makes the ACME HTTP-01 token reachable at /.well-known/acme-challenge/<token>.
// Returns a cleanup function that removes the file or stops the listener.
func serveChallenge(ctx context.Context, token, keyAuth, webRoot, addr string) (func(), error) {
	// The token comes from the ACME server and becomes a file name and a URL
	// path; RFC 8555 §8.1 limits it to base64url, and enforcing that keeps a
	// hostile or compromised CA from writing outside the webroot.
	if !validACMEToken(token) {
		return nil, fmt.Errorf("acme challenge token is not base64url")
	}
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
	lns, err := listenHTTP01(addr)
	if err != nil {
		return nil, err
	}
	// The listener faces the open internet for the life of the challenge, so
	// bound how long a client may dribble headers or hold a connection.
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	for _, ln := range lns {
		go func() { _ = srv.Serve(ln) }()
	}
	return func() { _ = srv.Shutdown(ctx) }, nil
}

func (r *AcmeRenewer) http01Addr() string {
	if r.HTTP01Addr != "" {
		return r.HTTP01Addr
	}
	return defaultHTTP01Addr
}

// listenHTTP01 binds the HTTP-01 listener(s). The usual causes of failure are
// another web server (IIS, nginx) holding the port, a lack of privilege, or
// a previous renewal still running; the error names them instead of passing
// the bare OS message on.
//
// With no host in addr, IPv4 (0.0.0.0) and IPv6 ([::]) are bound separately.
// A single dual-stack "tcp" bind is not enough: on Windows an IPv4-only
// listener on 0.0.0.0:80 does not stop a [::]:80 bind from succeeding, so the
// busy port went undetected and the CA's IPv4 connection reached the other
// server. A family the host does not support is skipped.
func listenHTTP01(addr string) ([]net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "" {
		ln, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			return nil, http01ListenError(addr, lerr)
		}
		return []net.Listener{ln}, nil
	}
	var lns []net.Listener
	for _, f := range []struct{ network, addr string }{
		{"tcp4", net.JoinHostPort("0.0.0.0", port)},
		{"tcp6", net.JoinHostPort("::", port)},
	} {
		ln, lerr := net.Listen(f.network, f.addr)
		if lerr != nil {
			if isAddrFamilyUnsupported(lerr) {
				continue
			}
			closeAll(lns)
			return nil, http01ListenError(f.addr, lerr)
		}
		lns = append(lns, ln)
	}
	if len(lns) == 0 {
		return nil, http01ListenError(addr, errors.New("no usable IPv4 or IPv6 address family"))
	}
	return lns, nil
}

func http01ListenError(addr string, err error) error {
	return fmt.Errorf("cannot listen on %s for the ACME HTTP-01 challenge: port 80 in use or not permitted; see docs/ops/WINDOWS_AGENT.md: %w", addr, err)
}

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
	}
}

// isAddrFamilyUnsupported reports an IP family the host lacks (e.g. IPv6
// disabled). 10047 is Windows WSAEAFNOSUPPORT, which syscall.EAFNOSUPPORT
// does not match there.
func isAddrFamilyUnsupported(err error) bool {
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	var en syscall.Errno
	if errors.As(err, &en) && uintptr(en) == 10047 {
		return true
	}
	return strings.Contains(err.Error(), "address family not supported")
}

// describeAuthzError makes sure an authorization failure carries a reason.
// A CA that reports no challenge error would otherwise print an empty detail.
func describeAuthzError(err error) error {
	var ae *acme.AuthorizationError
	if errors.As(err, &ae) && len(ae.Errors) == 0 {
		return fmt.Errorf("%w (the CA gave no detail; check the challenge URL is reachable from the CA on port 80 and the Hub log)", err)
	}
	return err
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

// validACMEToken reports whether token is a non-empty base64url string
// (RFC 8555 §8.1: "MUST NOT contain any characters outside the base64url
// alphabet").
func validACMEToken(token string) bool {
	if token == "" || len(token) > 256 {
		return false
	}
	for _, c := range token {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
