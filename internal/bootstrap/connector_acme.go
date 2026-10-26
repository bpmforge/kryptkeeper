// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/egress"
)

// W11-04: the ACME upstream connector — renewal executes AT the customer's
// original CA (Let's Encrypt or any RFC 8555 CA, EAB included) and the
// result lands in our inventory as a synced, managed certificate. Client is
// golang.org/x/crypto/acme; no hand-rolled JWS anywhere (spec decision 1)
// except the single ES256 newOrder signer in connector_acme_ari.go, which
// exists only to send the RFC 9773 "replaces" member the library lacks.
//
// Two solvers: http-01 on a configured listener (correct when the hub is
// reachable at the certificate's name, and what tests against the in-repo
// ACME server use) and dns-01 through a DNS provider API (W20-29;
// Cloudflare first), for hubs the public CA cannot reach.

type acmeConnectorConfig struct {
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	// HTTP01Listen is where the connector serves key authorizations during
	// an order, e.g. ":80" or "127.0.0.1:8123". Required for issuance.
	HTTP01Listen string `json:"http01_listen"`
	// HTTP01Mode is "hub" (default: the http01_listen listener) or "fleet"
	// (W27-23: the key authorization is placed on the host that serves the
	// name, over its managed target's SSH connection). See
	// connector_acme_http01_fleet.go.
	HTTP01Mode  string           `json:"http01_mode,omitempty"`
	HTTP01Hosts []acmeHTTP01Host `json:"http01_hosts,omitempty"`
	// Challenge is "http-01" (the default) or "dns-01".
	Challenge string `json:"challenge,omitempty"`
	// DNSProvider names the dns-01 provider: cloudflare, route53, azure, gcp,
	// rfc2136, delegated or plugin (see connector_acme_dns01*.go).
	DNSProvider string `json:"dns_provider,omitempty"`
	// DNSPluginID and DNSPluginCredential complete dns_provider "plugin"
	// (W38-08): the enabled dns01 plugin, and the outbound credential that
	// holds its credential fields. Both are names, not secrets.
	DNSPluginID         string `json:"dns_plugin_id,omitempty"`
	DNSPluginCredential string `json:"dns_plugin_credential,omitempty"`
	// DNSPropagation picks how the hub checks the TXT record is visible
	// before telling the CA to validate: auto (default), authoritative,
	// resolver, doh or none. See connector_acme_dnscheck.go.
	DNSPropagation string `json:"dns_propagation,omitempty"`
	// DNSResolver is the recursive resolver (host[:port]) for mode
	// resolver; empty uses the system resolver.
	DNSResolver string `json:"dns_resolver,omitempty"`
	// DNSDoHURL is the application/dns-json endpoint for mode doh
	// (default Cloudflare; https://dns.google/resolve also works).
	DNSDoHURL string `json:"dns_doh_url,omitempty"`
	// DNSPropagationTimeout (default 3m, max 10m) bounds the wait per
	// identifier; DNSPropagationDelay is mode none's fixed wait (default 30s).
	DNSPropagationTimeout string `json:"dns_propagation_timeout,omitempty"`
	DNSPropagationDelay   string `json:"dns_propagation_delay,omitempty"`
}

// acmeCredentialPayload is the documented plaintext of an ACME connector's
// credential_ref (all optional): a persisted account key and/or EAB.
type acmeCredentialPayload struct {
	AccountKeyPEM string `json:"account_key_pem,omitempty"`
	EABKid        string `json:"eab_kid,omitempty"`
	EABHmacB64    string `json:"eab_hmac_b64,omitempty"`
	// CloudflareAPIToken is a token scoped to DNS edit on the zone (dns-01).
	CloudflareAPIToken string `json:"cloudflare_api_token,omitempty"`
	// DNS is the provider-specific credential object (route53, azure, gcp, ...).
	DNS json.RawMessage `json:"dns,omitempty"`
}

type acmeIssuerConnector struct {
	id        string
	cfg       acmeConnectorConfig
	credRef   string
	creds     OutboundCredentialStore
	inventory CertificateProvider
	tenant    string

	// fleet http-01 seams (W27-23); nil targets = the env store on first use,
	// nil fleetDial = the real SSH dial.
	targets   ManagedTargetStore
	fleetDial sshDialFunc

	// dnsPluginHost overrides the process-wide plugin host (tests).
	dnsPluginHost *dnsPluginHost

	// dns-01 seams; nil means the real Cloudflare API and DNS.
	newDNS      func(acmeCredentialPayload) (dnsProvider, error)
	lookupNS    func(context.Context, string) ([]*net.NS, error)
	lookupTXT   txtLookup
	lookupDoH   func(ctx context.Context, endpoint, name string) ([]string, error)
	dnsInterval time.Duration

	// allowLoopbackForTest permits http and 127.0.0.0/8 upstreams in tests.
	allowLoopbackForTest bool
}

var _ connectors.IssuerConnector = (*acmeIssuerConnector)(nil)

// NewACMEIssuerConnector builds the upstream connector from its stored row.
func NewACMEIssuerConnector(rec ConnectorRecord, inventory CertificateProvider, creds OutboundCredentialStore) connectors.IssuerConnector {
	var cfg acmeConnectorConfig
	_ = json.Unmarshal([]byte(rec.ConfigJSON), &cfg) // malformed config zeroes out; connector then fails clearly on use
	return &acmeIssuerConnector{
		id: rec.ID, cfg: cfg, credRef: rec.CredentialRef,
		creds: creds, inventory: inventory, tenant: rec.Tenant,
	}
}

func (c *acmeIssuerConnector) ID() string     { return c.id }
func (c *acmeIssuerConnector) Type() string   { return "acme" }
func (c *acmeIssuerConnector) Origin() string { return "synced" }

func (c *acmeIssuerConnector) Health(ctx context.Context) connectors.Health {
	if c.cfg.DirectoryURL == "" {
		return connectors.Health{Status: "degraded", Detail: "config_json.directory_url is not set"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.DirectoryURL, nil)
	if err != nil {
		logging.Infof("acme connector %s: health: bad directory_url: %v", c.id, err)
		return connectors.Health{Status: "degraded", Detail: healthUnreachable}
	}
	resp, err := c.httpClient(5 * time.Second).Do(req)
	if err != nil {
		// The raw error stays in the server log: reflecting it would let a
		// caller with discovery.manage map internal hosts and ports.
		logging.Warnf("acme connector %s: health probe failed: %v", c.id, err)
		if errors.Is(err, egress.ErrBlockedDestination) {
			return connectors.Health{Status: "degraded", Detail: healthBlocked}
		}
		return connectors.Health{Status: "degraded", Detail: healthUnreachable}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		logging.Infof("acme connector %s: directory returned %d", c.id, resp.StatusCode)
		return connectors.Health{Status: "degraded", Detail: healthErrorStatus}
	}
	return connectors.Health{Status: "healthy"}
}

// Fixed Health.Detail vocabulary for network probes (OWASP-A10-002).
const (
	healthUnreachable = "unreachable"
	healthBlocked     = "blocked destination"
	healthErrorStatus = "directory returned an error status"
)

// httpClient is the only client used to reach the upstream CA. directory_url
// is operator-set, so it must be https and may not point at loopback or
// link-local/metadata space; private space is allowed (an internal CA is the
// common case) unless KRYPTKEEPER_EGRESS_DENY_PRIVATE=true. allowLoopbackForTest
// is the unexported test seam (the in-repo ACME server is plain http on
// 127.0.0.1), mirroring newDNS/lookupNS.
func (c *acmeIssuerConnector) httpClient(timeout time.Duration) *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:          true,
		AllowLoopback:         c.allowLoopbackForTest,
		RequireHTTPS:          !c.allowLoopbackForTest,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               timeout,
	}))
}

// credential resolves the connector's credential payload (all optional).
func (c *acmeIssuerConnector) credential(ctx context.Context) (acmeCredentialPayload, error) {
	var payload acmeCredentialPayload
	if c.credRef == "" || c.creds == nil {
		return payload, nil
	}
	plaintext, err := c.creds.Resolve(ctx, c.credRef)
	if err != nil {
		return payload, fmt.Errorf("acme connector credential %q: %w", c.credRef, err)
	}
	defer zeroize(plaintext)
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return payload, errors.New("acme connector credential payload is not the documented JSON shape (account_key_pem/eab_kid/eab_hmac_b64/cloudflare_api_token/dns)")
	}
	return payload, nil
}

// accountClient builds the acme.Client and ensures a registered account.
func (c *acmeIssuerConnector) accountClient(ctx context.Context, payload acmeCredentialPayload) (*acme.Client, error) {

	var key *ecdsa.PrivateKey
	if payload.AccountKeyPEM != "" {
		block, _ := pem.Decode([]byte(payload.AccountKeyPEM))
		if block == nil {
			return nil, errors.New("acme connector account_key_pem is not PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme connector account key: %w", err)
		}
		ec, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme connector account key must be ECDSA")
		}
		key = ec
	} else {
		// Ephemeral per-process account: fine against private CAs; store a
		// key in the credential for public CAs (spec decision 2).
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		key = generated
	}

	client := &acme.Client{Key: key, DirectoryURL: c.cfg.DirectoryURL, HTTPClient: c.httpClient(30 * time.Second), RetryBackoff: acmeRetryBackoff}
	acct := &acme.Account{}
	if c.cfg.Email != "" {
		acct.Contact = []string{"mailto:" + c.cfg.Email}
	}
	if payload.EABKid != "" {
		hmacKey, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload.EABHmacB64, "="))
		if err != nil {
			return nil, errors.New("acme connector eab_hmac_b64 is not base64url")
		}
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: payload.EABKid, Key: hmacKey}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		// Re-registering an existing account key is not an error.
		if !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return nil, fmt.Errorf("acme register: %w", err)
		}
	}
	return client, nil
}

// http01Responder publishes http-01 key authorizations for an order: the hub
// listener by default, target hosts in fleet mode (W27-23).
type http01Responder interface {
	put(ctx context.Context, identifier, path, keyAuth string) error
	// release runs right after WaitAuthorization, success or failure.
	release(ctx context.Context, identifier string) error
	// close is idempotent and removes anything still placed.
	close()
}

// http01Solver serves key authorizations for the order's duration.
type http01Solver struct {
	srv    *http.Server
	tokens map[string]string // path -> key authorization
}

func newHTTP01Solver(listen string) (*http01Solver, error) {
	if listen == "" {
		return nil, errors.New("acme connector http01_listen is not configured; http-01 cannot be solved (dns-01 needs a DNS-provider adapter — deferred, see spec W11-04)")
	}
	solver := &http01Solver{tokens: map[string]string{}}
	// A plain handler, not a ServeMux: this ephemeral listener exists only
	// for an order's duration on its own port and is NOT part of the hub API
	// surface (the openapi route validator scans mux registrations).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ka, ok := solver.tokens[r.URL.Path]; ok {
			_, _ = w.Write([]byte(ka))
			return
		}
		http.NotFound(w, r)
	})
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("acme http-01 listener on %s: %w", listen, err)
	}
	solver.srv = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = solver.srv.Serve(ln) }()
	return solver, nil
}

func (s *http01Solver) put(_ context.Context, _, path, keyAuth string) error {
	s.tokens[path] = keyAuth
	return nil
}
func (s *http01Solver) release(context.Context, string) error { return nil }
func (s *http01Solver) close()                                { _ = s.srv.Close() }

// issueOnce is one un-gated issuance; Issue (connector_acme_ratelimit.go) wraps it.
func (c *acmeIssuerConnector) issueOnce(ctx context.Context, req connectors.IssueRequest) (connectors.IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil {
		return connectors.IssueResult{}, errors.New("acme connector: request carries no CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return connectors.IssueResult{}, fmt.Errorf("acme connector: CSR unparseable: %w", err)
	}
	// Identifiers come from the CSR — the signed artifact — never from
	// caller-typed strings (spec decision 4).
	names := map[string]bool{}
	if csr.Subject.CommonName != "" {
		names[csr.Subject.CommonName] = true
	}
	for _, dns := range csr.DNSNames {
		names[dns] = true
	}
	if len(names) == 0 {
		return connectors.IssueResult{}, errors.New("acme connector: CSR carries no DNS identifiers")
	}
	ids := make([]acme.AuthzID, 0, len(names))
	for name := range names {
		ids = append(ids, acme.AuthzID{Type: "dns", Value: name})
	}

	payload, err := c.credential(ctx)
	if err != nil {
		return connectors.IssueResult{}, err
	}
	client, err := c.accountClient(ctx, payload)
	if err != nil {
		return connectors.IssueResult{}, err
	}
	challengeType := c.cfg.Challenge
	if challengeType == "" {
		challengeType = "http-01"
	}
	var solver http01Responder
	var dns dnsProvider
	var propagation dnsPropagation
	checkState := &dnsCheckState{}
	switch challengeType {
	case "http-01":
		if c.cfg.HTTP01Mode == "fleet" {
			if solver, err = newFleetHTTP01Solver(c); err != nil {
				return connectors.IssueResult{}, err
			}
		} else {
			hub, herr := newHTTP01Solver(c.cfg.HTTP01Listen)
			if herr != nil {
				return connectors.IssueResult{}, herr
			}
			solver = hub
		}
		defer solver.close()
	case "dns-01":
		if propagation, err = c.cfg.propagation(c.allowLoopbackForTest); err != nil {
			return connectors.IssueResult{}, err
		}
		if dns, err = c.dnsProvider(payload); err != nil {
			return connectors.IssueResult{}, err
		}
	default:
		return connectors.IssueResult{}, fmt.Errorf("acme connector challenge %q: use http-01 or dns-01", challengeType)
	}
	// TXT records come down even when the order fails, on a fresh context
	// so a cancelled request still cleans up.
	var cleanups []func(context.Context) error
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, cleanup := range cleanups {
			if err := cleanup(cctx); err != nil {
				logging.Infof("acme connector %s: dns-01 cleanup: %v", c.id, err)
			}
		}
	}()

	// Park behind any Retry-After a sibling order just drew: the throttle
	// cannot see a 429 the ACME client retries internally.
	if err := connectors.UpstreamGateFrom(ctx).Wait(ctx); err != nil {
		return connectors.IssueResult{}, fmt.Errorf("acme order: %w", err)
	}
	order, err := c.authorizeOrder(ctx, client, ids)
	if err != nil {
		return connectors.IssueResult{}, fmt.Errorf("acme order: %w", err)
	}
	logging.Infof("acme connector %s: order status=%s identifiers=%d", c.id, order.Status, len(ids))
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return connectors.IssueResult{}, fmt.Errorf("acme authorization: %w", err)
		}
		logging.Infof("acme connector %s: authorization status=%s identifier=%s", c.id, authz.Status, authz.Identifier.Value)
		if authz.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == challengeType {
				challenge = ch
				break
			}
		}
		if challenge == nil {
			return connectors.IssueResult{}, fmt.Errorf("acme: no %s challenge offered for %s", challengeType, authz.Identifier.Value)
		}
		if solver != nil {
			keyAuth, err := client.HTTP01ChallengeResponse(challenge.Token)
			if err != nil {
				return connectors.IssueResult{}, fmt.Errorf("acme key authorization: %w", err)
			}
			if err := solver.put(ctx, authz.Identifier.Value, client.HTTP01ChallengePath(challenge.Token), keyAuth); err != nil {
				return connectors.IssueResult{}, fmt.Errorf("acme http-01 for %s: %w", authz.Identifier.Value, err)
			}
		} else {
			cleanup, err := c.presentDNS01(ctx, client, dns, propagation, checkState, authz.Identifier.Value, challenge.Token)
			if cleanup != nil {
				cleanups = append(cleanups, cleanup)
			}
			if err != nil {
				return connectors.IssueResult{}, err
			}
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			return connectors.IssueResult{}, fmt.Errorf("acme challenge accept: %w", err)
		}
		logging.Infof("acme connector %s: challenge accepted type=%s identifier=%s", c.id, challengeType, authz.Identifier.Value)
		// WaitAuthorization surfaces the CA's problem detail on failure —
		// never swallowed (spec decision 6).
		validated, werr := client.WaitAuthorization(ctx, authz.URI)
		if solver != nil {
			if rerr := solver.release(ctx, authz.Identifier.Value); rerr != nil {
				logging.Infof("acme connector %s: http-01 cleanup for %s: %v", c.id, authz.Identifier.Value, rerr)
			}
		}
		if werr != nil {
			// The error text can carry the CA's problem detail (URL, token);
			// it goes to the caller, not the log.
			logging.Infof("acme connector %s: authorization status=%s identifier=%s", c.id, acme.StatusInvalid, authz.Identifier.Value)
			return connectors.IssueResult{}, fmt.Errorf("acme challenge validation for %s: %w", authz.Identifier.Value, werr)
		}
		logging.Infof("acme connector %s: authorization status=%s identifier=%s", c.id, validated.Status, authz.Identifier.Value)
	}
	finalOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return connectors.IssueResult{}, fmt.Errorf("acme order wait: %w", err)
	}
	logging.Infof("acme connector %s: order status=%s", c.id, finalOrder.Status)
	chainDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, block.Bytes, true)
	if err != nil {
		chainDER, err = recoverFinalizedOrder(ctx, client, order.URI, err)
	}
	if err != nil {
		return connectors.IssueResult{}, fmt.Errorf("acme finalize: %w", err)
	}
	if len(chainDER) == 0 {
		return connectors.IssueResult{}, errors.New("acme finalize returned an empty chain")
	}
	logging.Infof("acme connector %s: certificate issued identifiers=%d", c.id, len(ids))

	var chainPEM strings.Builder
	for _, der := range chainDER {
		chainPEM.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chainDER[0]}))

	// The upstream-issued leaf lands in OUR inventory as a synced, managed
	// certificate whose renewal path is this connector (spec decision 4).
	fingerprint := ""
	if c.inventory != nil {
		imported, err := c.inventory.ImportCertificate(ctx, CertificateImportRequest{
			CertificatePEM: leafPEM,
			TeamID:         req.TeamID,
		})
		switch {
		case err == nil:
			fingerprint = imported.CertificateItem.FingerprintSHA256
		case errors.Is(err, errCertificateConflict):
			// Already tracked (re-issue of an identical cert) — not an error.
			fingerprint = agentFingerprintOfPEM(leafPEM)
		default:
			return connectors.IssueResult{CertificatePEM: chainPEM.String()},
				fmt.Errorf("acme issued but inventory import failed: %w", err)
		}
		if fingerprint != "" {
			if _, err := c.inventory.UpdateEstate(ctx, fingerprint, EstateUpdate{
				Origin: "synced", ManagementState: "managed",
				RenewalMethod: "acme", RenewalConnectorID: c.id,
			}); err != nil {
				logging.Warnf("acme connector: estate stamp failed for %s: %v", fingerprint, err)
			}
		}
	}

	return connectors.IssueResult{
		FingerprintSHA256: fingerprint,
		CertificatePEM:    chainPEM.String(),
	}, nil
}

func (c *acmeIssuerConnector) dnsProvider(payload acmeCredentialPayload) (dnsProvider, error) {
	if c.newDNS != nil {
		return c.newDNS(payload)
	}
	if c.cfg.DNSProvider == "plugin" {
		return c.newPluginDNS()
	}
	return newDNSProviderFromConfig(c.cfg, payload)
}

// presentDNS01 publishes the TXT record for one identifier and waits until
// it is visible by the configured propagation method. A wildcard is
// validated at its base name (RFC 8555 §8.4).
func (c *acmeIssuerConnector) presentDNS01(ctx context.Context, client *acme.Client, dns dnsProvider, p dnsPropagation, st *dnsCheckState, identifier, token string) (func(context.Context) error, error) {
	value, err := client.DNS01ChallengeRecord(token)
	if err != nil {
		return nil, fmt.Errorf("acme dns-01 record: %w", err)
	}
	fqdn := "_acme-challenge." + strings.TrimPrefix(identifier, "*.")
	zone, cleanup, err := dns.Present(ctx, fqdn, value)
	if err != nil {
		return nil, fmt.Errorf("acme dns-01 for %s: %w", identifier, err)
	}
	interval := c.dnsInterval
	if interval == 0 {
		interval = 3 * time.Second
	}
	if err := c.waitPropagation(ctx, p, st, zone, fqdn, value, interval); err != nil {
		return cleanup, err
	}
	return cleanup, nil
}

// agentFingerprintOfPEM computes the SHA-256 fingerprint of a leaf PEM.
func agentFingerprintOfPEM(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(block.Bytes))
}

// recoverFinalizedOrder covers a CA (Pebble) whose finalize answer is
// "processing" with no Location header: x/crypto/acme takes the order URL from
// that header, so its internal WaitOrder("") fails with `Post ""` after the CA
// has already accepted the CSR. The order URL we kept from AuthorizeOrder is
// authoritative, so poll it and fetch the certificate only if the CA itself
// reports the order valid. CA rejections (*acme.Error, *acme.OrderError) and
// cancellation keep the original error; nothing here relaxes validation.
func recoverFinalizedOrder(ctx context.Context, client *acme.Client, orderURL string, cause error) ([][]byte, error) {
	var acmeErr *acme.Error
	var orderErr *acme.OrderError
	if orderURL == "" || ctx.Err() != nil || errors.As(cause, &acmeErr) || errors.As(cause, &orderErr) {
		return nil, cause
	}
	o, err := client.WaitOrder(ctx, orderURL)
	if err != nil || o.Status != acme.StatusValid {
		return nil, cause
	}
	chain, err := client.FetchCert(ctx, o.CertURL, true)
	if err != nil {
		return nil, fmt.Errorf("%w (order %s valid, certificate fetch: %v)", cause, acme.StatusValid, err)
	}
	return chain, nil
}
