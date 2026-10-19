// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/connectors"
)

// W26-27: ACME Renewal Information (RFC 9773) for the upstream connector.
// The scheduler asks the CA when to renew, renews at a random point inside
// the CA's suggested window, and tells the CA which certificate the new order
// replaces. golang.org/x/crypto/acme has neither ARI nor an order "replaces"
// member, so this file holds the one hand-rolled ES256 newOrder signer; the
// stock AuthorizeOrder path is used whenever no replaces certificate is in
// the context.

var (
	errARIUnsupported      = errors.New("acme ari: CA directory does not advertise renewalInfo")
	errACMEAlreadyReplaced = errors.New("acme: certificate already replaced")
	ariDefaultRetryAfter   = 6 * time.Hour
	ariMinRefresh          = time.Hour
	ariMaxResponseBytes    = int64(64 << 10)
	acmeErrAlreadyReplaced = "urn:ietf:params:acme:error:alreadyReplaced"
	acmeReplacesCtxKey     = acmeReplacesKey{}
)

type acmeReplacesKey struct{}

// ARIDecision is the scheduler's view of one certificate's ARI state.
// Known=false means "no usable ARI answer": fall back to threshold rules.
type ARIDecision struct {
	Known, Due bool
	At         time.Time
	Detail     string
}

type ariWindow struct {
	Start, End     time.Time
	ExplanationURL string
	RetryAfter     time.Duration
}

// ariCertID is the RFC 9773 certificate identifier:
// base64url(AKI keyIdentifier) "." base64url(serial), both unpadded.
func ariCertID(cert *x509.Certificate) (string, error) {
	if len(cert.AuthorityKeyId) == 0 {
		return "", errors.New("acme ari: certificate has no authority key identifier")
	}
	if cert.SerialNumber == nil {
		return "", errors.New("acme ari: certificate has no serial number")
	}
	return base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId) + "." +
		base64.RawURLEncoding.EncodeToString(cert.SerialNumber.Bytes()), nil
}

func parseLeafPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("acme ari: certificate is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// chooseRenewalTime picks a uniformly random instant in the part of the
// window that is still in the future (or now, when the window has closed).
func chooseRenewalTime(w ariWindow, now time.Time, randInt63n func(int64) int64) time.Time {
	if w.End.Before(now) {
		return now
	}
	start := w.Start
	if start.Before(now) {
		start = now
	}
	span := int64(w.End.Sub(start))
	if span <= 0 {
		return start
	}
	return start.Add(time.Duration(randInt63n(span + 1)))
}

// parseRetryAfter accepts delta-seconds (RFC 9773 servers) or an HTTP-date /
// RFC 3339 timestamp; anything unparseable yields the 6 h default.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if d, ok := ParseRetryAfterHeader(v, now); ok {
		return d
	}
	return ariDefaultRetryAfter
}

// ParseRetryAfterHeader parses a Retry-After value (delta-seconds, HTTP-date
// or RFC 3339). ok is false when v is empty, negative or unparseable; a date
// already in the past yields (0, true). Shared by ARI and the W26-28 backoff.
func ParseRetryAfterHeader(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	for _, layout := range []string{time.RFC3339, http.TimeFormat} {
		if t, err := time.Parse(layout, v); err == nil {
			if d := t.Sub(now); d > 0 {
				return d, true
			}
			return 0, true
		}
	}
	return 0, false
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	return min(max(d, lo), hi)
}

// fetchARI reads the directory's renewalInfo URL and the window for certPEM.
func (c *acmeIssuerConnector) fetchARI(ctx context.Context, certPEM string) (ariWindow, error) {
	cert, err := parseLeafPEM(certPEM)
	if err != nil {
		return ariWindow{}, err
	}
	id, err := ariCertID(cert)
	if err != nil {
		return ariWindow{}, err
	}
	hc := c.httpClient(15 * time.Second)

	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if _, _, err := ariGetJSON(ctx, hc, c.cfg.DirectoryURL, &dir); err != nil {
		return ariWindow{}, fmt.Errorf("acme ari directory: %w", err)
	}
	if dir.RenewalInfo == "" {
		return ariWindow{}, errARIUnsupported
	}

	var body struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	hdr, _, err := ariGetJSON(ctx, hc, strings.TrimRight(dir.RenewalInfo, "/")+"/"+id, &body)
	if err != nil {
		return ariWindow{}, fmt.Errorf("acme ari renewalInfo: %w", err)
	}
	if body.SuggestedWindow.Start.IsZero() || body.SuggestedWindow.End.IsZero() || body.SuggestedWindow.End.Before(body.SuggestedWindow.Start) {
		return ariWindow{}, errors.New("acme ari: response has no valid suggestedWindow")
	}
	return ariWindow{
		Start:          body.SuggestedWindow.Start,
		End:            body.SuggestedWindow.End,
		ExplanationURL: body.ExplanationURL,
		RetryAfter:     parseRetryAfter(hdr.Get("Retry-After"), time.Now()),
	}, nil
}

func ariGetJSON(ctx context.Context, hc *http.Client, url string, out any) (http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.Header, resp.StatusCode, fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, ariMaxResponseBytes)).Decode(out); err != nil {
		return resp.Header, resp.StatusCode, fmt.Errorf("decode: %w", err)
	}
	return resp.Header, resp.StatusCode, nil
}

// --- plan cache -----------------------------------------------------------

type ariPlan struct {
	chosen    time.Time
	window    ariWindow
	fetchedAt time.Time
}

// ariPlanCache is package-level because connector structs are rebuilt per
// renewal; it holds the chosen time across scheduler ticks.
type ariPlanCache struct {
	mu     sync.Mutex
	plans  map[string]ariPlan
	forced map[string]string // W26-29: connector|fp -> reason, see forceDue
	now    func() time.Time
	rand   func(int64) int64
}

func newARIPlanCache() *ariPlanCache {
	return &ariPlanCache{plans: map[string]ariPlan{}, forced: map[string]string{}, now: time.Now, rand: mrand.Int64N}
}

var ariPlans = newARIPlanCache()

func (p *ariPlanCache) get(key string) (ariPlan, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	plan, ok := p.plans[key]
	return plan, ok
}

func (p *ariPlanCache) fresh(plan ariPlan, now time.Time) bool {
	return now.Sub(plan.fetchedAt) < clampDuration(plan.window.RetryAfter, ariMinRefresh, ariDefaultRetryAfter)
}

// put stores a freshly fetched window. The previously chosen time is kept
// when the CA's window did not move, so repeated polls do not re-roll it.
func (p *ariPlanCache) put(key string, w ariWindow, now time.Time) ariPlan {
	p.mu.Lock()
	defer p.mu.Unlock()
	plan := ariPlan{window: w, fetchedAt: now}
	if old, ok := p.plans[key]; ok && old.window.Start.Equal(w.Start) && old.window.End.Equal(w.End) {
		plan.chosen = old.chosen
	} else {
		plan.chosen = chooseRenewalTime(w, now, p.rand)
	}
	// Bound memory: drop plans that have not been refreshed for a week.
	for k, v := range p.plans {
		if now.Sub(v.fetchedAt) > 7*24*time.Hour {
			delete(p.plans, k)
		}
	}
	p.plans[key] = plan
	return plan
}

// NewARIDueFunc builds the scheduler hook. Any error yields Known=false so an
// ARI outage never blocks renewal.
func NewARIDueFunc(registryFn func(context.Context) (*connectors.Registry, error), certs CertificateProvider) func(context.Context, CertificateItem, time.Time) ARIDecision {
	return func(ctx context.Context, item CertificateItem, now time.Time) ARIDecision {
		if reason, ok := ariPlans.forcedDue(item.RenewalConnectorID, item.FingerprintSHA256); ok && item.RenewalConnectorID != "" {
			return ARIDecision{Known: true, Due: true, At: now, Detail: "forced=" + reason}
		}
		if item.RenewalConnectorID == "" || registryFn == nil || certs == nil {
			return ARIDecision{}
		}
		reg, err := registryFn(ctx)
		if err != nil || reg == nil {
			return ARIDecision{}
		}
		conn, err := reg.Get(item.RenewalConnectorID)
		if err != nil || conn.Type() != "acme" {
			return ARIDecision{}
		}
		ac, ok := conn.(*acmeIssuerConnector)
		if !ok {
			return ARIDecision{}
		}
		key := item.RenewalConnectorID + "|" + item.FingerprintSHA256

		dl, derr := certs.DownloadCertificate(ctx, item.FingerprintSHA256, "pem", false)
		if derr != nil {
			return ARIDecision{}
		}
		certPEM := string(dl.Body)

		plan, cached := ariPlans.get(key)
		if !cached || !ariPlans.fresh(plan, now) {
			w, ferr := ac.fetchARI(ctx, certPEM)
			if ferr != nil {
				if !errors.Is(ferr, errARIUnsupported) {
					logging.Warnf("acme connector %s: ari fetch for %s failed, using threshold rules: %v", ac.id, item.FingerprintSHA256, ferr)
				}
				if cached {
					plan = ariPlan{chosen: plan.chosen, window: plan.window, fetchedAt: now}
				} else {
					return ARIDecision{}
				}
			} else {
				plan = ariPlans.put(key, w, now)
			}
		}
		leaf, lerr := parseLeafPEM(certPEM)
		if lerr != nil {
			return ARIDecision{}
		}
		id, ierr := ariCertID(leaf)
		if ierr != nil {
			return ARIDecision{}
		}
		return ARIDecision{
			Known: true,
			Due:   !now.Before(plan.chosen),
			At:    plan.chosen,
			Detail: fmt.Sprintf("ari_window=%s/%s chosen=%s replaces=%s",
				plan.window.Start.UTC().Format(time.RFC3339), plan.window.End.UTC().Format(time.RFC3339),
				plan.chosen.UTC().Format(time.RFC3339), id),
		}
	}
}

// --- replaces order -------------------------------------------------------

// WithACMEReplaces marks the context so the next ACME order created through
// the connector carries "replaces" for oldCertPEM. Empty PEM is a no-op.
func WithACMEReplaces(ctx context.Context, oldCertPEM string) context.Context {
	if strings.TrimSpace(oldCertPEM) == "" {
		return ctx
	}
	return context.WithValue(ctx, acmeReplacesCtxKey, oldCertPEM)
}

// authorizeOrder is client.AuthorizeOrder, plus "replaces" when the context
// carries a replaces certificate and the CA can take it. A missing AKI, an
// alreadyReplaced answer, or any failure to build the replaces order falls
// back to the stock order: renewal must never fail because of ARI.
func (c *acmeIssuerConnector) authorizeOrder(ctx context.Context, client *acme.Client, ids []acme.AuthzID) (*acme.Order, error) {
	oldPEM, _ := ctx.Value(acmeReplacesCtxKey).(string)
	if oldPEM == "" {
		return client.AuthorizeOrder(ctx, ids)
	}
	order, err := c.authorizeReplacesOrder(ctx, client, ids, oldPEM)
	switch {
	case err == nil:
		return order, nil
	case errors.Is(err, errACMEAlreadyReplaced):
		logging.Infof("acme connector %s: CA reports the certificate was already replaced; ordering without replaces", c.id)
	default:
		logging.Warnf("acme connector %s: replaces order failed (%v); ordering without replaces", c.id, err)
	}
	return client.AuthorizeOrder(ctx, ids)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (c *acmeIssuerConnector) authorizeReplacesOrder(ctx context.Context, client *acme.Client, ids []acme.AuthzID, oldPEM string) (*acme.Order, error) {
	old, err := parseLeafPEM(oldPEM)
	if err != nil {
		return nil, err
	}
	certID, err := ariCertID(old)
	if err != nil {
		return nil, err
	}
	key, ok := client.Key.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().BitSize != 256 {
		return nil, errors.New("acme replaces order needs an ECDSA P-256 account key")
	}
	dir, err := client.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("acme discover: %w", err)
	}
	if dir.NonceURL == "" || dir.OrderURL == "" {
		return nil, errors.New("acme directory lacks newNonce/newOrder")
	}
	kid := string(client.KID)
	if kid == "" {
		acct, err := client.GetReg(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("acme account lookup: %w", err)
		}
		kid = acct.URI
	}
	hc := c.httpClient(30 * time.Second)

	nreq, err := http.NewRequestWithContext(ctx, http.MethodHead, dir.NonceURL, nil)
	if err != nil {
		return nil, err
	}
	nresp, err := hc.Do(nreq)
	if err != nil {
		return nil, fmt.Errorf("acme nonce: %w", err)
	}
	_ = nresp.Body.Close()
	nonce := nresp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return nil, errors.New("acme nonce: CA returned no Replay-Nonce")
	}

	type identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	idents := make([]identifier, 0, len(ids))
	for _, id := range ids {
		idents = append(idents, identifier{Type: id.Type, Value: id.Value})
	}
	payload, _ := json.Marshal(struct {
		Identifiers []identifier `json:"identifiers"`
		Replaces    string       `json:"replaces"`
	}{idents, certID})
	protected, _ := json.Marshal(struct {
		Alg   string `json:"alg"`
		KID   string `json:"kid"`
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
	}{"ES256", kid, nonce, dir.OrderURL})
	signingInput := b64url(protected) + "." + b64url(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	body, _ := json.Marshal(map[string]string{
		"protected": b64url(protected), "payload": b64url(payload), "signature": b64url(sig),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dir.OrderURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme new-order: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, ariMaxResponseBytes))
	if resp.StatusCode != http.StatusCreated {
		var prob struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(raw, &prob) == nil && prob.Type == acmeErrAlreadyReplaced {
			return nil, errACMEAlreadyReplaced
		}
		return nil, fmt.Errorf("acme new-order with replaces: status %d %s", resp.StatusCode, prob.Type)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, errors.New("acme new-order: no Location header")
	}
	order, err := client.GetOrder(ctx, loc)
	if err != nil {
		return nil, err
	}
	if order.URI == "" {
		// Not every CA repeats Location on a POST-as-GET; WaitOrder needs it.
		order.URI = loc
	}
	return order, nil
}

// ConnectorRegistryFunc exposes the executor's per-renewal registry builder so
// the scheduler's ARI hook sees exactly the connectors renewal will use.
func (e *RenewalExecutor) ConnectorRegistryFunc() func(context.Context) (*connectors.Registry, error) {
	return e.connectorRegistry
}
