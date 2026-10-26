// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/trustpush"
)

type trustHub struct {
	t       *testing.T
	mux     *http.ServeMux
	auth    *Authenticator
	agents  AgentStore
	store   *dbTrustBundleStore
	pending PendingActionStore
	audit   *recordingAuditProvider
	propose string // bearer tokens
	approve string
}

func newTrustHub(t *testing.T) *trustHub {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "off")
	auth := newReportsTestAuth(t)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &trustHub{t: t, auth: auth, agents: NewAgentStore(), audit: &recordingAuditProvider{},
		store: &dbTrustBundleStore{db: db, ph: sqlitePlaceholder}, pending: newTestPendingStore(t)}
	if err := h.store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.mux = http.NewServeMux()
	cfg := &ServerConfig{Mux: h.mux}
	registerTrustBundleHandlers(cfg, h.mux, h.mux, auth, h.agents, h.store, h.pending, nil, nil, h.audit)
	registerPendingActionHandlers(h.mux, auth, nil, h.pending, h.audit, cfg.actionExecutors)
	h.propose = mintAdminToken(t, auth, "proposer-one", "")
	h.approve = mintAdminToken(t, auth, "approver-one", "")
	return h
}

func (h *trustHub) do(tok, method, path string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, bearerReq(tok, method, path, raw))
	return rec
}

func (h *trustHub) agentDo(id, token, method, path string, body any) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func (h *trustHub) registerAgent(name string, typ AgentType) (string, string) {
	id, tok, err := h.agents.register(name, typ)
	if err != nil {
		h.t.Fatal(err)
	}
	return id, tok
}

func trustCertPEM(t *testing.T, cn string, isCA bool, notAfter time.Time) (*x509.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestTrustBundlePropose_Refusals(t *testing.T) {
	h := newTrustHub(t)
	id, _ := h.registerAgent("web-1", AgentTypeLinux)
	_, root := trustCertPEM(t, "Root", true, time.Now().Add(time.Hour))
	_, leaf := trustCertPEM(t, "leaf", false, time.Now().Add(time.Hour))
	_, expired := trustCertPEM(t, "Old", true, time.Now().Add(-time.Minute))
	keyDER, _ := x509.MarshalECPrivateKey(mustKey(t))
	keyBlock := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	sel := map[string]any{"agent_ids": []string{id}}

	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"non-CA certificate", map[string]any{"name": "n", "action": "add", "cert_pem": leaf, "selector": sel}, "not a CA"},
		{"expired root on add", map[string]any{"name": "n", "action": "add", "cert_pem": expired, "selector": sel}, "expired"},
		{"private key in the bundle", map[string]any{"name": "n", "action": "add", "cert_pem": root + keyBlock, "selector": sel}, "only CERTIFICATE"},
		{"unknown agent", map[string]any{"name": "n", "action": "add", "cert_pem": root, "selector": map[string]any{"agent_ids": []string{"ghost"}}}, "unknown agent"},
		{"empty selector", map[string]any{"name": "n", "action": "add", "cert_pem": root, "selector": map[string]any{}}, "selector is empty"},
		{"bad action", map[string]any{"name": "n", "action": "replace", "cert_pem": root, "selector": sel}, "add or remove"},
		{"missing name", map[string]any{"name": " ", "action": "add", "cert_pem": root, "selector": sel}, "name is required"},
	}
	for _, tc := range cases {
		rec := h.do(h.propose, http.MethodPost, "/api/v1/trust-bundles", tc.body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %s (want 400 containing %q)", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
		if strings.Contains(rec.Body.String(), hex.EncodeToString(keyDER[:12])) {
			t.Errorf("%s: response echoed key bytes", tc.name)
		}
	}
	if list, _ := h.pending.List(context.Background(), "pending"); len(list) != 0 {
		t.Fatalf("a refused proposal must queue nothing, got %d", len(list))
	}
	var failures int
	for _, e := range h.audit.entries {
		if e.Action == "trust_bundle.propose" && e.Outcome == AuditOutcomeFailure {
			failures++
		}
	}
	if failures != len(cases) {
		t.Fatalf("every refusal is audited: %d of %d", failures, len(cases))
	}
	// An expired root may be named for removal.
	rec := h.do(h.propose, http.MethodPost, "/api/v1/trust-bundles", map[string]any{"name": "drop old", "action": "remove", "cert_pem": expired, "selector": sel})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("removing an expired root: %d %s", rec.Code, rec.Body.String())
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTrustBundle_ApprovalGatesAndStatusReporting(t *testing.T) {
	h := newTrustHub(t)
	linuxID, linuxTok := h.registerAgent("web-1", AgentTypeLinux)
	winID, winTok := h.registerAgent("win-1", AgentTypeWindows)
	otherID, otherTok := h.registerAgent("mac-1", AgentTypeMac)
	root, rootPEM := trustCertPEM(t, "Corp Root 2", true, time.Now().Add(24*time.Hour))

	rec := h.do(h.propose, http.MethodPost, "/api/v1/trust-bundles", map[string]any{
		"name": "rollover", "action": "add", "cert_pem": rootPEM,
		"selector": map[string]any{"agent_ids": []string{winID}, "agent_types": []string{"linux"}},
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body.String())
	}
	var proposed struct {
		Data struct {
			ActionID string `json:"action_id"`
			Targets  int    `json:"targets"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &proposed)
	if proposed.Data.Targets != 2 {
		t.Fatalf("selector union should match 2 agents, got %d", proposed.Data.Targets)
	}
	if list, _ := h.store.List(context.Background(), 10); len(list) != 0 {
		t.Fatal("no bundle may exist before approval")
	}
	// Nothing is offered to the agent yet.
	if rec := h.agentDo(linuxID, linuxTok, http.MethodGet, "/api/v1/agent/trust-tasks", nil); !strings.Contains(rec.Body.String(), `"tasks":[]`) {
		t.Fatalf("pre-approval tasks: %s", rec.Body.String())
	}

	// Proposer cannot approve their own proposal.
	approvePath := "/api/v1/pending-actions/" + proposed.Data.ActionID + "/approve"
	if rec := h.do(h.propose, http.MethodPost, approvePath, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval must be refused, got %d %s", rec.Code, rec.Body.String())
	}
	if list, _ := h.store.List(context.Background(), 10); len(list) != 0 {
		t.Fatal("a refused self-approval must create nothing")
	}
	if rec := h.do(h.approve, http.MethodPost, approvePath, nil); rec.Code != http.StatusOK {
		t.Fatalf("approval: %d %s", rec.Code, rec.Body.String())
	}
	bundles, _ := h.store.List(context.Background(), 10)
	if len(bundles) != 1 || len(bundles[0].AgentIDs) != 2 || bundles[0].CreatedBy != "proposer-one" || bundles[0].ApprovedBy != "approver-one" {
		t.Fatalf("bundle after approval: %+v", bundles)
	}
	bid := bundles[0].ID
	sum := sha256.Sum256(root.Raw)
	if bundles[0].Certs[0].SHA256 != hex.EncodeToString(sum[:]) || !bundles[0].Certs[0].Root {
		t.Fatalf("cert summary: %+v", bundles[0].Certs[0])
	}

	// The targeted agent now sees it; the untargeted one does not; bad token 401.
	rec = h.agentDo(linuxID, linuxTok, http.MethodGet, "/api/v1/agent/trust-tasks", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), bid) || !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("targeted agent tasks: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.agentDo(otherID, otherTok, http.MethodGet, "/api/v1/agent/trust-tasks", nil); strings.Contains(rec.Body.String(), bid) {
		t.Fatal("an untargeted agent must not be offered the bundle")
	}
	if rec := h.agentDo(linuxID, "wrong", http.MethodGet, "/api/v1/agent/trust-tasks", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}

	// Status reporting: a refusal is recorded and re-offered, an applied is final.
	report := func(id, tok, outcome, detail string) *httptest.ResponseRecorder {
		return h.agentDo(id, tok, http.MethodPost, "/api/v1/agent/trust-result", map[string]string{"bundle_id": bid, "outcome": outcome, "detail": detail})
	}
	if rec := report(winID, winTok, trustpush.OutcomeRefused, "not opted in"); rec.Code != 200 {
		t.Fatalf("report refused: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.agentDo(winID, winTok, http.MethodGet, "/api/v1/agent/trust-tasks", nil); !strings.Contains(rec.Body.String(), bid) {
		t.Fatal("a refused bundle stays on offer")
	}
	if rec := report(linuxID, linuxTok, trustpush.OutcomeApplied, "added 1 certificate(s)"); rec.Code != 200 {
		t.Fatalf("report applied: %d", rec.Code)
	}
	if rec := h.agentDo(linuxID, linuxTok, http.MethodGet, "/api/v1/agent/trust-tasks", nil); strings.Contains(rec.Body.String(), bid) {
		t.Fatal("an applied bundle is not offered again")
	}
	if rec := report(otherID, otherTok, trustpush.OutcomeApplied, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("an agent outside the target list must be refused: %d", rec.Code)
	}
	if rec := report(linuxID, linuxTok, "installed", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown outcome: %d", rec.Code)
	}

	rec = h.do(h.propose, http.MethodGet, "/api/v1/trust-bundles/"+bid, nil)
	var detail struct {
		Data struct {
			Bundle trustBundleSummary `json:"bundle"`
			Hosts  []trustHostStatus  `json:"hosts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil || rec.Code != 200 {
		t.Fatalf("detail: %d %v %s", rec.Code, err, rec.Body.String())
	}
	if b := detail.Data.Bundle; b.Targets != 2 || b.Applied != 1 || b.Refused != 1 || b.Pending != 0 {
		t.Fatalf("tally: %+v", b)
	}
	byName := map[string]string{}
	for _, hs := range detail.Data.Hosts {
		byName[hs.AgentName] = hs.Outcome
	}
	if byName["web-1"] != "applied" || byName["win-1"] != "refused_not_opted_in" {
		t.Fatalf("per-host status: %v", byName)
	}
	if rec := h.do(h.propose, http.MethodGet, "/api/v1/trust-bundles", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), bid) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(h.propose, http.MethodGet, "/api/v1/trust-bundles/tb-nope", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown bundle: %d", rec.Code)
	}

	var sawPropose, sawCreate, sawResult bool
	for _, e := range h.audit.entries {
		switch {
		case e.Action == "trust_bundle.propose" && e.Outcome == AuditOutcomePendingApproval:
			sawPropose = true
		case e.Action == "trust_bundle.create" && strings.Contains(e.ChangeSummary, "approved_by=approver-one") && strings.Contains(e.ChangeSummary, "proposed_by=proposer-one"):
			sawCreate = true
		case e.Action == "agent.trust_result" && e.ResourceID == bid:
			sawResult = true
		}
	}
	if !sawPropose || !sawCreate || !sawResult {
		t.Fatalf("audit trail incomplete: propose=%v create=%v result=%v", sawPropose, sawCreate, sawResult)
	}
}

func TestTrustBundle_ExecutorRevalidatesAndDropsGoneAgents(t *testing.T) {
	h := newTrustHub(t)
	id, _ := h.registerAgent("web-1", AgentTypeLinux)
	exec := newTrustBundleExecutor(h.store, h.agents, h.audit)
	_, leaf := trustCertPEM(t, "leaf", false, time.Now().Add(time.Hour))
	params, _ := json.Marshal(trustBundleParams{Name: "x", Action: "add", CertPEM: leaf, AgentIDs: []string{id}})
	if _, err := exec(context.Background(), PendingAction{ID: "a1", Params: params, ProposedBy: "p"}, AuthPrincipal{ID: "q"}); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("a row written outside the handler must still be refused: %v", err)
	}
	_, root := trustCertPEM(t, "Root", true, time.Now().Add(time.Hour))
	params, _ = json.Marshal(trustBundleParams{Name: "x", Action: "add", CertPEM: root, AgentIDs: []string{"gone"}})
	if _, err := exec(context.Background(), PendingAction{ID: "a2", Params: params, ProposedBy: "p"}, AuthPrincipal{ID: "q"}); err == nil {
		t.Fatal("a bundle with no surviving target must not be created")
	}
}

type fakeCAs struct {
	CAProvider
	items []CAListItem
}

func (f fakeCAs) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{Items: f.items, Total: len(f.items)}, nil
}

type fakeCerts struct {
	CertificateProvider
	items []CertificateItem
}

func (f fakeCerts) ListCertificates(_ context.Context, q CertificateListQuery) (CertificateListResult, error) {
	if q.Offset > 0 {
		return CertificateListResult{Total: len(f.items)}, nil
	}
	return CertificateListResult{Items: f.items, Total: len(f.items)}, nil
}

func TestRemovalWarnsWhenTheRootIssuedLiveCertificates(t *testing.T) {
	root, rootPEM := trustCertPEM(t, "Hub Root", true, time.Now().Add(time.Hour))
	cas, err := trustpush.ParseCAs(rootPEM, time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(root.Raw)
	now := time.Now()
	revoked := now.Format(time.RFC3339)
	certs := fakeCerts{items: []CertificateItem{
		{FingerprintSHA256: "live-1", CAID: "ca-1", CommonName: "a.example", ValidUntil: now.Add(time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "revoked", CAID: "ca-1", CommonName: "b.example", ValidUntil: now.Add(time.Hour).Format(time.RFC3339), RevokedAt: &revoked},
		{FingerprintSHA256: "expired", CAID: "ca-1", CommonName: "c.example", ValidUntil: now.Add(-time.Hour).Format(time.RFC3339)},
	}}
	cap := fakeCAs{items: []CAListItem{{ID: "ca-1", Name: "Hub Root", CertificateFingerprintSHA256: hex.EncodeToString(sum[:])}}}
	w := removalWarnings(context.Background(), cas, certs, cap, now)
	if len(w) != 1 || !strings.Contains(w[0], "distrusts 1 live managed certificate") {
		t.Fatalf("warnings = %v", w)
	}
	// A root the hub never issued from raises nothing.
	_, other := trustCertPEM(t, "Elsewhere", true, time.Now().Add(time.Hour))
	otherCAs, _ := trustpush.ParseCAs(other, time.Now(), true)
	if w := removalWarnings(context.Background(), otherCAs, certs, cap, now); len(w) != 0 {
		t.Fatalf("unrelated root warned: %v", w)
	}
}

func TestTrustBundlePropose_RemoveCarriesTheWarningToTheApprover(t *testing.T) {
	h := newTrustHub(t)
	id, _ := h.registerAgent("web-1", AgentTypeLinux)
	root, rootPEM := trustCertPEM(t, "Hub Root", true, time.Now().Add(time.Hour))
	sum := sha256.Sum256(root.Raw)
	h.mux = http.NewServeMux()
	cfg := &ServerConfig{Mux: h.mux}
	certs := fakeCerts{items: []CertificateItem{{FingerprintSHA256: "live-1", CAID: "ca-1", ValidUntil: time.Now().Add(time.Hour).Format(time.RFC3339)}}}
	cas := fakeCAs{items: []CAListItem{{ID: "ca-1", Name: "Hub Root", CertificateFingerprintSHA256: hex.EncodeToString(sum[:])}}}
	registerTrustBundleHandlers(cfg, h.mux, h.mux, h.auth, h.agents, h.store, h.pending, certs, cas, h.audit)
	rec := h.do(h.propose, http.MethodPost, "/api/v1/trust-bundles", map[string]any{
		"name": "retire root", "action": "remove", "cert_pem": rootPEM, "selector": map[string]any{"agent_ids": []string{id}},
	})
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), "distrusts 1 live managed certificate") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	list, _ := h.pending.List(context.Background(), "pending")
	if len(list) != 1 || !strings.Contains(list[0].Rationale, "WARNING") {
		t.Fatalf("the approver must see the warning in the queue: %+v", list)
	}
}

func TestTrustBundleExecutor_TenantAdminCannotApproveAFleetWidePush(t *testing.T) {
	h := newTrustHub(t)
	t.Setenv("MULTI_TENANCY", "on") // after newTrustHub, which pins it off
	id, _ := h.registerAgent("web-1", AgentTypeLinux)
	_, root := trustCertPEM(t, "Root", true, time.Now().Add(time.Hour))
	params, _ := json.Marshal(trustBundleParams{Name: "x", Action: "add", CertPEM: root, AgentIDs: []string{id}})
	exec := newTrustBundleExecutor(h.store, h.agents, h.audit)
	act := PendingAction{ID: "a1", Params: params, ProposedBy: "root-admin", Tenant: "acme"}

	_, err := exec(context.Background(), act, AuthPrincipal{ID: "acme-admin", Tenant: "acme", Role: "pki-admin"})
	if err == nil || !strings.Contains(err.Error(), "super-admin") {
		t.Fatalf("a tenant-scoped approver must be refused: %v", err)
	}
	if list, _ := h.store.List(context.Background(), 10); len(list) != 0 {
		t.Fatal("a refused approval must create nothing")
	}
	if _, err := exec(context.Background(), act, AuthPrincipal{ID: "platform-admin", Role: "pki-admin", SuperAdmin: true}); err != nil {
		t.Fatalf("a platform super-admin may approve: %v", err)
	}
}
