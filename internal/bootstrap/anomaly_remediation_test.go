// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// remediationFakes count every mutation so a test can assert "executed N times".
type remediationFakes struct {
	mu        sync.Mutex
	suspended []string
	activated []string
	patched   map[string]bool
	revoked   []string
	failRev   map[string]bool
}

type remCAs struct {
	CAProvider
	f *remediationFakes
}

func (c remCAs) GetCA(_ context.Context, id string) (CAListItem, bool, error) {
	return CAListItem{ID: id}, id != "ca-missing", nil
}
func (c remCAs) SuspendCA(_ context.Context, id string) (CAStatusChange, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.suspended = append(c.f.suspended, id)
	return CAStatusChange{ID: id, Status: "suspended"}, nil
}
func (c remCAs) ActivateCA(_ context.Context, id string) (CAStatusChange, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.activated = append(c.f.activated, id)
	return CAStatusChange{ID: id, Status: "active"}, nil
}

type remTemplates struct {
	TemplateProvider
	f *remediationFakes
}

func (t remTemplates) GetTemplate(_ context.Context, id string) (TemplateItem, bool, error) {
	return TemplateItem{ID: id}, id != "tpl-missing", nil
}
func (t remTemplates) PatchTemplate(_ context.Context, id string, req TemplatePatchRequest) (TemplateItem, error) {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	if t.f.patched == nil {
		t.f.patched = map[string]bool{}
	}
	t.f.patched[id] = *req.Active
	return TemplateItem{ID: id}, nil
}

type remCerts struct {
	CertificateProvider
	f    *remediationFakes
	caOf map[string]string
}

func (c remCerts) ListCertificates(context.Context, CertificateListQuery) (CertificateListResult, error) {
	return CertificateListResult{Total: 7}, nil
}
func (c remCerts) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	return CertificateDetail{CertificateItem: CertificateItem{FingerprintSHA256: fp, CAID: c.caOf[fp]}}, true, nil
}
func (c remCerts) RevokeCertificate(_ context.Context, fp string, _ CertificateRevokeRequest) (CertificateRevokeResult, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.f.failRev[fp] {
		return CertificateRevokeResult{}, fmt.Errorf("boom")
	}
	c.f.revoked = append(c.f.revoked, fp)
	return CertificateRevokeResult{FingerprintSHA256: fp}, nil
}

type remEnv struct {
	mux     *http.ServeMux
	auth    *Authenticator
	pending PendingActionStore
	audit   *expiryAudit
	f       *remediationFakes
	sched   *AnomalyScheduler
	certs   remCerts
}

func newRemEnv(t *testing.T, nFingerprints int) *remEnv {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	f := &remediationFakes{}
	fps := make([]string, nFingerprints)
	for i := range fps {
		fps[i] = fmt.Sprintf("fp-%03d", i)
	}
	e := &remEnv{
		mux: http.NewServeMux(), auth: auth, pending: newTestPendingStore(t), audit: &expiryAudit{}, f: f,
		sched: &AnomalyScheduler{fingerprintsByRequester: map[string][]string{"mallory": fps}},
		certs: remCerts{f: f, caOf: map[string]string{}},
	}
	return e
}

// wire builds the real wiring: WithAnomalyRemediation registers the
// executors, registerPendingActionHandlers reads them from the config.
func (e *remEnv) wire(t *testing.T) {
	t.Helper()
	cas, tpls := remCAs{f: e.f}, remTemplates{f: e.f}
	e.mux = http.NewServeMux()
	registerAnomalyRemediationHandlers(e.mux, e.auth, e.sched, e.certs, cas, tpls, e.pending, e.audit)
	exec := newAnomalyRemediationExecutor(e.certs, cas, tpls, e.audit)
	execs := map[string]ActionExecutor{}
	for _, typ := range anomalyActionTypes {
		execs[typ] = exec
	}
	registerPendingActionHandlers(e.mux, e.auth, e.certs, e.pending, e.audit, execs)
}

func (e *remEnv) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func (e *remEnv) token(t *testing.T, principal, role string) string {
	t.Helper()
	_, tok, err := e.auth.CreateAPIKeyAs("", principal+"-key", principal, role, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func remBody(action, ca, tpl, requester string) []byte {
	b, _ := json.Marshal(map[string]string{"action": action, "ca_id": ca, "template_id": tpl, "requester": requester, "finding_kind": "requester_burst"})
	return b
}

var allRemediationBodies = map[string][]byte{
	"suspend_ca":       remBody("suspend_ca", "ca-1", "", ""),
	"reactivate_ca":    remBody("reactivate_ca", "ca-1", "", ""),
	"disable_template": remBody("disable_template", "", "tpl-1", ""),
	"enable_template":  remBody("enable_template", "", "tpl-1", ""),
	"revoke_batch":     remBody("revoke_batch", "", "", "mallory"),
}

func (e *remEnv) propose(t *testing.T, tok string, body []byte) (id string, out map[string]any) {
	t.Helper()
	rec := e.do(bearerReq(tok, http.MethodPost, anomalyRemediationsRoute, body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	id, _ = env.Data["pending_action_id"].(string)
	if id == "" || env.Data["status"] != "proposed" {
		t.Fatalf("propose body: %s", rec.Body.String())
	}
	return id, env.Data
}

func (e *remEnv) mutations() int {
	e.f.mu.Lock()
	defer e.f.mu.Unlock()
	return len(e.f.suspended) + len(e.f.activated) + len(e.f.patched) + len(e.f.revoked)
}

func (e *remEnv) decide(tok, id, verb string) *httptest.ResponseRecorder {
	return e.do(bearerReq(tok, http.MethodPost, "/api/v1/pending-actions/"+id+"/"+verb, nil))
}

func TestRemediationLandsProposedAndExecutesZeroTimes(t *testing.T) {
	e := newRemEnv(t, 3)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	for name, body := range allRemediationBodies {
		id, data := e.propose(t, prop, body)
		if _, ok := data["blast_radius"].(map[string]any); !ok {
			t.Errorf("%s: no blast_radius in %v", name, data)
		}
		a, ok, _ := e.pending.Get(context.Background(), id)
		if !ok || a.Status != "pending" || a.ProposedBy != "proposer-one" {
			t.Errorf("%s: queue row = %+v ok=%v", name, a, ok)
		}
	}
	if n := e.mutations(); n != 0 {
		t.Fatalf("%d mutations before any approval", n)
	}
	rec := e.do(bearerReq(prop, http.MethodGet, "/api/v1/pending-actions?status=pending", nil))
	var list struct {
		Data []PendingAction `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Data) != 5 {
		t.Fatalf("pending-actions list: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := e.audit.find(anomalyAuditProposeAction); !ok {
		t.Fatal("no anomaly.remediation.propose audit row")
	}
	if got := e.audit.count(anomalyAuditProposeAction, AuditOutcomePendingApproval); got != 5 {
		t.Fatalf("propose audit rows = %d", got)
	}
}

func TestProposerCannotApprove(t *testing.T) {
	e := newRemEnv(t, 3)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	for name, body := range allRemediationBodies {
		id, _ := e.propose(t, prop, body)
		if rec := e.decide(prop, id, "approve"); rec.Code != http.StatusForbidden {
			t.Errorf("%s: self-approval = %d", name, rec.Code)
		}
	}
	if n := e.mutations(); n != 0 {
		t.Fatalf("%d mutations after refused self-approval", n)
	}
}

func TestSecondApproverExecutes(t *testing.T) {
	e := newRemEnv(t, 3)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	appr := e.token(t, "approver-one", "pki-admin")

	for _, name := range []string{"suspend_ca", "reactivate_ca", "disable_template", "enable_template", "revoke_batch"} {
		id, _ := e.propose(t, prop, allRemediationBodies[name])
		if rec := e.decide(appr, id, "approve"); rec.Code != http.StatusOK {
			t.Fatalf("%s approve: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	f := e.f
	if len(f.suspended) != 1 || len(f.activated) != 1 || len(f.revoked) != 3 {
		t.Fatalf("suspended=%v activated=%v revoked=%v", f.suspended, f.activated, f.revoked)
	}
	if v, ok := f.patched["tpl-1"]; !ok || !v { // enable ran last
		t.Fatalf("patched = %v", f.patched)
	}
	if _, ok := e.audit.find(anomalyAuditProposeAction); !ok {
		t.Fatal("no propose audit row")
	}
	if got := e.audit.count(anomalyAuditApproveAction, AuditOutcomeSuccess); got != 5 {
		t.Fatalf("approve audit rows = %d", got)
	}
	ent, _ := e.audit.find(anomalyAuditApproveAction)
	if ent.ActorID != "approver-one" {
		t.Fatalf("approve audit actor = %q, want the approver", ent.ActorID)
	}
}

func TestRejectAuditedAndNeverExecutes(t *testing.T) {
	e := newRemEnv(t, 3)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	appr := e.token(t, "approver-one", "pki-admin")
	id, _ := e.propose(t, prop, allRemediationBodies["revoke_batch"])
	if rec := e.decide(appr, id, "reject"); rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	if ent, ok := e.audit.find(anomalyAuditRejectAction); !ok || ent.ActorID != "approver-one" || ent.ResourceID != id {
		t.Fatalf("reject audit = %+v ok=%v", ent, ok)
	}
	if a, _, _ := e.pending.Get(context.Background(), id); a.Status != "rejected" {
		t.Fatalf("status = %s", a.Status)
	}
	if n := e.mutations(); n != 0 {
		t.Fatalf("%d mutations after reject", n)
	}
	if rec := e.decide(appr, id, "approve"); rec.Code != http.StatusConflict {
		t.Fatalf("approve after reject: %d", rec.Code)
	}
}

func TestReEnableViaSameApprovalPath(t *testing.T) {
	e := newRemEnv(t, 1)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	appr := e.token(t, "approver-one", "pki-admin")
	id, _ := e.propose(t, prop, allRemediationBodies["suspend_ca"])
	e.decide(appr, id, "approve")
	if len(e.f.suspended) != 1 {
		t.Fatalf("suspended = %v", e.f.suspended)
	}
	id2, _ := e.propose(t, prop, allRemediationBodies["reactivate_ca"])
	if len(e.f.activated) != 0 {
		t.Fatal("reactivated before approval")
	}
	if a, _, _ := e.pending.Get(context.Background(), id2); a.Status != "pending" {
		t.Fatalf("status = %s", a.Status)
	}
	if rec := e.decide(prop, id2, "approve"); rec.Code != http.StatusForbidden {
		t.Fatalf("self re-enable: %d", rec.Code)
	}
	if rec := e.decide(appr, id2, "approve"); rec.Code != http.StatusOK {
		t.Fatalf("approve re-enable: %d %s", rec.Code, rec.Body.String())
	}
	if len(e.f.activated) != 1 || e.f.activated[0] != "ca-1" {
		t.Fatalf("activated = %v", e.f.activated)
	}
}

func TestRevokeBatchCapAndTruncated(t *testing.T) {
	e := newRemEnv(t, 150)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	appr := e.token(t, "approver-one", "pki-admin")
	id, data := e.propose(t, prop, allRemediationBodies["revoke_batch"])
	if br := data["blast_radius"].(map[string]any); br["certificates"] != float64(100) {
		t.Fatalf("blast radius = %v", br)
	}
	a, _, _ := e.pending.Get(context.Background(), id)
	var p anomalyParams
	if err := json.Unmarshal(a.Params, &p); err != nil || len(p.Fingerprints) != 100 || !p.Truncated || p.Requester != "mallory" {
		t.Fatalf("params = %+v err=%v", p, err)
	}
	e.decide(appr, id, "approve")
	if len(e.f.revoked) != 100 {
		t.Fatalf("revoked %d", len(e.f.revoked))
	}
}

func TestRevokeBatchPartialAndTotalFailure(t *testing.T) {
	e := newRemEnv(t, 3)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	appr := e.token(t, "approver-one", "pki-admin")
	e.f.failRev = map[string]bool{"fp-001": true}
	id, _ := e.propose(t, prop, allRemediationBodies["revoke_batch"])
	if rec := e.decide(appr, id, "approve"); rec.Code != http.StatusOK || len(e.f.revoked) != 2 {
		t.Fatalf("partial: %d revoked=%v", rec.Code, e.f.revoked)
	}
	e.f.failRev = map[string]bool{"fp-000": true, "fp-001": true, "fp-002": true}
	id, _ = e.propose(t, prop, allRemediationBodies["revoke_batch"])
	if rec := e.decide(appr, id, "approve"); rec.Code == http.StatusOK {
		t.Fatalf("all-failed batch reported success: %s", rec.Body.String())
	}
	if a, _, _ := e.pending.Get(context.Background(), id); a.Status != "failed" {
		t.Fatalf("status = %s", a.Status)
	}
	if got := e.audit.count(anomalyAuditApproveAction, AuditOutcomeFailure); got != 1 {
		t.Fatalf("failure audit rows = %d", got)
	}
}

func TestRevokeBatchNoRecentIssuance409(t *testing.T) {
	e := newRemEnv(t, 3)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	rec := e.do(bearerReq(prop, http.MethodPost, anomalyRemediationsRoute, remBody("revoke_batch", "", "", "nobody")))
	if rec.Code != http.StatusConflict {
		t.Fatalf("code = %d", rec.Code)
	}
	if e.audit.count(anomalyAuditProposeAction, AuditOutcomeFailure) != 1 {
		t.Fatal("conflict not audited")
	}
}

func TestUnknownAction400(t *testing.T) {
	e := newRemEnv(t, 1)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	for _, body := range [][]byte{
		remBody("delete_ca", "ca-1", "", ""),
		remBody("", "", "", ""),
		remBody("suspend_ca", "", "", ""),
		[]byte(`{"action":"suspend_ca","ca_id":"ca-1","bogus":1}`),
		[]byte(`not json`),
	} {
		if rec := e.do(bearerReq(prop, http.MethodPost, anomalyRemediationsRoute, body)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, rec.Code)
		}
	}
	for _, body := range [][]byte{remBody("suspend_ca", "ca-missing", "", ""), remBody("disable_template", "", "tpl-missing", "")} {
		if rec := e.do(bearerReq(prop, http.MethodPost, anomalyRemediationsRoute, body)); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", body, rec.Code)
		}
	}
	if got := e.audit.count(anomalyAuditProposeAction, AuditOutcomeFailure); got != 7 {
		t.Fatalf("failure audit rows = %d, want 7", got)
	}
}

func TestViewerCannotPropose403(t *testing.T) {
	e := newRemEnv(t, 1)
	e.wire(t)
	viewer := e.token(t, "viewer-one", "viewer")
	rec := e.do(bearerReq(viewer, http.MethodPost, anomalyRemediationsRoute, allRemediationBodies["suspend_ca"]))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d", rec.Code)
	}
	if e.audit.count(anomalyAuditProposeAction, AuditOutcomeDenied) != 1 {
		t.Fatal("denial not audited")
	}
	if rec := e.do(httptest.NewRequest(http.MethodPost, anomalyRemediationsRoute, nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", rec.Code)
	}
	if e.mutations() != 0 {
		t.Fatal("mutation by viewer")
	}
}

func TestMCPAgentCannotApprove(t *testing.T) {
	e := newRemEnv(t, 1)
	e.wire(t)
	agent := e.token(t, "agent-1", RoleMCPAgent)
	id, _ := e.propose(t, agent, allRemediationBodies["suspend_ca"])
	if rec := e.decide(agent, id, "approve"); rec.Code != http.StatusForbidden {
		t.Fatalf("mcp-agent approve: %d", rec.Code)
	}
	if e.mutations() != 0 {
		t.Fatal("mutation after mcp-agent approve")
	}
}

func TestListFiltersToAnomalyTypes(t *testing.T) {
	e := newRemEnv(t, 1)
	e.wire(t)
	prop := e.token(t, "proposer-one", "pki-admin")
	e.propose(t, prop, allRemediationBodies["suspend_ca"])
	if _, err := e.pending.Create(context.Background(), PendingAction{ActionType: "revoke", Params: json.RawMessage(`{}`), ProposedBy: "x"}); err != nil {
		t.Fatal(err)
	}
	rec := e.do(bearerReq(prop, http.MethodGet, anomalyRemediationsRoute, nil))
	var out struct {
		Data []PendingAction `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Data) != 1 || out.Data[0].ActionType != ActionAnomalySuspendCA {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCrossTenantTargetIs404(t *testing.T) {
	e := newRemEnv(t, 1)
	e.wire(t)
	setupExceptionTenants(t, &exceptionEnv{auth: e.auth})
	mk := func(principal, tenant string) string {
		_, tok, err := e.auth.CreateAPIKey(principal+"-key", principal, "pki-admin", []string{"*"}, "", tenant, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	acme, globex := mk("acme-prop", "acme"), mk("globex-admin", "globex")
	req := func(tok, tenant string, body []byte) *httptest.ResponseRecorder {
		return e.do(tenantReq(tok, tenant, http.MethodPost, anomalyRemediationsRoute, body))
	}
	if rec := req(acme, "acme", remBody("suspend_ca", "ca-globex", "", "")); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant CA: %d %s", rec.Code, rec.Body.String())
	}
	if e.audit.count(anomalyAuditProposeAction, AuditOutcomeDenied) != 1 {
		t.Fatal("cross-tenant refusal not audited as denied")
	}
	rec := req(acme, "acme", remBody("suspend_ca", "ca-acme", "", ""))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("own-tenant CA: %d %s", rec.Code, rec.Body.String())
	}
	// Another tenant neither lists nor decides it.
	list := e.do(tenantReq(globex, "globex", http.MethodGet, anomalyRemediationsRoute, nil))
	var out struct {
		Data []PendingAction `json:"data"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &out); err != nil || len(out.Data) != 0 {
		t.Fatalf("globex list: %d %s", list.Code, list.Body.String())
	}
	var created struct {
		Data struct {
			ID string `json:"pending_action_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if r := e.do(tenantReq(globex, "globex", http.MethodPost, "/api/v1/pending-actions/"+created.Data.ID+"/approve", nil)); r.Code != http.StatusNotFound {
		t.Fatalf("globex approve acme's: %d", r.Code)
	}
	// A tenant-scoped approver of the same tenant is refused at execution:
	// CAs are instance-global, so only a super-admin may approve.
	acme2 := mk("acme-appr", "acme")
	if r := e.do(tenantReq(acme2, "acme", http.MethodPost, "/api/v1/pending-actions/"+created.Data.ID+"/approve", nil)); r.Code == http.StatusOK {
		t.Fatalf("tenant-scoped approval executed: %s", r.Body.String())
	}
	if e.mutations() != 0 {
		t.Fatal("mutation under tenant-scoped approval")
	}
}

func TestExecutorsRegistered(t *testing.T) {
	t.Setenv(dbModeEnv, dbModeSQLite)
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	cfg := applyServerOptions(http.NewServeMux(), []ServerOption{
		WithAnomalyRemediation(newReportsTestAuth(t), nil, nil, nil, nil, &expiryAudit{}),
	})
	for _, typ := range anomalyActionTypes {
		if cfg.actionExecutors[typ] == nil {
			t.Errorf("no executor registered for %s", typ)
		}
	}
	// The generic proposer must not accept anomaly types.
	for _, typ := range anomalyActionTypes {
		if validActionType(typ) {
			t.Errorf("%s is forgeable through POST /pending-actions", typ)
		}
	}
}

func TestRecentFingerprintsByRequester(t *testing.T) {
	now := time.Now()
	got := recentFingerprintsByRequester([]IssuanceEvent{
		{RequestedBy: "a", Fingerprint: "f2", IssuedAt: now.Add(-10 * time.Minute)},
		{RequestedBy: "a", Fingerprint: "f1", IssuedAt: now.Add(-5 * time.Minute)},
		{RequestedBy: "a", Fingerprint: "old", IssuedAt: now.Add(-2 * time.Hour)},
		{RequestedBy: "", Fingerprint: "anon", IssuedAt: now},
	}, now)
	if len(got) != 1 || len(got["a"]) != 2 || got["a"][0] != "f1" {
		t.Fatalf("got %v", got)
	}
	s := &AnomalyScheduler{fingerprintsByRequester: got}
	c := s.FingerprintsFor("a")
	c[0] = "mutated"
	if s.FingerprintsFor("a")[0] != "f1" {
		t.Fatal("FingerprintsFor leaked internal slice")
	}
}
