// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// exceptionCerts serves a fixed set of certificates by fingerprint.
type exceptionCerts struct {
	*reportCertProvider
	byFP map[string]CertificateItem
}

func (p exceptionCerts) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	it, ok := p.byFP[fp]
	return CertificateDetail{CertificateItem: it}, ok, nil
}

// exceptionCAs knows a fixed set of CA ids.
type exceptionCAs struct {
	stubCreatableCAProvider
	ids map[string]bool
}

func (p exceptionCAs) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	var items []CAListItem
	for id, ok := range p.ids {
		if ok {
			items = append(items, CAListItem{ID: id})
		}
	}
	return CAListResult{Items: items, Total: len(items)}, nil
}

func (p exceptionCAs) GetCA(_ context.Context, id string) (CAListItem, bool, error) {
	return CAListItem{ID: id}, p.ids[id], nil
}

type exceptionEnv struct {
	mux     *http.ServeMux
	auth    *Authenticator
	store   *sqliteFindingExceptionStore
	pending PendingActionStore
	audit   *expiryAudit
	certs   exceptionCerts
	cas     exceptionCAs
}

func newExceptionEnv(t *testing.T) *exceptionEnv {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv(exceptionMaxDaysEnv, "")
	auth := newReportsTestAuth(t)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "exc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteFindingExceptionStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureTenantSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &exceptionEnv{
		mux: http.NewServeMux(), auth: auth, store: store, pending: newTestPendingStore(t), audit: &expiryAudit{},
		certs: exceptionCerts{reportCertProvider: &reportCertProvider{}, byFP: map[string]CertificateItem{
			"fp-1":      {FingerprintSHA256: "fp-1", CAID: "ca-1", OwnerTeam: "payments", OwnerEmail: "pay@example.com", RiskFlags: []string{"WEAK_RSA_KEY"}},
			"fp-acme":   {FingerprintSHA256: "fp-acme", CAID: "ca-acme", RiskFlags: []string{"WEAK_RSA_KEY"}},
			"fp-globex": {FingerprintSHA256: "fp-globex", CAID: "ca-globex", RiskFlags: []string{"WEAK_RSA_KEY"}},
		}},
		cas: exceptionCAs{ids: map[string]bool{"ca-1": true, "ca-acme": true, "ca-globex": true}},
	}
	registerExceptionHandlers(e.mux, auth, e.certs, e.cas, store, e.pending, e.audit)
	registerPendingActionHandlers(e.mux, auth, e.certs, e.pending, e.audit,
		map[string]ActionExecutor{ExceptionCreateActionType: newExceptionExecutor(store, e.certs, e.cas, e.audit)})
	return e
}

func (e *exceptionEnv) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func excBody(target, code string, days int) []byte {
	b, _ := json.Marshal(exceptionRequest{
		TargetType: FindingExceptionTargetCertificate, TargetID: target, FindingCode: code,
		JustificationCode: JustificationRiskAccepted, JustificationNote: "decommission planned",
		ExpiresAt: time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour).Format(time.RFC3339),
	})
	return b
}

func (e *exceptionEnv) propose(t *testing.T, token string, body []byte) string {
	t.Helper()
	rec := e.do(bearerReq(token, http.MethodPost, "/api/v1/exceptions", body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data struct {
			Status          string `json:"status"`
			PendingActionID string `json:"pending_action_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Data.PendingActionID == "" || out.Data.Status != "pending" {
		t.Fatalf("propose body: %s", rec.Body.String())
	}
	return out.Data.PendingActionID
}

func (e *exceptionEnv) activeCount(t *testing.T) int {
	t.Helper()
	l, err := e.store.ListActive(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return len(l)
}

func TestCreateReturns202AndNoEffect(t *testing.T) {
	e := newExceptionEnv(t)
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	e.propose(t, prop, excBody("fp-1", "WEAK_RSA_KEY", 30))
	if n := e.activeCount(t); n != 0 {
		t.Fatalf("exception active without approval: %d", n)
	}
	active, _ := e.store.ListActive(context.Background(), time.Now())
	if r := computeCryptoPostureReport(findingFunnelTestCerts(), active); r.Findings.Suppressed != 0 {
		t.Fatalf("suppressed before approval: %d", r.Findings.Suppressed)
	}
	if _, ok := e.audit.find("exception.create"); !ok {
		t.Fatal("no exception.create audit row")
	}
}

func TestSecondApproverActivates(t *testing.T) {
	e := newExceptionEnv(t)
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	appr := mintAdminToken(t, e.auth, "approver-one", "")
	id := e.propose(t, prop, excBody("fp-1", "WEAK_RSA_KEY", 30))
	rec := e.do(bearerReq(appr, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	active, _ := e.store.ListActive(context.Background(), time.Now())
	if len(active) != 1 || active[0].CreatedBy != "proposer-one" || active[0].TargetID != "fp-1" {
		t.Fatalf("active = %+v", active)
	}
	ent, ok := e.audit.find("exception.approve")
	if !ok || ent.ActorID != "approver-one" || ent.ResourceID != active[0].ID {
		t.Fatalf("exception.approve audit = %+v ok=%v", ent, ok)
	}
	if _, ok := e.audit.find("exception.create"); !ok {
		t.Fatal("no exception.create audit row")
	}
	tenants, _ := e.store.TenantsByID(context.Background())
	if tenants[active[0].ID] != DefaultTenant {
		t.Fatalf("stamp = %q", tenants[active[0].ID])
	}
}

func TestSelfApprovalRefused(t *testing.T) {
	e := newExceptionEnv(t)
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	id := e.propose(t, prop, excBody("fp-1", "WEAK_RSA_KEY", 30))
	rec := e.do(bearerReq(prop, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self approval: %d", rec.Code)
	}
	if e.activeCount(t) != 0 {
		t.Fatal("exception created by self approval")
	}
}

func TestMaxDaysAndWildcard(t *testing.T) {
	e := newExceptionEnv(t)
	tok := mintAdminToken(t, e.auth, "proposer-one", "")
	post := func(body []byte) int {
		return e.do(bearerReq(tok, http.MethodPost, "/api/v1/exceptions", body)).Code
	}
	if c := post(excBody("fp-1", "WEAK_RSA_KEY", 366)); c != http.StatusBadRequest {
		t.Fatalf("366d: %d", c)
	}
	// Stay a minute inside the cap so the request's own latency cannot tip it.
	atCap, _ := json.Marshal(exceptionRequest{TargetType: "certificate", TargetID: "fp-1", FindingCode: "WEAK_RSA_KEY",
		JustificationCode: JustificationRiskAccepted, ExpiresAt: time.Now().UTC().Add(365*24*time.Hour - time.Minute).Format(time.RFC3339)})
	if c := post(atCap); c != http.StatusAccepted {
		t.Fatalf("365d: %d", c)
	}
	t.Setenv(exceptionMaxDaysEnv, "30")
	if c := post(excBody("fp-1", "OTHER_CODE", 31)); c != http.StatusBadRequest {
		t.Fatalf("31d with EXCEPTION_MAX_DAYS=30: %d", c)
	}
	t.Setenv(exceptionMaxDaysEnv, "9999") // env can only shorten the cap
	if exceptionMaxDays() != 365 {
		t.Fatalf("cap widened: %d", exceptionMaxDays())
	}
	for _, tgt := range []string{"*", "abc*", "%", "all", "ANY", "a?b"} {
		if c := post(excBody(tgt, "WEAK_RSA_KEY", 5)); c != http.StatusBadRequest {
			t.Errorf("target %q: %d", tgt, c)
		}
		if c := post(excBody("fp-1", tgt, 5)); c != http.StatusBadRequest {
			t.Errorf("code %q: %d", tgt, c)
		}
	}
	past, _ := json.Marshal(exceptionRequest{TargetType: "certificate", TargetID: "fp-1", FindingCode: "X",
		JustificationCode: JustificationRiskAccepted, ExpiresAt: time.Now().Add(-time.Hour).Format(time.RFC3339)})
	if c := post(past); c != http.StatusBadRequest {
		t.Fatalf("past expiry: %d", c)
	}
	if c := post([]byte(`{"target_type":"certificate","bogus":1}`)); c != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", c)
	}
}

func TestDeleteReturnsCountImmediately(t *testing.T) {
	e := newExceptionEnv(t)
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	appr := mintAdminToken(t, e.auth, "approver-one", "")
	id := e.propose(t, prop, excBody("fp-1", "WEAK_RSA_KEY", 30))
	e.do(bearerReq(appr, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil))
	active, _ := e.store.ListActive(context.Background(), time.Now())
	if len(active) != 1 {
		t.Fatalf("active = %d", len(active))
	}
	excID := active[0].ID
	funnel := func() int {
		a, _ := e.store.ListActive(context.Background(), time.Now())
		certs := []CertificateItem{{FingerprintSHA256: "fp-1", RiskFlags: []string{"WEAK_RSA_KEY"}}}
		return computeCryptoPostureReport(certs, a).Findings.Suppressed
	}
	if funnel() != 1 {
		t.Fatal("not suppressed while active")
	}
	rec := e.do(bearerReq(prop, http.MethodDelete, "/api/v1/exceptions/"+excID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if funnel() != 0 {
		t.Fatal("still suppressed after delete")
	}
	if _, ok := e.audit.find("exception.delete"); !ok {
		t.Fatal("no exception.delete audit row")
	}
	if rec := e.do(bearerReq(prop, http.MethodDelete, "/api/v1/exceptions/"+excID, nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d", rec.Code)
	}
	if tenants, _ := e.store.TenantsByID(context.Background()); len(tenants) != 0 {
		t.Fatalf("stamp not removed: %v", tenants)
	}
}

func TestDuplicateConflict(t *testing.T) {
	e := newExceptionEnv(t)
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	appr := mintAdminToken(t, e.auth, "approver-one", "")
	id := e.propose(t, prop, excBody("fp-1", "WEAK_RSA_KEY", 30))
	if rec := e.do(bearerReq(prop, http.MethodPost, "/api/v1/exceptions", excBody("fp-1", "WEAK_RSA_KEY", 30))); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate pending: %d", rec.Code)
	}
	e.do(bearerReq(appr, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil))
	if rec := e.do(bearerReq(prop, http.MethodPost, "/api/v1/exceptions", excBody("fp-1", "WEAK_RSA_KEY", 30))); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate active: %d", rec.Code)
	}
	// A different finding code on the same target is not a duplicate.
	e.propose(t, prop, excBody("fp-1", "SAN_SPRAWL", 30))
}

func TestListShowsPendingAndActive(t *testing.T) {
	e := newExceptionEnv(t)
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	appr := mintAdminToken(t, e.auth, "approver-one", "")
	id := e.propose(t, prop, excBody("fp-1", "WEAK_RSA_KEY", 30))
	e.do(bearerReq(appr, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil))
	pend := e.propose(t, prop, excBody("fp-1", "SAN_SPRAWL", 30))
	rec := e.do(bearerReq(prop, http.MethodGet, "/api/v1/exceptions", nil))
	var out struct {
		Data []exceptionView `json:"data"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Data) != 2 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	got := map[string]exceptionView{}
	for _, v := range out.Data {
		got[v.Status] = v
	}
	if got["active"].FindingCode != "WEAK_RSA_KEY" || got["pending"].PendingActionID != pend || got["pending"].FindingCode != "SAN_SPRAWL" {
		t.Fatalf("views = %+v", got)
	}
}

func TestMCPAgentCannotPropose(t *testing.T) {
	e := newExceptionEnv(t)
	_, tok, err := e.auth.CreateAPIKeyAs("", "agent-key", "agent-1", RoleMCPAgent, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.do(bearerReq(tok, http.MethodPost, "/api/v1/exceptions", excBody("fp-1", "WEAK_RSA_KEY", 30))); rec.Code != http.StatusForbidden {
		t.Fatalf("mcp-agent propose: %d", rec.Code)
	}
}

func TestExecutorFailsClosedWhenTargetVanished(t *testing.T) {
	e := newExceptionEnv(t)
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	appr := mintAdminToken(t, e.auth, "approver-one", "")
	id := e.propose(t, prop, excBody("fp-1", "WEAK_RSA_KEY", 30))
	delete(e.certs.byFP, "fp-1")
	rec := e.do(bearerReq(appr, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("approved a vanished target: %s", rec.Body.String())
	}
	if e.activeCount(t) != 0 {
		t.Fatal("exception created for a vanished target")
	}
	if a, _, _ := e.pending.Get(context.Background(), id); a.Status != "failed" {
		t.Fatalf("queue status = %s", a.Status)
	}
}

func TestCATargetAndUnknownTarget(t *testing.T) {
	e := newExceptionEnv(t)
	tok := mintAdminToken(t, e.auth, "proposer-one", "")
	ca, _ := json.Marshal(exceptionRequest{TargetType: "ca", TargetID: "ca-1", FindingCode: "CA_EXPIRING",
		JustificationCode: JustificationCompensatingControl, ExpiresAt: time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
	e.propose(t, tok, ca)
	if rec := e.do(bearerReq(tok, http.MethodPost, "/api/v1/exceptions", excBody("fp-missing", "X", 5))); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown cert: %d", rec.Code)
	}
}

// setupExceptionTenants turns multi-tenancy on with acme/globex owning one CA
// each, and installs the tenant store the handlers consult.
func setupExceptionTenants(t *testing.T, e *exceptionEnv) (acme, acme2, globex string) {
	t.Helper()
	t.Setenv("MULTI_TENANCY", "on")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv(dbModeEnv, dbModeSQLite)
	t.Setenv("APP_AUDIT_DB_DSN", "")
	ts := NewTenantStoreFromEnv()
	if ts == nil {
		t.Fatal("tenant store unavailable")
	}
	ctx := context.Background()
	for _, id := range []string{"acme", "globex"} {
		if _, err := ts.CreateTenant(ctx, id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.SetCATenant(ctx, "ca-acme", "acme"); err != nil {
		t.Fatal(err)
	}
	if err := ts.SetCATenant(ctx, "ca-globex", "globex"); err != nil {
		t.Fatal(err)
	}
	prev := activeTenantStore
	setActiveTenantStore(ts)
	t.Cleanup(func() { setActiveTenantStore(prev) })
	mk := func(name, principal, tenant string) string {
		_, tok, err := e.auth.CreateAPIKey(name, principal, "pki-admin", []string{"*"}, "", tenant, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	return mk("acme-1", "acme-prop", "acme"), mk("acme-2", "acme-appr", "acme"), mk("globex-1", "globex-admin", "globex")
}

func tenantReq(token, tenant, method, url string, body []byte) *http.Request {
	r := bearerReq(token, method, url, body)
	r.Header.Set("X-Tenant", tenant)
	return r
}

func TestTenantIsolation(t *testing.T) {
	e := newExceptionEnv(t)
	acme, acme2, globex := setupExceptionTenants(t, e)

	// A tenant cannot except another tenant's certificate or CA.
	if rec := e.do(tenantReq(acme, "acme", http.MethodPost, "/api/v1/exceptions", excBody("fp-globex", "WEAK_RSA_KEY", 30))); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant propose: %d", rec.Code)
	}
	caBody, _ := json.Marshal(exceptionRequest{TargetType: "ca", TargetID: "ca-globex", FindingCode: "X",
		JustificationCode: JustificationRiskAccepted, ExpiresAt: time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
	if rec := e.do(tenantReq(acme, "acme", http.MethodPost, "/api/v1/exceptions", caBody)); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant CA propose: %d", rec.Code)
	}

	pid := e.propose(t, acme, excBody("fp-acme", "WEAK_RSA_KEY", 30))

	// The pending proposal is invisible to, and undecidable by, globex.
	list := func(tok, tenant string) []exceptionView {
		rec := e.do(tenantReq(tok, tenant, http.MethodGet, "/api/v1/exceptions", nil))
		var out struct {
			Data []exceptionView `json:"data"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		return out.Data
	}
	if got := list(globex, "globex"); len(got) != 0 {
		t.Fatalf("globex sees acme's pending: %+v", got)
	}
	if rec := e.do(tenantReq(globex, "globex", http.MethodPost, "/api/v1/pending-actions/"+pid+"/approve", nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("globex approve acme's action: %d", rec.Code)
	}
	if e.activeCount(t) != 0 {
		t.Fatal("exception created by a foreign tenant")
	}

	// acme's second principal approves; the exception is stamped acme.
	if rec := e.do(tenantReq(acme2, "acme", http.MethodPost, "/api/v1/pending-actions/"+pid+"/approve", nil)); rec.Code != http.StatusOK {
		t.Fatalf("acme approve: %d %s", rec.Code, rec.Body.String())
	}
	active, _ := e.store.ListActive(context.Background(), time.Now())
	if len(active) != 1 {
		t.Fatalf("active = %d", len(active))
	}
	if tenants, _ := e.store.TenantsByID(context.Background()); tenants[active[0].ID] != "acme" {
		t.Fatalf("stamp = %v", tenants)
	}
	if got := list(acme, "acme"); len(got) != 1 || got[0].Status != "active" {
		t.Fatalf("acme list = %+v", got)
	}
	if got := list(globex, "globex"); len(got) != 0 {
		t.Fatalf("globex sees acme's exception: %+v", got)
	}
	if rec := e.do(tenantReq(globex, "globex", http.MethodDelete, "/api/v1/exceptions/"+active[0].ID, nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("globex delete acme's: %d", rec.Code)
	}
	if e.activeCount(t) != 1 {
		t.Fatal("foreign tenant deleted the exception")
	}
	if rec := e.do(tenantReq(acme, "acme", http.MethodDelete, "/api/v1/exceptions/"+active[0].ID, nil)); rec.Code != http.StatusOK {
		t.Fatalf("acme delete own: %d", rec.Code)
	}
}

// A platform super-admin proposes on a tenant's resource: the exception lands
// in the tenant that owns the target, not in the super-admin's own tenant.
func TestSuperAdminProposalStampsTargetTenant(t *testing.T) {
	e := newExceptionEnv(t)
	_, _, globex := setupExceptionTenants(t, e)
	rec := e.do(bearerReq("reports-test-token", http.MethodPost, "/api/v1/exceptions", excBody("fp-globex", "WEAK_RSA_KEY", 30)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("super-admin propose: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data struct {
			ID string `json:"pending_action_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	a, ok, _ := e.pending.Get(context.Background(), out.Data.ID)
	if !ok || a.Tenant != "globex" {
		t.Fatalf("pending action tenant = %q", a.Tenant)
	}
	if rec := e.do(tenantReq(globex, "globex", http.MethodPost, "/api/v1/pending-actions/"+out.Data.ID+"/approve", nil)); rec.Code != http.StatusOK {
		t.Fatalf("globex approve: %d %s", rec.Code, rec.Body.String())
	}
	active, _ := e.store.ListActive(context.Background(), time.Now())
	if tenants, _ := e.store.TenantsByID(context.Background()); len(active) != 1 || tenants[active[0].ID] != "globex" {
		t.Fatalf("stamp = %v active=%d", tenants, len(active))
	}
}

func TestExceptionStoreWithoutTenantStampIsUnavailable(t *testing.T) {
	e := newExceptionEnv(t)
	mux := http.NewServeMux()
	registerExceptionHandlers(mux, e.auth, e.certs, e.cas, nil, e.pending, e.audit)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, e.auth, "p", ""), http.MethodGet, "/api/v1/exceptions", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil store: %d", rec.Code)
	}
}

func TestOpenAPIHasNoV09ExceptionNotes(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"not available in v0.9", "cannot be created yet"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("openapi.yaml still says %q", banned)
		}
	}
}

// ---- target_file exceptions (install posture) ----

// addFile puts a discovered file in the exception store's database, linked to
// the given certificate fingerprints.
func (e *exceptionEnv) addFile(t *testing.T, id, tenant, host, path string, fps ...string) {
	t.Helper()
	ctx := context.Background()
	if err := ensureDiscoveredFilesSchema(ctx, e.store.db, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.db.Exec(`INSERT INTO discovered_files (id, tenant, host, path, kind, posture, findings) VALUES (?, ?, ?, ?, 'jks', 'root_service', '[]')`, id, tenant, host, path); err != nil {
		t.Fatal(err)
	}
	for _, fp := range fps {
		if _, err := e.store.db.Exec(`INSERT INTO certificate_files (certificate_fingerprint, file_id) VALUES (?, ?)`, fp, id); err != nil {
			t.Fatal(err)
		}
	}
}

func fileExcBody(fileID, code string) []byte {
	b, _ := json.Marshal(exceptionRequest{
		TargetType: FindingExceptionTargetFile, TargetID: fileID, FindingCode: code,
		JustificationCode: JustificationCompensatingControl, JustificationNote: "tomcat runs in a locked-down container",
		ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
	})
	return b
}

func TestFileExceptionLifecycle(t *testing.T) {
	e := newExceptionEnv(t)
	e.addFile(t, "file-1", "", "10.0.0.7", "/opt/tomcat/conf/keystore.jks", "fp-1")
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	appr := mintAdminToken(t, e.auth, "approver-one", "")

	id := e.propose(t, prop, fileExcBody("file-1", "SERVICE_RUNS_AS_ROOT"))
	if n := e.activeCount(t); n != 0 {
		t.Fatal("active before approval")
	}
	if rec := e.do(bearerReq(prop, http.MethodPost, "/api/v1/exceptions", fileExcBody("file-1", "SERVICE_RUNS_AS_ROOT"))); rec.Code != http.StatusConflict {
		t.Fatalf("a second claim on the same finding on the same file must conflict: %d", rec.Code)
	}
	if rec := e.do(bearerReq(appr, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil)); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	active, _ := e.store.ListActive(context.Background(), time.Now())
	if len(active) != 1 || active[0].TargetType != FindingExceptionTargetFile || active[0].TargetID != "file-1" {
		t.Fatalf("active = %+v", active)
	}

	rec := e.do(bearerReq(prop, http.MethodGet, "/api/v1/exceptions", nil))
	var list struct{ Data []exceptionView }
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Data) != 1 || list.Data[0].TargetLabel != "10.0.0.7:/opt/tomcat/conf/keystore.jks" {
		t.Fatalf("list: %s", rec.Body.String())
	}

	// The compliance evidence pack lists it, named by host:path and owned by the cert's team.
	risks := buildAcceptedRisks(context.Background(), e.store, []CertificateItem{e.certs.byFP["fp-1"]}, nil, time.Now())
	if len(risks) != 1 || risks[0].TargetType != "target_file" || risks[0].TargetLabel != "10.0.0.7:/opt/tomcat/conf/keystore.jks" || risks[0].OwnerTeam != "payments" {
		t.Fatalf("accepted risks: %+v", risks)
	}
	if got := buildAcceptedRisks(context.Background(), e.store, []CertificateItem{e.certs.byFP["fp-acme"]}, nil, time.Now()); len(got) != 0 {
		t.Fatalf("a file with no certificate in scope must not be listed: %+v", got)
	}

	// Posture view: the accepted code is flagged on the endpoint.
	eps := []DiscoveryEndpoint{{InstallPosture: &DiscoveryInstallPosture{FileID: "file-1", Findings: []string{"SERVICE_RUNS_AS_ROOT: java runs as uid 0", "KEY_WORLD_READABLE: mode 644"}}}}
	markAcceptedFileFindings(context.Background(), e.store.db, false, eps)
	if got := eps[0].InstallPosture.AcceptedFindings; len(got) != 1 || got[0] != "SERVICE_RUNS_AS_ROOT" {
		t.Fatalf("accepted findings: %v", got)
	}
}

func TestFileExceptionRefusals(t *testing.T) {
	e := newExceptionEnv(t)
	prop := mintAdminToken(t, e.auth, "proposer-one", "")
	appr := mintAdminToken(t, e.auth, "approver-one", "")
	if rec := e.do(bearerReq(prop, http.MethodPost, "/api/v1/exceptions", fileExcBody("nope", "SERVICE_RUNS_AS_ROOT"))); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown file: %d", rec.Code)
	}
	if rec := e.do(bearerReq(prop, http.MethodPost, "/api/v1/exceptions", fileExcBody("f*", "SERVICE_RUNS_AS_ROOT"))); rec.Code != http.StatusBadRequest {
		t.Fatalf("wildcard: %d", rec.Code)
	}
	// Fail closed: a file that vanished between proposal and approval aborts the action.
	e.addFile(t, "file-gone", "", "h", "/p.jks")
	id := e.propose(t, prop, fileExcBody("file-gone", "HOME_DIR_KEYSTORE"))
	if _, err := e.store.db.Exec(`DELETE FROM discovered_files WHERE id = 'file-gone'`); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(bearerReq(appr, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil)); rec.Code == http.StatusOK {
		t.Fatalf("approval of a vanished file must fail: %d", rec.Code)
	}
	if e.activeCount(t) != 0 {
		t.Fatal("exception created for a vanished file")
	}
}

func TestFileExceptionTenantIsolation(t *testing.T) {
	e := newExceptionEnv(t)
	acme, _, globex := setupExceptionTenants(t, e)
	e.addFile(t, "file-acme", "acme", "10.1.0.1", "/opt/a.jks")
	if rec := e.do(bearerReq(globex, http.MethodPost, "/api/v1/exceptions", fileExcBody("file-acme", "SERVICE_RUNS_AS_ROOT"))); rec.Code != http.StatusNotFound {
		t.Fatalf("another tenant's file must look absent: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(bearerReq(acme, http.MethodPost, "/api/v1/exceptions", fileExcBody("file-acme", "SERVICE_RUNS_AS_ROOT"))); rec.Code != http.StatusAccepted {
		t.Fatalf("own tenant: %d %s", rec.Code, rec.Body.String())
	}
}
