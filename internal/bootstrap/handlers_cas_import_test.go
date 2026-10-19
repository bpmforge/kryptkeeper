// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W23-03: external root import and trust-anchor removal under D-122 dual
// control. Two genuinely different admins (alice proposes, bob approves).

type importEnv struct {
	auth         *Authenticator
	mux          *http.ServeMux
	engine       *ca.Engine
	store        ca.Store
	keys         keystore.Store
	audit        *recordingAuditProvider
	alice, bob   string
	rootPEM      string
	rootKey      *ecdsa.PrivateKey
	rootTemplate *x509.Certificate
}

// testRoot builds a self-signed offline root with its own key.
func testRoot(t *testing.T, cn string, pathLen int, pathLenZero bool) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLenZero,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newImportEnv(t *testing.T, dualControl string) *importEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", dualControl)
	auth := NewAuthenticatorFromEnv()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("import-test-passphrase-32chars!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })
	store := ca.NewMemStore()
	engine := ca.NewEngine(keys, store)
	queue := NewPendingActionStoreFromEnv()
	if queue == nil {
		t.Fatal("pending action store unavailable")
	}
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, NewEngineCAProvider(engine), NewTenantStoreFromEnv(), audit)
	registerPendingActionHandlers(mux, auth, NewFileCertificateProviderFromEnv(), queue, audit, nil, keys)
	tmpl, key, rootPEM := testRoot(t, "Offline Root", 1, false)
	return &importEnv{
		auth: auth,
		mux:  mux, engine: engine, store: store, keys: keys, audit: audit,
		alice:   mintAdminToken(t, auth, "alice", ""),
		bob:     mintAdminToken(t, auth, "bob", ""),
		rootPEM: rootPEM, rootKey: key, rootTemplate: tmpl,
	}
}

func (e *importEnv) do(token, method, path string, body map[string]any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(token, method, path, raw))
	return rec
}

func (e *importEnv) importBody(pemText string, extra map[string]any) map[string]any {
	b := map[string]any{"name": "ext-root", "type": "root", "key_storage_type": "external", "certificate_pem": pemText}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// importFully drives propose -> bob approves -> alice redeems.
func (e *importEnv) importFully(t *testing.T, pemText string) *httptest.ResponseRecorder {
	t.Helper()
	rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(pemText, nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose import: %d %s", rec.Code, rec.Body.String())
	}
	id := actionID(t, rec)
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("approve import: %d %s", rec.Code, rec.Body.String())
	}
	return e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(pemText, map[string]any{"approved_action_id": id}))
}

func (e *importEnv) caID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Data struct {
			ID             string `json:"id"`
			KeyStorageType string `json:"key_storage_type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Data.ID == "" {
		t.Fatalf("no CA in %d: %s", rec.Code, rec.Body.String())
	}
	return p.Data.ID
}

func (e *importEnv) audited(action string, outcome AuditOutcome) bool {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	for _, en := range e.audit.entries {
		if en.Action == action && en.Outcome == outcome {
			return true
		}
	}
	return false
}

func TestImportRootRequiresDualControlThenRedeems(t *testing.T) {
	e := newImportEnv(t, "unset")
	path := "/api/v1/cas/import"

	rec := e.do(e.alice, http.MethodPost, path, e.importBody(e.rootPEM, nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	id := actionID(t, rec)
	if cas, _ := e.engine.ListCAs(); len(cas) != 0 {
		t.Fatalf("a proposal must not import anything, found %d CAs", len(cas))
	}
	withGrant := e.importBody(e.rootPEM, map[string]any{"approved_action_id": id})

	if rec := e.do(e.alice, http.MethodPost, path, withGrant); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "not approved") {
		t.Fatalf("redeem before approval: want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: want 403, got %d", rec.Code)
	}
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("approve by other admin: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(e.bob, http.MethodPost, path, withGrant); rec.Code != http.StatusForbidden {
		t.Fatalf("redeem by non-proposer: want 403, got %d", rec.Code)
	}
	rec = e.do(e.alice, http.MethodPost, path, withGrant)
	if rec.Code != http.StatusCreated {
		t.Fatalf("redeem: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			KeyStorageType string `json:"key_storage_type"`
			Type           string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.KeyStorageType != "external" || created.Data.Type != "root" {
		t.Fatalf("imported CA = %+v, want root/external", created.Data)
	}
	if rec := e.do(e.alice, http.MethodPost, path, withGrant); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "already redeemed") {
		t.Fatalf("second redeem: want 403 already redeemed, got %d: %s", rec.Code, rec.Body.String())
	}
	if !e.audited("ca.import", AuditOutcomeProposed) || !e.audited("ca.import", AuditOutcomeSuccess) {
		t.Fatal("ca.import must be audited as proposed and success")
	}
}

func TestImportGrantDoesNotCoverAnotherCertificate(t *testing.T) {
	e := newImportEnv(t, "unset")
	rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(e.rootPEM, nil))
	id := actionID(t, rec)
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d", rec.Code)
	}
	_, _, otherPEM := testRoot(t, "Other Root", 1, false)
	rec = e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(otherPEM, map[string]any{"approved_action_id": id}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("grant for root A used for root B: want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if cas, _ := e.engine.ListCAs(); len(cas) != 0 {
		t.Fatalf("nothing may be imported, found %d CAs", len(cas))
	}
}

func TestImportRootRejectsNonSelfSignedWithChainImportHint(t *testing.T) {
	e := newImportEnv(t, "unset")
	childKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, e.rootTemplate, &childKey.PublicKey, e.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(interPEM, nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "chain import") {
		t.Fatalf("want 400 with chain import hint, got %d: %s", rec.Code, rec.Body.String())
	}
	// Rejected before the gate: no pending action exists to be approved.
	if e.audited("ca.import", AuditOutcomeProposed) {
		t.Fatal("a rejected import must not create a proposal")
	}
}

func TestImportRootRejectsBadTypeAndStorage(t *testing.T) {
	e := newImportEnv(t, "unset")
	for name, extra := range map[string]map[string]any{
		"intermediate type": {"type": "intermediate"},
		"software storage":  {"key_storage_type": "software"},
		"empty pem":         {"certificate_pem": ""},
	} {
		if rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(e.rootPEM, extra)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody("not a pem", nil)); rec.Code != http.StatusBadRequest {
		t.Errorf("garbage pem: want 400, got %d", rec.Code)
	}
}

func TestImportRootRequiresAdmin(t *testing.T) {
	e := newImportEnv(t, "unset")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cas/import", strings.NewReader("{}"))
	e.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: want 401, got %d", rec.Code)
	}
}

func TestImportRootDirectWhenDualControlOff(t *testing.T) {
	e := newImportEnv(t, "false")
	rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(e.rootPEM, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("dual control off: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(e.rootPEM, nil)); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate import: want 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIssuanceFromImportedRootReturns422NoSigningKey(t *testing.T) {
	e := newImportEnv(t, "false")
	id := e.caID(t, e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(e.rootPEM, nil)))
	_, err := e.engine.IssueCertificate(id, ca.IssuanceRequest{})
	if !errors.Is(err, ca.ErrCANoSigningKey) {
		t.Fatalf("issuance from keyless root: err = %v, want ErrCANoSigningKey", err)
	}
	rec := httptest.NewRecorder()
	if !writeCSRorCAStateError(rec, fmt.Errorf("issue: %w", err)) || rec.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(rec.Body.String(), "no signing key available") {
		t.Fatalf("want 422 no signing key available, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKeyCustodyReportHasNoKeyForImportedRoot(t *testing.T) {
	e := newImportEnv(t, "false")
	e.caID(t, e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(e.rootPEM, nil)))
	report, err := buildKeyCustodyReport(t.Context(), e.keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Keys) != 0 {
		t.Fatalf("imported root must not appear as a custody key, got %d", len(report.Keys))
	}
}

func TestTrustAnchorRemovalGatedAndRefusedWithChild(t *testing.T) {
	e := newImportEnv(t, "unset")
	rootID := e.caID(t, e.importFully(t, e.rootPEM))
	child := &ca.CA{ID: "child-1", Name: "child", Type: "intermediate", ParentCAID: rootID, Status: "active", KeyID: "k", CreatedAt: time.Now()}
	if err := e.store.Save(child); err != nil {
		t.Fatal(err)
	}
	del := func(token, query string) *httptest.ResponseRecorder {
		return e.do(token, http.MethodDelete, "/api/v1/cas/"+rootID+query, nil)
	}

	if rec := del(e.alice, ""); rec.Code != http.StatusConflict {
		t.Fatalf("removal with active child: want 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := e.store.UpdateStatus(child.ID, "revoked"); err != nil {
		t.Fatal(err)
	}

	rec := del(e.alice, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("removal propose: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	id := actionID(t, rec)
	q := "?approved_action_id=" + id
	if rec := del(e.alice, q); rec.Code != http.StatusForbidden {
		t.Fatalf("redeem before approval: want 403, got %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: want 403, got %d", rec.Code)
	}
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("approve by other admin: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := del(e.bob, q); rec.Code != http.StatusForbidden {
		t.Fatalf("redeem by non-proposer: want 403, got %d", rec.Code)
	}
	if rec := del(e.alice, q); rec.Code != http.StatusNoContent {
		t.Fatalf("redeem: want 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.engine.GetCA(rootID); got == nil || got.Status != "revoked" {
		t.Fatalf("trust anchor status = %+v, want revoked", got)
	}
	if rec := del(e.alice, q); rec.Code == http.StatusNoContent {
		t.Fatal("a grant must not be redeemable twice")
	}

	// Documented rollback: re-importing the same root reactivates it.
	rec = e.importFully(t, e.rootPEM)
	if rec.Code != http.StatusCreated || e.caID(t, rec) != rootID {
		t.Fatalf("re-import: want 201 reactivating %s, got %d: %s", rootID, rec.Code, rec.Body.String())
	}
	if got, _ := e.engine.GetCA(rootID); got.Status != "active" {
		t.Fatalf("reactivated status = %s, want active", got.Status)
	}
	for _, o := range []AuditOutcome{AuditOutcomeProposed, AuditOutcomeSuccess} {
		if !e.audited("ca.trust_anchor_remove", o) {
			t.Errorf("ca.trust_anchor_remove %s not audited", o)
		}
	}
}

func TestTrustAnchorRemovalRefusesKeyedCA(t *testing.T) {
	e := newImportEnv(t, "false")
	created, err := e.engine.CreateRootCA("own", pkix.Name{CommonName: "Own Root"}, keystore.ECDSAP256, time.Hour*24)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.do(e.alice, http.MethodDelete, "/api/v1/cas/"+created.ID, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("removing a CA that holds a key: want 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.engine.GetCA(created.ID); got.Status != "active" {
		t.Fatal("keyed CA must be untouched")
	}
}
