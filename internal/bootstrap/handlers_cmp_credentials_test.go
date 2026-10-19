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
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/cmp"
	kkdb "kryptkeeper/internal/db"
)

var cmpCredPassphrase = []byte("cmp-cred-test-passphrase")

func newCMPCredMux(t *testing.T, passphrase []byte) (*http.ServeMux, *Authenticator, *cmp.DBCredentialStore, *scepRecordingAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "cmp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil { // exercises 000183
		t.Fatalf("migrate: %v", err)
	}
	store := cmp.NewDBCredentialStore(db, false, func(s string) ([]byte, error) { return OpenSecret(cmpCredPassphrase, s) })
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	RegisterCMPCredentialHandlers(mux, auth, store, func() []byte { return passphrase }, audit)
	return mux, auth, store, audit
}

type cmpMinted struct {
	Data struct {
		ID        string `json:"id"`
		Reference string `json:"reference"`
		Secret    string `json:"secret"`
		Enforced  *bool  `json:"enforced"`
		SHA256    string `json:"cert_sha256"`
		Subject   string `json:"subject"`
	} `json:"data"`
}

func mintCMP(t *testing.T, mux *http.ServeMux, body map[string]any) cmpMinted {
	t.Helper()
	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/cmp/credentials", "test-token", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response carrying the secret must not be cached")
	}
	var m cmpMinted
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func testAnchorPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "cmp anchor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCMPCredentialSecretShownOnce(t *testing.T) {
	mux, _, store, audit := newCMPCredMux(t, cmpCredPassphrase)
	m := mintCMP(t, mux, map[string]any{"kind": "pbm", "label": "plant-7", "allowed_dns_suffixes": []string{".plant7.example"}})
	if len(m.Data.Secret) != 24 || !strings.HasPrefix(m.Data.Reference, "kk-cmp-") || len(m.Data.Reference) != len("kk-cmp-")+12 {
		t.Fatalf("minted %+v", m.Data)
	}
	// The stored secret is the one returned, and the credential store serves it.
	secret, c, ok := store.LookupPBM(t.Context(), []byte(m.Data.Reference))
	if !ok || string(secret) != m.Data.Secret || len(c.AllowedDNSSuffixes) != 1 {
		t.Fatalf("lookup: ok=%v cred=%+v", ok, c)
	}

	list := scepAPI(t, mux, http.MethodGet, "/api/v1/cmp/credentials", "test-token", nil)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), m.Data.Secret) || strings.Contains(list.Body.String(), "sealed") ||
		!strings.Contains(list.Body.String(), m.Data.Reference) {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}
	for _, e := range audit.entries {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), m.Data.Secret) {
			t.Fatalf("secret reached the audit log: %s", b)
		}
	}
	found := false
	for _, e := range audit.entries {
		if e.Action == "cmp.credential.create" && e.Outcome == AuditOutcomeSuccess && strings.Contains(e.ChangeSummary, m.Data.Reference) {
			found = true
		}
	}
	if !found {
		t.Fatal("no create audit row naming the reference")
	}
}

func TestCMPCredentialRotateAndRevoke(t *testing.T) {
	mux, _, store, _ := newCMPCredMux(t, cmpCredPassphrase)
	m := mintCMP(t, mux, map[string]any{"kind": "pbm"})
	rot := scepAPI(t, mux, http.MethodPost, "/api/v1/cmp/credentials/"+m.Data.ID+"/rotate", "test-token", nil)
	if rot.Code != http.StatusOK || rot.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("rotate: %d %s", rot.Code, rot.Body.String())
	}
	var r cmpMinted
	_ = json.Unmarshal(rot.Body.Bytes(), &r)
	if r.Data.Secret == "" || r.Data.Secret == m.Data.Secret || r.Data.Reference != m.Data.Reference {
		t.Fatalf("rotated %+v", r.Data)
	}
	if secret, _, ok := store.LookupPBM(t.Context(), []byte(m.Data.Reference)); !ok || string(secret) != r.Data.Secret {
		t.Fatal("store does not serve the rotated secret")
	}

	if del := scepAPI(t, mux, http.MethodDelete, "/api/v1/cmp/credentials/"+m.Data.ID, "test-token", nil); del.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", del.Code)
	}
	if _, _, ok := store.LookupPBM(t.Context(), []byte(m.Data.Reference)); ok {
		t.Fatal("revoked secret still served")
	}
	list := scepAPI(t, mux, http.MethodGet, "/api/v1/cmp/credentials", "test-token", nil)
	if !strings.Contains(list.Body.String(), `"revoked_at":"20`) {
		t.Fatalf("list after revoke: %s", list.Body.String())
	}
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodDelete, "/api/v1/cmp/credentials/" + m.Data.ID, http.StatusConflict},
		{http.MethodPost, "/api/v1/cmp/credentials/" + m.Data.ID + "/rotate", http.StatusConflict},
		{http.MethodDelete, "/api/v1/cmp/credentials/cmpc-nope", http.StatusNotFound},
		{http.MethodPost, "/api/v1/cmp/credentials/cmpc-nope/rotate", http.StatusNotFound},
	} {
		if rec := scepAPI(t, mux, tc.method, tc.path, "test-token", nil); rec.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

func TestCMPCredentialAnchor(t *testing.T) {
	mux, _, _, _ := newCMPCredMux(t, nil) // anchors need no passphrase
	good := testAnchorPEM(t, time.Now().Add(24*time.Hour))
	m := mintCMP(t, mux, map[string]any{"kind": "trust_anchor", "label": "root", "certificate_pem": good})
	if m.Data.Enforced == nil || *m.Data.Enforced || len(m.Data.SHA256) != 64 || m.Data.Subject == "" {
		t.Fatalf("anchor %+v", m.Data)
	}
	post := func(pemText string) int {
		return scepAPI(t, mux, http.MethodPost, "/api/v1/cmp/credentials", "test-token",
			map[string]any{"kind": "trust_anchor", "certificate_pem": pemText}).Code
	}
	if got := post(good); got != http.StatusConflict {
		t.Errorf("duplicate: %d, want 409", got)
	}
	for name, in := range map[string]string{
		"garbage": "x", "expired": testAnchorPEM(t, time.Now().Add(-time.Hour)),
		"two":  testAnchorPEM(t, time.Now().Add(time.Hour)) + testAnchorPEM(t, time.Now().Add(time.Hour)),
		"huge": good + strings.Repeat("A", 9000),
	} {
		if got := post(in); got != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, got)
		}
	}
	if rec := scepAPI(t, mux, http.MethodPost, "/api/v1/cmp/credentials/"+m.Data.ID+"/rotate", "test-token", nil); rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusBadRequest {
		t.Errorf("rotate anchor: %d", rec.Code)
	}
	list := scepAPI(t, mux, http.MethodGet, "/api/v1/cmp/credentials", "test-token", nil)
	if strings.Contains(list.Body.String(), "BEGIN CERTIFICATE") || !strings.Contains(list.Body.String(), `"enforced":false`) {
		t.Fatalf("list: %s", list.Body.String())
	}
}

func TestCMPCredentialValidation(t *testing.T) {
	mux, _, _, _ := newCMPCredMux(t, cmpCredPassphrase)
	for name, body := range map[string]map[string]any{
		"bad kind":   {"kind": "other"},
		"no kind":    {},
		"bad suffix": {"kind": "pbm", "allowed_dns_suffixes": []string{"*.example"}},
		"long label": {"kind": "pbm", "label": strings.Repeat("x", 201)},
	} {
		if rec := scepAPI(t, mux, http.MethodPost, "/api/v1/cmp/credentials", "test-token", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}
}

func TestCMPCredentialRequiresPKIAdmin(t *testing.T) {
	mux, auth, _, audit := newCMPCredMux(t, cmpCredPassphrase)
	_, opKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if rec := scepAPI(t, mux, m, "/api/v1/cmp/credentials", opKey, map[string]any{}); rec.Code != http.StatusForbidden {
			t.Errorf("%s as operator: %d, want 403", m, rec.Code)
		}
		if rec := scepAPI(t, mux, m, "/api/v1/cmp/credentials", "", map[string]any{}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d, want 401", m, rec.Code)
		}
	}
	if rec := scepAPI(t, mux, http.MethodDelete, "/api/v1/cmp/credentials/x", opKey, nil); rec.Code != http.StatusForbidden {
		t.Errorf("DELETE as operator: %d, want 403", rec.Code)
	}
	if rec := scepAPI(t, mux, http.MethodPost, "/api/v1/cmp/credentials/x/rotate", opKey, nil); rec.Code != http.StatusForbidden {
		t.Errorf("rotate as operator: %d, want 403", rec.Code)
	}
	denied := 0
	for _, e := range audit.entries {
		if e.Outcome == AuditOutcomeDenied {
			denied++
		}
	}
	if denied != 6 {
		t.Errorf("denied audit rows = %d, want 6", denied)
	}
}

func TestCMPCredentialMintNeedsPassphrase(t *testing.T) {
	mux, _, _, audit := newCMPCredMux(t, nil)
	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/cmp/credentials", "test-token", map[string]any{"kind": "pbm"})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "credential store passphrase") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if n := len(audit.entries); n == 0 || audit.entries[n-1].Outcome != AuditOutcomeFailure {
		t.Fatalf("no failure audit row: %+v", audit.entries)
	}
}
