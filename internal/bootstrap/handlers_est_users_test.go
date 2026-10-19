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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/est"
	"kryptkeeper/internal/keystore"
)

type estUserEnv struct {
	mux      *http.ServeMux
	auth     *Authenticator
	store    *est.DBUserStore
	audit    *scepRecordingAudit
	estSrv   *est.Server
	estHTTP  *httptest.Server
	fileUser map[string]bool
}

func newESTUserEnv(t *testing.T) *estUserEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "est.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	e := &estUserEnv{auth: auth, store: est.NewDBUserStore(db, false), audit: &scepRecordingAudit{}, fileUser: map[string]bool{"filed": true}}
	e.mux = http.NewServeMux()
	RegisterESTUserHandlers(e.mux, auth, e.store, func(n string) bool { return e.fileUser[n] }, e.audit)

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("est-users-test-passphrase-32byte"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "EST Users Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	e.estSrv = est.NewServer(engine, root.ID).WithUserSource(e.store)
	e.estHTTP = httptest.NewTLSServer(e.estSrv.Handler())
	t.Cleanup(e.estHTTP.Close)
	return e
}

// enroll returns the status of a simpleenroll for a.devices.example.com.
func (e *estUserEnv) enroll(t *testing.T, user, pass string) int {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.devices.example.com"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, e.estHTTP.URL+"/.well-known/est/simpleenroll", strings.NewReader(base64.StdEncoding.EncodeToString(der)))
	req.SetBasicAuth(user, pass)
	resp, err := e.estHTTP.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

type estUserBody struct {
	Data struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Suffixes []string `json:"allowed_dns_suffixes"`
	} `json:"data"`
}

func (e *estUserEnv) create(t *testing.T, name string) estUserBody {
	t.Helper()
	rec := scepAPI(t, e.mux, http.MethodPost, "/api/v1/est/users", "test-token",
		map[string]any{"username": name, "allowed_dns_suffixes": []string{".Devices.Example.com"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response carrying the password must not be cached")
	}
	var b estUserBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestESTUserCreateShowsPasswordOnceAndNeverLeaks(t *testing.T) {
	e := newESTUserEnv(t)
	b := e.create(t, "line-3")
	if len(b.Data.Password) != 24 || b.Data.Suffixes[0] != ".devices.example.com" {
		t.Fatalf("created %+v", b.Data)
	}
	if got := e.enroll(t, "line-3", b.Data.Password); got != http.StatusOK {
		t.Fatalf("the generated password does not enroll: %d", got)
	}

	for _, path := range []string{"/api/v1/est/users", "/api/v1/est/users/line-3"} {
		rec := scepAPI(t, e.mux, http.MethodGet, path, "test-token", nil)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "line-3") {
			t.Fatalf("%s: %d %s", path, rec.Code, body)
		}
		if strings.Contains(body, b.Data.Password) || strings.Contains(body, "$2") || strings.Contains(body, "hash") {
			t.Fatalf("%s leaks a credential: %s", path, body)
		}
	}
	for _, en := range e.audit.entries {
		if strings.Contains(en.ChangeSummary, b.Data.Password) || strings.Contains(en.ChangeSummary, "$2") {
			t.Fatalf("credential reached the audit log: %+v", en)
		}
	}
	if last := e.audit.entries[len(e.audit.entries)-1]; last.Action != "est.user.create" || last.ResourceType != "est_user" || last.ResourceID != "line-3" || last.Outcome != AuditOutcomeSuccess {
		t.Fatalf("audit %+v", last)
	}
}

func TestESTUserRotateInvalidatesOldPassword(t *testing.T) {
	e := newESTUserEnv(t)
	old := e.create(t, "rot").Data.Password
	rec := scepAPI(t, e.mux, http.MethodPost, "/api/v1/est/users/rot/rotate", "test-token", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	var b estUserBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if b.Data.Password == "" || b.Data.Password == old {
		t.Fatal("rotate returned no new password")
	}
	if got := e.enroll(t, "rot", old); got != http.StatusUnauthorized {
		t.Fatalf("old password after rotate: %d", got)
	}
	if got := e.enroll(t, "rot", b.Data.Password); got != http.StatusOK {
		t.Fatalf("new password: %d", got)
	}
	if rec := scepAPI(t, e.mux, http.MethodPost, "/api/v1/est/users/nobody/rotate", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("rotate unknown: %d", rec.Code)
	}
}

func TestESTUserDisableBlocksEnrollmentAndDeleteRemoves(t *testing.T) {
	e := newESTUserEnv(t)
	pw := e.create(t, "dis").Data.Password
	rec := scepAPI(t, e.mux, http.MethodPatch, "/api/v1/est/users/dis", "test-token", map[string]any{"disabled": true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"disabled":true`) {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	if got := e.enroll(t, "dis", pw); got != http.StatusUnauthorized {
		t.Fatalf("disabled user enrolled: %d", got)
	}
	scepAPI(t, e.mux, http.MethodPatch, "/api/v1/est/users/dis", "test-token", map[string]any{"disabled": false})
	if got := e.enroll(t, "dis", pw); got != http.StatusOK {
		t.Fatalf("re-enabled user: %d", got)
	}
	if rec := scepAPI(t, e.mux, http.MethodDelete, "/api/v1/est/users/dis", "test-token", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if got := e.enroll(t, "dis", pw); got != http.StatusUnauthorized {
		t.Fatalf("deleted user enrolled: %d", got)
	}
	if rec := scepAPI(t, e.mux, http.MethodDelete, "/api/v1/est/users/dis", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete again: %d", rec.Code)
	}
}

func TestESTUserAPIRefusals(t *testing.T) {
	e := newESTUserEnv(t)
	_, operatorKey, err := e.auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.create(t, "dup")
	good := []string{".devices.example.com"}
	for _, tc := range []struct {
		name, token string
		body        map[string]any
		want        int
	}{
		{"anonymous", "", map[string]any{"username": "x", "allowed_dns_suffixes": good}, http.StatusUnauthorized},
		{"operator", operatorKey, map[string]any{"username": "x", "allowed_dns_suffixes": good}, http.StatusForbidden},
		{"colon in username", "test-token", map[string]any{"username": "a:b", "allowed_dns_suffixes": good}, http.StatusBadRequest},
		{"empty username", "test-token", map[string]any{"allowed_dns_suffixes": good}, http.StatusBadRequest},
		{"no suffixes", "test-token", map[string]any{"username": "x"}, http.StatusBadRequest},
		{"bad suffix", "test-token", map[string]any{"username": "x", "allowed_dns_suffixes": []string{"nodot.example.com"}}, http.StatusBadRequest},
		{"too many suffixes", "test-token", map[string]any{"username": "x", "allowed_dns_suffixes": manySuffixes(21)}, http.StatusBadRequest},
		{"duplicate", "test-token", map[string]any{"username": "dup", "allowed_dns_suffixes": good}, http.StatusConflict},
		{"clashes with users file", "test-token", map[string]any{"username": "filed", "allowed_dns_suffixes": good}, http.StatusConflict},
	} {
		if rec := scepAPI(t, e.mux, http.MethodPost, "/api/v1/est/users", tc.token, tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
	if rec := scepAPI(t, e.mux, http.MethodPatch, "/api/v1/est/users/dup", "test-token", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Errorf("empty patch: %d", rec.Code)
	}
	if rec := scepAPI(t, e.mux, http.MethodGet, "/api/v1/est/users/nobody", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Errorf("get unknown: %d", rec.Code)
	}
}

func TestESTUserListFlagsFileShadowedUsers(t *testing.T) {
	e := newESTUserEnv(t)
	e.create(t, "plain")
	e.create(t, "shadow")
	e.fileUser["shadow"] = true // defined in the file after it was stored
	rec := scepAPI(t, e.mux, http.MethodGet, "/api/v1/est/users", "test-token", nil)
	var out struct {
		Data []struct {
			Username string `json:"username"`
			Shadowed bool   `json:"shadowed_by_file"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	got := map[string]bool{}
	for _, u := range out.Data {
		got[u.Username] = u.Shadowed
	}
	if len(got) != 2 || got["plain"] || !got["shadow"] {
		t.Fatalf("%v", got)
	}
}

func manySuffixes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "." + strings.Repeat("a", i+1) + ".example.com"
	}
	return out
}
