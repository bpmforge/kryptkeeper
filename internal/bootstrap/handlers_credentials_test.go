// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"kryptkeeper/internal/agentdiscovery"
)

// The properties a credential API must not lose: plaintext goes in and
// NEVER comes back out, and only admins touch it at all.

func credentialsTestMux(t *testing.T) (*http.ServeMux, *sqliteOutboundCredentialStore) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "credentials-handler.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, newReportsTestAuth(t), store, stubAuditProvider{}, nil)
	return mux, store
}

func TestCredentialCreateNeverEchoesTheSecret(t *testing.T) {
	mux, store := credentialsTestMux(t)
	secret := "-----BEGIN OPENSSH PRIVATE KEY-----\nsuper-secret-material\n-----END" // secret-scan:allow fake fixture
	body, _ := json.Marshal(map[string]any{
		"name":            "prod fleet ssh",
		"credential_type": "ssh_key",
		"payload":         map[string]string{"user": "root", "private_key_pem": secret},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	// The one property that must hold above all others.
	if strings.Contains(rec.Body.String(), "super-secret-material") {
		t.Fatal("the create response echoed the secret payload")
	}
	var resp struct{ Data OutboundCredentialMeta }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.ID == "" || resp.Data.CredentialType != "ssh_key" {
		t.Fatalf("metadata wrong: %+v", resp.Data)
	}
	// And the stored material must be the real thing, resolvable internally.
	got, err := store.Resolve(context.Background(), resp.Data.ID)
	if err != nil || !strings.Contains(string(got), "super-secret-material") {
		t.Fatalf("stored payload wrong: %v %s", err, got)
	}
	// List: metadata only, no secret.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/credentials", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "super-secret-material") {
		t.Fatalf("list leaked or failed: %d", rec.Code)
	}
}

func TestCredentialWindowsPasswordRoundTripsThroughTheAPI(t *testing.T) {
	mux, store := credentialsTestMux(t)
	body, _ := json.Marshal(map[string]any{
		"name":            "iis-web-01 winrm",
		"credential_type": "windows_password",
		"payload": map[string]string{
			"base_url": "https://iis-web-01.corp.example.com:5986/wsman",
			"username": "CORP\\svc-pki", "password": "s3cret", "ipport": "0.0.0.0:443",
		},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("windows_password must be creatable over the API: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data OutboundCredentialMeta }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := store.Resolve(context.Background(), resp.Data.ID)
	var payload struct {
		BaseURL string `json:"base_url"`
		IPPort  string `json:"ipport"`
	}
	if err := json.Unmarshal(got, &payload); err != nil || payload.BaseURL == "" || payload.IPPort == "" {
		t.Fatalf("payload did not survive: %v %s", err, got)
	}
}

func TestCredentialRejectsUnknownTypeAndBadBody(t *testing.T) {
	mux, _ := credentialsTestMux(t)
	body, _ := json.Marshal(map[string]any{
		"name": "x", "credential_type": "carrier_pigeon", "payload": map[string]string{"a": "b"},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown type must be refused, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", []byte(`{"name":"x"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing payload must be refused, got %d", rec.Code)
	}
}

func TestCredentialDeleteAndAuth(t *testing.T) {
	mux, store := credentialsTestMux(t)
	meta, err := store.Create(context.Background(), "cred-del", "doomed", CredentialTypeAPIToken, "", []byte(`{}`))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodDelete, "/api/v1/credentials/"+meta.ID, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodDelete, "/api/v1/credentials/"+meta.ID, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("double delete must 404, got %d", rec.Code)
	}
	// Unauthenticated is refused everywhere.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/credentials", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// An unconfigured store must explain itself, not 500 or NPE.
func TestCredentialUnconfiguredStoreNames503(t *testing.T) {
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, newReportsTestAuth(t), nil, stubAuditProvider{}, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/credentials", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "APP_CREDENTIAL_STORE_PASSPHRASE") {
		t.Fatalf("must 503 naming the config, got %d: %s", rec.Code, rec.Body.String())
	}
}

// W18-11: the preflight says what the credential can do, resolves the
// secret only inside the process, and never echoes it.
func TestCredentialPreflightReportsLevelWithoutLeakingSecret(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "preflight.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	_ = store.EnsureSchema(context.Background())
	var seen agentdiscovery.WinRMConfig
	fake := func(_ context.Context, cfg agentdiscovery.WinRMConfig) agentdiscovery.WinRMPreflight {
		seen = cfg
		return agentdiscovery.WinRMPreflight{Level: agentdiscovery.PreflightDiscover, CanDiscover: true, Detail: "standard token"}
	}
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, newReportsTestAuth(t), store, stubAuditProvider{}, fake)

	win, _ := store.Create(context.Background(), "cred-win", "iis", CredentialTypeWindowsPassword, "",
		[]byte(`{"base_url":"https://iis:5986/wsman","username":"kktest","password":"hunter2-secret"}`))
	tok, _ := store.Create(context.Background(), "cred-tok", "f5", CredentialTypeAPIToken, "", []byte(`{"token":"t"}`))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials/"+win.ID+"/preflight", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatal("the preflight response echoed the password")
	}
	var resp struct {
		Data struct {
			CredentialID string `json:"credential_id"`
			Level        string `json:"level"`
			CanDiscover  bool   `json:"can_discover"`
			CanInstall   bool   `json:"can_install"`
		}
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Level != "discover" || !resp.Data.CanDiscover || resp.Data.CanInstall || resp.Data.CredentialID != win.ID {
		t.Fatalf("verdict wrong: %+v", resp.Data)
	}
	if seen.EndpointURL != "https://iis:5986/wsman" || seen.Username != "kktest" || seen.Password != "hunter2-secret" {
		t.Fatalf("the probe did not receive the resolved credential: %+v", seen)
	}

	// Only windows_password credentials have a WinRM preflight.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials/"+tok.ID+"/preflight", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("api_token preflight must be 400, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials/nope/preflight", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id must be 404, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/credentials/"+win.ID+"/preflight", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated must be 401, got %d", rec.Code)
	}
}

func postSSHCredential(t *testing.T, mux *http.ServeMux, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": "kkscan", "credential_type": "ssh_key", "payload": payload})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", body))
	return rec
}

// W34-14: the sudo_* combination is validated at create time.
func TestCredentialSSHPrivilegeValidation(t *testing.T) {
	mux, _ := credentialsTestMux(t)
	sha := strings.Repeat("ab", 32)
	base := func(extra map[string]any) map[string]any {
		p := map[string]any{"user": "kkscan", "private_key_pem": "fake"} // secret-scan:allow fake fixture
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	cases := []struct {
		name  string
		extra map[string]any
		want  int
	}{
		{"default none", nil, http.StatusCreated},
		{"explicit none", map[string]any{"sudo_mode": "none"}, http.StatusCreated},
		{"nopasswd", map[string]any{"sudo_mode": "nopasswd"}, http.StatusCreated},
		{"password ok", map[string]any{"sudo_mode": "password", "sudo_password": "pw-1"}, http.StatusCreated},
		{"helper ok", map[string]any{"sudo_mode": "helper", "helper_sha256": sha}, http.StatusCreated},
		{"password missing", map[string]any{"sudo_mode": "password"}, http.StatusBadRequest},
		{"password with nopasswd", map[string]any{"sudo_mode": "nopasswd", "sudo_password": "pw-1"}, http.StatusBadRequest},
		{"password without mode", map[string]any{"sudo_password": "pw-1"}, http.StatusBadRequest},
		{"helper missing sha", map[string]any{"sudo_mode": "helper"}, http.StatusBadRequest},
		{"helper bad sha", map[string]any{"sudo_mode": "helper", "helper_sha256": "xyz"}, http.StatusBadRequest},
		{"sha with password mode", map[string]any{"sudo_mode": "password", "sudo_password": "pw-1", "helper_sha256": sha}, http.StatusBadRequest},
		{"unknown mode", map[string]any{"sudo_mode": "root"}, http.StatusBadRequest},
	}
	for _, c := range cases {
		rec := postSSHCredential(t, mux, base(c.extra))
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.want, rec.Body.String())
		}
		if rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), "pw-1") {
			t.Errorf("%s: error echoed the password", c.name)
		}
	}
	// The check is specific to ssh_key.
	body, _ := json.Marshal(map[string]any{"name": "api", "credential_type": "api_token", "payload": map[string]any{"sudo_mode": "password"}})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("api_token payloads are not validated as ssh: %d", rec.Code)
	}
}

// The sudo password is encrypted at rest and never in a response, a list, or
// an audit row.
func TestCredentialSudoPasswordNeverLeaks(t *testing.T) {
	const pw = "Sudo-Pw-Marker-7731"
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "cred-sudo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	audit := &sshRecordingAudit{}
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, newReportsTestAuth(t), store, audit, nil)

	rec := postSSHCredential(t, mux, map[string]any{"user": "kkscan", "private_key_pem": "fake", "sudo_mode": "password", "sudo_password": pw}) // secret-scan:allow fake fixture
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data OutboundCredentialMeta }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	bad := postSSHCredential(t, mux, map[string]any{"user": "kkscan", "sudo_mode": "password"})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", bad.Code)
	}
	list := httptest.NewRecorder()
	mux.ServeHTTP(list, authedReq(http.MethodGet, "/api/v1/credentials", nil))

	for name, text := range map[string]string{"create": rec.Body.String(), "list": list.Body.String(), "reject": bad.Body.String()} {
		if strings.Contains(text, pw) {
			t.Errorf("%s response leaked the sudo password", name)
		}
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.entries) == 0 {
		t.Fatal("expected audit entries")
	}
	for _, e := range audit.entries {
		if b, _ := json.Marshal(e); strings.Contains(string(b), pw) {
			t.Errorf("audit entry leaked the sudo password: %s", b)
		}
	}
	var onDisk string
	if err := db.QueryRow(`SELECT envelope FROM outbound_credentials WHERE id = ?`, resp.Data.ID).Scan(&onDisk); err != nil {
		t.Fatalf("read stored row: %v", err)
	}
	if strings.Contains(onDisk, pw) {
		t.Fatal("sudo password stored in plaintext")
	}
	got, err := store.Resolve(context.Background(), resp.Data.ID)
	if err != nil || !strings.Contains(string(got), pw) {
		t.Fatalf("stored payload must round-trip internally: %v", err)
	}
}

func TestCredentialPrivilegedManualFlagIsAuditedAndListed(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "priv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), "cred-1", "ops", CredentialTypeSSHKey, "", []byte(`{"user":"deploy"}`)); err != nil {
		t.Fatal(err)
	}
	audit := &sshRecordingAudit{}
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, newReportsTestAuth(t), store, audit, nil)

	put := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedReq(http.MethodPut, path, []byte(body)))
		return rec
	}
	if rec := put("/api/v1/credentials/cred-1/privileged", `{"privileged":true,"reason":"owns the host"}`); rec.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rec.Code, rec.Body)
	}
	m, _ := store.Get(context.Background(), "cred-1")
	if !m.Privileged || m.PrivilegedReason != "owns the host" || !strings.HasPrefix(m.PrivilegedSetBy, "manual:") || m.PrivilegedSetAt == "" {
		t.Fatalf("stored: %+v", m)
	}
	var found bool
	for _, e := range audit.entries {
		if e.Action == "credential.privileged.set" && e.Outcome == AuditOutcomeSuccess && strings.Contains(e.ChangeSummary, `"source":"manual"`) && strings.Contains(e.ChangeSummary, "owns the host") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit row: %+v", audit.entries)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/credentials", nil))
	if !strings.Contains(rec.Body.String(), `"privileged":true`) {
		t.Fatalf("list lacks the flag: %s", rec.Body)
	}

	if rec := put("/api/v1/credentials/cred-1/privileged", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing privileged: %d", rec.Code)
	}
	if rec := put("/api/v1/credentials/nope/privileged", `{"privileged":true}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", rec.Code)
	}
	if rec := put("/api/v1/credentials/cred-1/privileged", `{"privileged":false}`); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d", rec.Code)
	}
	m, _ = store.Get(context.Background(), "cred-1")
	if m.Privileged || m.PrivilegedReason != "" || m.PrivilegedSetBy != "" {
		t.Fatalf("clearing must clear reason and actor: %+v", m)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/credentials/cred-1/privileged", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
}

func TestPrivilegedCredentialsSummaryScopedToTenantAndHosts(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	targets, creds := winrmTestStores(t)
	ctx := context.Background()
	for _, c := range []struct{ id, tenant string }{{"c-a", "tenant-a"}, {"c-b", "tenant-b"}, {"c-plain", "tenant-a"}} {
		if _, err := creds.Create(ctx, c.id, c.id, CredentialTypeSSHKey, c.tenant, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	_ = creds.SetPrivileged(ctx, "c-a", true, "uid 0", "auto:preflight")
	_ = creds.SetPrivileged(ctx, "c-b", true, "x", "manual:u1")
	for i, host := range []string{"h2", "h1"} {
		if _, err := targets.Create(ctx, ManagedTarget{ID: fmt.Sprintf("t%d", i), Name: host, Host: host, DiscoveryMode: "network",
			InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "c-a", Tenant: "tenant-a"}); err != nil {
			t.Fatal(err)
		}
	}
	got := buildPrivilegedCredentialsSummary(ctx, AuthPrincipal{Tenant: "tenant-a"}, creds, targets)
	if got == nil || got.Count != 1 || got.HostCount != 2 || got.Credentials[0].ID != "c-a" ||
		got.Credentials[0].Source != "auto" || strings.Join(got.Credentials[0].Hosts, ",") != "h1,h2" {
		t.Fatalf("%+v", got)
	}
	if buildPrivilegedCredentialsSummary(ctx, AuthPrincipal{}, nil, targets) != nil {
		t.Fatal("no credential store: section omitted")
	}
}

func TestPostgresCredentialPrivilegedRoundTrip(t *testing.T) {
	db, err := sql.Open("pgx", freshPostgresForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &postgresOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	ctx := context.Background()
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "c1", "ops", CredentialTypeSSHKey, "", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPrivileged(ctx, "c1", true, "uid 0", "auto:preflight"); err != nil {
		t.Fatal(err)
	}
	m, err := store.Get(ctx, "c1")
	if err != nil || !m.Privileged || m.PrivilegedReason != "uid 0" || m.PrivilegedSetAt == "" {
		t.Fatalf("%+v %v", m, err)
	}
	if err := store.SetPrivileged(ctx, "nope", true, "x", "y"); err == nil {
		t.Fatal("unknown id must fail")
	}
}
