// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// RC1-A-01: a discovery.manage principal must not be able to arm hub-side key
// egress. Roles used: discovery-operator (discovery.manage only), pki-operator
// (certificate.renew, not admin), pki-admin.
type egressFixture struct {
	mux    *http.ServeMux
	store  ManagedTargetStore
	credID string
	audit  *recordingAudit
	tokens map[string]string
}

func newEgressFixture(t *testing.T) *egressFixture {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "egress.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteManagedTargetStore{db: db}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	creds := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := creds.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	meta, err := creds.Create(t.Context(), "cred-real", "dev cluster", CredentialTypeSSHKey, "", testSSHCredentialJSON(t))
	if err != nil {
		t.Fatal(err)
	}

	f := &egressFixture{store: store, credID: meta.ID, audit: &recordingAudit{}, tokens: map[string]string{"admin": "test-token"}}
	for _, role := range []string{"discovery-operator", "pki-operator", "viewer", "mcp-agent"} {
		_, tok, err := auth.CreateAPIKey("u-"+role, "u-"+role, role, nil, "", "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		f.tokens[role] = tok
	}
	f.mux = http.NewServeMux()
	registerTargetHandlers(f.mux, auth, store, nil, f.audit, targetEgressDeps{credentials: creds})
	return f
}

func (f *egressFixture) do(method, path, role, body string) *httptest.ResponseRecorder {
	return doTargetsRequest(f.mux, method, path, f.tokens[role], body)
}

func (f *egressFixture) create(t *testing.T, role, body string, want int) ManagedTarget {
	t.Helper()
	rec := f.do(http.MethodPost, "/api/v1/targets", role, body)
	if rec.Code != want {
		t.Fatalf("%s create %s: got %d want %d: %s", role, body, rec.Code, want, rec.Body.String())
	}
	var resp struct {
		Data ManagedTarget `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.Data
}

func TestDiscoveryOperatorCannotArmKeyEgress(t *testing.T) {
	f := newEgressFixture(t)
	exploit := `{"name":"x","host":"payments.example.com","install_mode":"k8s","credential_ref":"` + f.credID + `","auto_renew":true,"renewal_threshold_days":30}`
	f.create(t, "discovery-operator", exploit, http.StatusForbidden)
	// Each lever on its own.
	f.create(t, "discovery-operator", `{"name":"x","host":"h","auto_renew":true}`, http.StatusForbidden)
	f.create(t, "discovery-operator", `{"name":"x","host":"h","credential_ref":"`+f.credID+`"}`, http.StatusForbidden)
	f.create(t, "viewer", `{"name":"x","host":"h","auto_renew":true}`, http.StatusForbidden)
	f.create(t, "mcp-agent", `{"name":"x","host":"h","auto_renew":true}`, http.StatusForbidden)

	denied := 0
	for _, e := range f.audit.events {
		if e == "target.create:denied" {
			denied++
		}
	}
	if denied != 5 {
		t.Fatalf("refusals not audited: %v", f.audit.events)
	}
	if items, _ := f.store.List(t.Context()); len(items) != 0 {
		t.Fatalf("a refused request created %d target(s)", len(items))
	}

	// Plain discovery work still works, and cannot be turned into egress later.
	tgt := f.create(t, "discovery-operator", `{"name":"web","host":"payments.example.com","discovery_mode":"network"}`, http.StatusCreated)
	if tgt.AutoRenewSetBy != "" {
		t.Fatalf("unarmed target stamped: %+v", tgt)
	}
	for _, patch := range []string{
		`{"auto_renew":true}`,
		`{"credential_ref":"` + f.credID + `"}`,
		`{"plugin_id":"p","install_mode":"plugin"}`,
	} {
		if rec := f.do(http.MethodPatch, "/api/v1/targets/"+tgt.ID, "discovery-operator", patch); rec.Code != http.StatusForbidden {
			t.Fatalf("PATCH %s by discovery-operator: got %d: %s", patch, rec.Code, rec.Body.String())
		}
	}
	if rec := f.do(http.MethodPatch, "/api/v1/targets/"+tgt.ID, "discovery-operator", `{"name":"renamed","renewal_threshold_days":14}`); rec.Code != http.StatusOK {
		t.Fatalf("harmless PATCH refused: %d %s", rec.Code, rec.Body.String())
	}
}

func TestArmingStampsTheAuthorizedPrincipalAndPinsTheBinding(t *testing.T) {
	f := newEgressFixture(t)

	// certificate.renew arms auto_renew; naming a credential is admin-only.
	f.create(t, "pki-operator", `{"name":"op","host":"a.example.com","install_mode":"ssh","credential_ref":"`+f.credID+`","auto_renew":true}`, http.StatusForbidden)
	armed := f.create(t, "pki-operator", `{"name":"op","host":"a.example.com","install_mode":"ssh","auto_renew":true}`, http.StatusCreated)
	if !strings.HasPrefix(armed.AutoRenewSetBy, "key:") {
		t.Fatalf("AutoRenewSetBy = %q", armed.AutoRenewSetBy)
	}
	adminArmed := f.create(t, "admin", `{"name":"adm","host":"b.example.com","install_mode":"ssh","credential_ref":"`+f.credID+`","auto_renew":true}`, http.StatusCreated)
	if adminArmed.AutoRenewSetBy == "" {
		t.Fatal("admin-armed target not stamped")
	}

	// The stamp cannot be forged from the request body.
	forged := f.create(t, "admin", `{"name":"f","host":"c.example.com","auto_renew_set_by":"someone"}`, http.StatusCreated)
	if forged.AutoRenewSetBy != "" {
		t.Fatalf("body-supplied auto_renew_set_by accepted: %q", forged.AutoRenewSetBy)
	}

	// Re-aiming an armed target (the exploit with a PATCH) is refused.
	for _, patch := range []string{`{"host":"payments.example.com"}`, `{"install_mode":"k8s"}`, `{"install_key_path":"/etc/x"}`, `{"verify_host_port":"10.0.0.1:443"}`, `{"credential_ref":"cred-other"}`} {
		if rec := f.do(http.MethodPatch, "/api/v1/targets/"+adminArmed.ID, "discovery-operator", patch); rec.Code != http.StatusForbidden {
			t.Fatalf("PATCH %s on an armed target by discovery-operator: %d %s", patch, rec.Code, rec.Body.String())
		}
	}
	// ...but a no-op re-save of auto_renew=true is harmless and does not re-stamp.
	rec := f.do(http.MethodPatch, "/api/v1/targets/"+adminArmed.ID, "discovery-operator", `{"auto_renew":true,"name":"adm2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("no-op auto_renew re-save: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Data ManagedTarget `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Data.AutoRenewSetBy != adminArmed.AutoRenewSetBy {
		t.Fatalf("a non-renewer re-stamped the target: %q", got.Data.AutoRenewSetBy)
	}
	// A renewer may move the host and is recorded as the one who did.
	rec = f.do(http.MethodPatch, "/api/v1/targets/"+adminArmed.ID, "pki-operator", `{"host":"d.example.com"}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || !strings.HasPrefix(got.Data.AutoRenewSetBy, "key:") || got.Data.AutoRenewSetBy == adminArmed.AutoRenewSetBy {
		t.Fatalf("renewer host change: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTargetReferencesMustExist(t *testing.T) {
	f := newEgressFixture(t)
	f.create(t, "admin", `{"name":"x","host":"h","install_mode":"ssh","credential_ref":"cred-doesnotexist","auto_renew":true}`, http.StatusBadRequest)
	f.create(t, "admin", `{"name":"x","host":"h","install_mode":"plugin","plugin_id":"ghost"}`, http.StatusBadRequest)
	f.create(t, "admin", `{"name":"x","host":"h","install_mode":"ssh","credential_ref":"`+f.credID+`"}`, http.StatusCreated)
	// Existing-but-unchanged references are not re-validated on unrelated PATCHes.
	tgt := f.create(t, "admin", `{"name":"y","host":"h2","install_mode":"ssh","credential_ref":"`+f.credID+`"}`, http.StatusCreated)
	if rec := f.do(http.MethodPatch, "/api/v1/targets/"+tgt.ID, "admin", `{"credential_ref":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH to unknown credential: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTargetThresholdAndVerifyHostPortRejectedOverHTTP(t *testing.T) {
	f := newEgressFixture(t)
	f.create(t, "admin", `{"name":"x","host":"h","renewal_threshold_days":3650}`, http.StatusBadRequest)
	f.create(t, "admin", `{"name":"x","host":"h","verify_host_port":"169.254.169.254:80"}`, http.StatusBadRequest)
	f.create(t, "admin", `{"name":"x","host":"h","verify_host_port":"localhost:443"}`, http.StatusBadRequest)
}

// The scheduler refuses an auto_renew target nobody authorized, whatever the
// row says: a row written before the stamp existed, or straight into the DB.
func TestSchedulerSkipsAutoRenewTargetWithoutAuthorizedStamp(t *testing.T) {
	armed := ManagedTarget{Name: "a", Host: "a.example.com", InstallMode: "keychain", AutoRenew: true, CredentialRef: "c", AutoRenewSetBy: "admin-1"}
	unstamped := ManagedTarget{Name: "u", Host: "u.example.com", InstallMode: "keychain", AutoRenew: true, CredentialRef: "c"}
	got := autoRenewTargetsByHost([]ManagedTarget{armed, unstamped})
	if _, ok := got["a.example.com"]; !ok || len(got) != 1 {
		t.Fatalf("eligible targets = %v", got)
	}
	if !strings.Contains(autoRenewSkipReason(unstamped), "certificate.renew") {
		t.Fatalf("skip reason does not say how to fix it: %q", autoRenewSkipReason(unstamped))
	}
}
