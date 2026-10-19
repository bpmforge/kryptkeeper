// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keyinventory"
	"kryptkeeper/internal/sshkeys"
)

// W17-03: the W15-01 cloud key inventory, wired. Sources are injected
// through the newKeyInventorySources package var (the cloud_discovery
// precedent) so these run with no cloud credentials.

type fakeKeySource struct {
	provider string
	keys     []keyinventory.Key
	err      error
}

func (f fakeKeySource) Provider() string { return f.provider }
func (f fakeKeySource) ListKeys(context.Context) ([]keyinventory.Key, error) {
	return f.keys, f.err
}

func withKeySources(t *testing.T, sources ...keyinventory.KeySource) {
	t.Helper()
	prev := newKeyInventorySources
	newKeyInventorySources = func(context.Context) []keyinventory.KeySource { return sources }
	t.Cleanup(func() { newKeyInventorySources = prev })
}

func keyInventoryMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerKeyInventoryHandler(mux, newReportsTestAuth(t), nil, stubAuditProvider{}, nil)
	return mux
}

func TestKeyInventoryAggregatesAcrossProviders(t *testing.T) {
	withKeySources(t,
		fakeKeySource{provider: "aws-kms", keys: []keyinventory.Key{
			{Provider: "aws-kms", KeyID: "arn:aws:kms:k1", Algorithm: "RSA_2048", PQCReadiness: "vulnerable"},
		}},
		fakeKeySource{provider: "gcp-kms", keys: []keyinventory.Key{
			{Provider: "gcp-kms", KeyID: "projects/p/k2", Algorithm: "ML-DSA-65", PQCReadiness: "quantum_safe"},
		}},
	)
	rec := httptest.NewRecorder()
	keyInventoryMux(t).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/inventory/keys", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Total  int                `json:"total"`
			PQC    map[string]int     `json:"pqc_summary"`
			Keys   []keyinventory.Key `json:"keys"`
			Errors []string           `json:"errors"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Total != 2 || len(resp.Data.Keys) != 2 {
		t.Fatalf("expected 2 keys across providers: %+v", resp.Data)
	}
	// PQC readiness is the point of this inventory, so it must be summarized.
	if resp.Data.PQC["vulnerable"] != 1 || resp.Data.PQC["quantum_safe"] != 1 {
		t.Fatalf("pqc summary wrong: %+v", resp.Data.PQC)
	}
}

// A dead provider must degrade, never sink the others — the read-only
// contract Collect() already guarantees, preserved through the handler.
func TestKeyInventoryProviderFailureIsPartialNotFatal(t *testing.T) {
	withKeySources(t,
		fakeKeySource{provider: "aws-kms", keys: []keyinventory.Key{{Provider: "aws-kms", KeyID: "k1", PQCReadiness: "vulnerable"}}},
		fakeKeySource{provider: "azure-kv", err: errors.New("vault unreachable")},
	)
	rec := httptest.NewRecorder()
	keyInventoryMux(t).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/inventory/keys", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("a single dead provider must not fail the request, got %d", rec.Code)
	}
	var resp struct {
		Data struct {
			Total  int      `json:"total"`
			Errors []string `json:"errors"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Total != 1 {
		t.Fatalf("the healthy provider's keys must still be returned: %+v", resp.Data)
	}
	if len(resp.Data.Errors) != 1 {
		t.Fatalf("the failure must be reported, not swallowed: %+v", resp.Data.Errors)
	}
}

func TestKeyInventoryRequiresAuth(t *testing.T) {
	withKeySources(t, fakeKeySource{provider: "aws-kms"})
	rec := httptest.NewRecorder()
	keyInventoryMux(t).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/inventory/keys", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// CLOUD-001: authentication alone must not reach the cloud accounts.
func TestKeyInventoryPermissionGate(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth := NewAuthenticatorFromEnv()
	roles, _ := newCustomRoleStore(t)
	if _, err := roles.CreateRole(CustomRole{Name: "cert-only", Permissions: []string{"certificate.read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := roles.CreateRole(CustomRole{Name: "key-mgr", Permissions: []string{"key.manage"}}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerKeyInventoryHandler(mux, auth, roles, stubAuditProvider{}, nil)
	withKeySources(t, fakeKeySource{provider: "aws-kms"})

	cases := []struct {
		role string
		want int
	}{
		{"viewer", http.StatusOK},
		{"pki-viewer", http.StatusOK},
		{"auditor", http.StatusOK},
		{"pki-admin", http.StatusOK},
		{"key-mgr", http.StatusOK},
		{RoleMCPAgent, http.StatusForbidden},
		{"cert-only", http.StatusForbidden},
		{"service-account", http.StatusForbidden},
	}
	for _, c := range cases {
		_, tok, err := auth.CreateAPIKey("k-"+c.role, "p-"+c.role, c.role, nil, "", "", time.Now())
		if err != nil {
			t.Fatalf("%s: %v", c.role, err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/inventory/keys", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("role %s: got %d, want %d: %s", c.role, rec.Code, c.want, rec.Body.String())
		}
	}
}

// CLOUD-001: raw SDK errors carry ARNs and account ids; the client gets the
// provider name only.
func TestKeyInventoryErrorsAreGeneric(t *testing.T) {
	const raw = "operation error KMS: ListKeys, AccessDeniedException: User: arn:aws:sts::123456789012:assumed-role/hub/i-0abc is not authorized"
	withKeySources(t, fakeKeySource{provider: "aws-kms", err: errors.New(raw)})
	rec := httptest.NewRecorder()
	keyInventoryMux(t).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/inventory/keys", nil))
	body := rec.Body.String()
	if strings.Contains(body, "arn:aws") || strings.Contains(body, "123456789012") {
		t.Fatalf("cloud identifiers leaked to the client: %s", body)
	}
	if !strings.Contains(body, "cloud key inventory unavailable: aws-kms") {
		t.Fatalf("expected generic provider error, got %s", body)
	}
}

// W24-33: SSH host/user keys join the cloud keys; a hung provider is bounded.

type sshEndpointsDiscovery struct {
	DiscoveryProvider
	eps []DiscoveryEndpoint
}

func (d sshEndpointsDiscovery) ListEndpoints(_ context.Context, q DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	return DiscoveryEndpointResult{Endpoints: d.eps}, nil
}

type keyInvBody struct {
	Data struct {
		Total     int                `json:"total"`
		Providers []string           `json:"providers"`
		Keys      []keyinventory.Key `json:"keys"`
		Errors    []string           `json:"errors"`
	} `json:"data"`
}

func withSSHUserInventory(t *testing.T, inv *sshkeys.Inventory) {
	t.Helper()
	prev := sshUserKeyInventory
	sshUserKeyInventory = inv
	t.Cleanup(func() { sshUserKeyInventory = prev })
}

func TestKeyInventoryIncludesSSHHostAndUserKeys(t *testing.T) {
	withKeySources(t, fakeKeySource{provider: "aws-kms", keys: []keyinventory.Key{{Provider: "aws-kms", KeyID: "k1", PQCReadiness: "vulnerable"}}})
	inv := sshkeys.NewInventory()
	inv.Add(sshkeys.SSHKey{Fingerprint: "SHA256:u1", KeyType: sshkeys.RSA, BitSize: 2048, Host: "h2", IsAuthorized: true})
	withSSHUserInventory(t, inv)
	disc := sshEndpointsDiscovery{eps: []DiscoveryEndpoint{
		{Hostname: "h1", Port: 22, Protocol: "ssh", SSHHostKeyAlgorithms: []string{"ssh-ed25519", "ssh-rsa"}},
		{Hostname: "h3", Port: 22, Protocol: "ssh"},
	}}
	mux := http.NewServeMux()
	registerKeyInventoryHandler(mux, newReportsTestAuth(t), nil, stubAuditProvider{}, disc)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/inventory/keys", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	var resp keyInvBody
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Total != 4 || strings.Join(resp.Data.Providers, ",") != "aws-kms,ssh-host,ssh-user" {
		t.Fatalf("unexpected: %+v", resp.Data)
	}
	var user *keyinventory.Key
	hosts := 0
	for i, k := range resp.Data.Keys {
		switch k.Provider {
		case "ssh-user":
			user = &resp.Data.Keys[i]
		case "ssh-host":
			hosts++
			if k.KeyType != "host" {
				t.Errorf("host key_type %q", k.KeyType)
			}
		}
	}
	if hosts != 2 || user == nil || user.KeyType != "user" || user.Algorithm != "RSA_2048" || !user.Stale {
		t.Fatalf("rows wrong: hosts=%d user=%+v", hosts, user)
	}
}

func TestKeyInventoryPartialOutageWithin5s(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	withKeySources(t,
		hungKeySource{provider: "slow-kms", release: release},
		fakeKeySource{provider: "aws-kms", keys: []keyinventory.Key{{Provider: "aws-kms", KeyID: "k1", PQCReadiness: "vulnerable"}}},
	)
	withSSHUserInventory(t, sshkeys.NewInventory())
	rec := httptest.NewRecorder()
	start := time.Now()
	keyInventoryMux(t).ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/inventory/keys", nil))
	elapsed := time.Since(start)
	if rec.Code != http.StatusOK || elapsed > 5*time.Second || elapsed < 2500*time.Millisecond {
		t.Fatalf("code=%d elapsed=%s", rec.Code, elapsed)
	}
	var resp keyInvBody
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Data.Errors) != 1 || resp.Data.Errors[0] != "cloud key inventory unavailable: slow-kms" || resp.Data.Total != 1 {
		t.Fatalf("unexpected: %+v", resp.Data)
	}
}

type hungKeySource struct {
	provider string
	release  chan struct{}
}

func (h hungKeySource) Provider() string { return h.provider }
func (h hungKeySource) ListKeys(context.Context) ([]keyinventory.Key, error) {
	<-h.release
	return nil, nil
}
