// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// pinnedExecuteFixture issues a cert pinned to connectorID and an ssh target,
// with an empty env connector store in a temp dir.
func pinnedExecuteFixture(t *testing.T, connectorID string) (mux *http.ServeMux, fp, target, caID string, provider CertificateProvider) {
	t.Helper()
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	mux, provider, targetStore, credStore, caID := newRenewalExecuteTestMux(t)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "pinned.example.com", "pinned.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-pinned",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	fp = issued.CertificateItem.FingerprintSHA256
	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{
		ManagementState: "managed", RenewalMethod: "acme", RenewalConnectorID: connectorID,
	}); err != nil {
		t.Fatalf("estate update: %v", err)
	}
	if _, err := credStore.Create(ctx, "cred-p1", "pinned ssh", CredentialTypeSSHKey, "", testSSHCredentialJSON(t)); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if _, err := targetStore.Create(ctx, ManagedTarget{
		ID: "tgt-p1", Name: "pinned-target", Host: "127.0.0.1",
		DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-p1",
	}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	return mux, fp, "tgt-p1", caID, provider
}

func executePinned(t *testing.T, mux *http.ServeMux, fp, target string) *httptest.ResponseRecorder {
	t.Helper()
	return postRenewalExecute(t, mux, "test-token", map[string]any{
		"fingerprint": fp, "target_id": target,
		"install": map[string]string{"server_type": "nginx", "cert_path": "/etc/nginx/tls/p.crt", "key_path": "/etc/nginx/tls/p.key"},
	})
}

// A cert pinned to a connector the registry cannot resolve must fail the
// manual execute and leave no hub-CA successor behind.
func TestRenewalExecuteHandlerPinnedUnknownConnectorFailsClosed(t *testing.T) {
	mux, fp, target, _, provider := pinnedExecuteFixture(t, "conn-missing")
	rec := executePinned(t, mux, fp, target)
	if rec.Code == http.StatusOK {
		t.Fatalf("pinned renewal with unresolvable connector must fail, got 200: %s", rec.Body.String())
	}
	after, _, err := provider.GetCertificate(context.Background(), fp)
	if err != nil {
		t.Fatalf("get predecessor: %v", err)
	}
	if after.SuccessorFP != nil {
		t.Fatalf("hub CA minted a successor for a connector-pinned cert: %v", *after.SuccessorFP)
	}
}

// With the connector created in the env store AFTER the handler was
// registered, the same request routes through it: the registry is resolved
// per renewal, not snapshotted at boot.
func TestRenewalExecuteHandlerPinnedConnectorRoutesUpstream(t *testing.T) {
	mux, fp, target, caID, _ := pinnedExecuteFixture(t, "conn-int")
	store := newConnectorStoreFromEnv()
	if store == nil {
		t.Fatal("env connector store unavailable")
	}
	if _, err := store.Create(context.Background(), ConnectorRecord{
		ID: "conn-int", Name: "int", Type: "internal", ConfigJSON: `{"ca_id":"` + caID + `"}`,
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	rec := executePinned(t, mux, fp, target)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 via connector, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data RenewalExecuteResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Data.Renewed || resp.Data.NewFingerprint == "" {
		t.Fatalf("expected renewed successor, got %+v", resp.Data)
	}
}
