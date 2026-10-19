// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/agentinstall"
)

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTargetsHandler_HostKeyProbe(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	key := testHostKey(t)
	old := probeTargetHostKey
	t.Cleanup(func() { probeTargetHostKey = old })
	var gotHost string
	var gotPort int
	probeTargetHostKey = func(_ context.Context, host string, port int) (ssh.PublicKey, error) {
		gotHost, gotPort = host, port
		return key, nil
	}

	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets/hostkey", "test-token", `{"host":"web01.example.com"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Host, Algorithm string
			Port            int
			SSHHostKey      string `json:"ssh_host_key"`
			Fingerprint     string `json:"fingerprint_sha256"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if gotHost != "web01.example.com" || gotPort != 22 {
		t.Fatalf("probe called with %s:%d", gotHost, gotPort)
	}
	if resp.Data.Fingerprint != agentinstall.HostKeyFingerprint(key) || resp.Data.SSHHostKey != agentinstall.HostKeyLine(key) || resp.Data.Algorithm != "ssh-ed25519" || resp.Data.Port != 22 {
		t.Fatalf("unexpected response: %+v", resp.Data)
	}

	rec = doTargetsRequest(mux, http.MethodPost, "/api/v1/targets/hostkey", "test-token", `{"host":"127.0.0.1"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("loopback host: status = %d, want 400", rec.Code)
	}
	rec = doTargetsRequest(mux, http.MethodPost, "/api/v1/targets/hostkey", "", `{"host":"web01"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated probe: status = %d, want 401", rec.Code)
	}
}

func TestTargetsHandler_CreateStoresConfirmedHostKey(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	key := testHostKey(t)
	body := `{"name":"Web01","host":"web01.example.com","install_mode":"ssh","ssh_host_key":"` + agentinstall.HostKeyLine(key) + `"}`
	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data ManagedTarget `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	want := agentinstall.HostKeyFingerprint(key)
	if created.Data.SSHHostKeyFingerprint != want {
		t.Fatalf("create fingerprint = %q, want %q", created.Data.SSHHostKeyFingerprint, want)
	}
	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+created.Data.ID, "test-token", "")
	var got struct {
		Data ManagedTarget `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Data.SSHHostKeyFingerprint != want || got.Data.SSHHostKey != agentinstall.HostKeyLine(key) {
		t.Fatalf("stored pin not returned: %+v", got.Data)
	}

	other := testHostKey(t)
	rec = doTargetsRequest(mux, http.MethodPatch, "/api/v1/targets/"+created.Data.ID, "test-token", `{"ssh_host_key":"`+agentinstall.HostKeyLine(other)+`"}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got.Data.SSHHostKeyFingerprint != agentinstall.HostKeyFingerprint(other) {
		t.Fatalf("patch did not replace the pin: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTargetsHandler_RejectsMalformedHostKey(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token",
		`{"name":"Web01","host":"web01","install_mode":"ssh","ssh_host_key":"not a key"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "authorized_keys format") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestTargetsHandler_HostKeyRejectedForNonSSHMode(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token",
		`{"name":"Web01","host":"web01","install_mode":"agent","ssh_host_key":"`+agentinstall.HostKeyLine(testHostKey(t))+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPinnedHostKeyFor_StoredWinsOverCredential(t *testing.T) {
	stored, cred := testHostKey(t), testHostKey(t)
	tgt := ManagedTarget{SSHHostKey: agentinstall.HostKeyLine(stored)}
	if got := pinnedHostKeyFor(tgt, cred); agentinstall.HostKeyFingerprint(got) != agentinstall.HostKeyFingerprint(stored) {
		t.Fatal("stored pin must win over the credential's key")
	}
	if got := pinnedHostKeyFor(ManagedTarget{}, cred); agentinstall.HostKeyFingerprint(got) != agentinstall.HostKeyFingerprint(cred) {
		t.Fatal("legacy target must fall back to the credential's key")
	}
}

func TestRecordHostKeyMismatch_WritesAudit(t *testing.T) {
	ap := &recordingAuditProvider{}
	mm := &agentinstall.HostKeyMismatchError{Host: "web01", Pinned: "SHA256:aaa", Observed: "SHA256:bbb"}
	recordHostKeyMismatch(context.Background(), ap, "target-1", mm)
	if len(ap.entries) != 1 {
		t.Fatalf("entries = %d", len(ap.entries))
	}
	e := ap.entries[0]
	if e.Action != "target.hostkey.mismatch" || e.Outcome != AuditOutcomeFailure || e.ResourceID != "target-1" ||
		!strings.Contains(e.ChangeSummary, "SHA256:aaa") || !strings.Contains(e.ChangeSummary, "SHA256:bbb") {
		t.Fatalf("unexpected audit entry: %+v", e)
	}
}
