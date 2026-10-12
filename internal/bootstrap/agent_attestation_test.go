// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// W5-07: agent registration is closed by default; secrets or the
// explicit migration flag open it.

func newAttestationMux(t *testing.T) *http.ServeMux {
	t.Helper()
	store := NewAgentStore()
	mux := http.NewServeMux()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "attestation-test-token")
	auth := NewAuthenticatorFromEnv()
	registerAgentHandlers(mux, auth, store, stubAuditProvider{})
	return mux
}

func postRegister(t *testing.T, mux *http.ServeMux, body map[string]string, header string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", bytes.NewReader(raw))
	if header != "" {
		req.Header.Set("X-Enrollment-Secret", header)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestAgentRegistrationClosedByDefault(t *testing.T) {
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "")
	mux := newAttestationMux(t)

	rec := postRegister(t, mux, map[string]string{"name": "anon", "type": "linux"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous registration must be refused by default, got %d: %s", rec.Code, rec.Body.String())
	}
	// The operator hint lives in the server log; an unauthenticated caller
	// must not learn which env vars gate enrollment (FB-14 / EH-004).
	if strings.Contains(rec.Body.String(), "KRYPTKEEPER_") {
		t.Fatalf("refusal must not echo gate internals to the caller, got: %s", rec.Body.String())
	}
}

func TestAgentRegistrationRequiresMatchingSecret(t *testing.T) {
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "prov-secret-one, prov-secret-two")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "")
	mux := newAttestationMux(t)

	// Missing secret: refused.
	rec := postRegister(t, mux, map[string]string{"name": "a1", "type": "linux"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing secret must be refused, got %d", rec.Code)
	}
	// Wrong secret: refused.
	rec = postRegister(t, mux, map[string]string{"name": "a1", "type": "linux", "enrollment_secret": "guess"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong secret must be refused, got %d", rec.Code)
	}
	// Correct secret in body: enrolled.
	rec = postRegister(t, mux, map[string]string{"name": "a1", "type": "linux", "enrollment_secret": "prov-secret-one"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid secret must enrol, got %d: %s", rec.Code, rec.Body.String())
	}
	// Rotation: the second configured secret also works, via the header.
	rec = postRegister(t, mux, map[string]string{"name": "a2", "type": "linux"}, "prov-secret-two")
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotated secret must enrol, got %d: %s", rec.Code, rec.Body.String())
	}
	// The token contract is intact.
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["agent_id"] == "" || resp["token"] == "" {
		t.Fatalf("registration response contract broken: %s", rec.Body.String())
	}
}

func TestAgentRegistrationSecretsWinOverOpenFlag(t *testing.T) {
	// Once secrets exist they are REQUIRED, even if someone forgot to
	// remove the migration flag.
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "the-secret")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	mux := newAttestationMux(t)

	rec := postRegister(t, mux, map[string]string{"name": "sneaky", "type": "linux"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("secrets must override the open flag, got %d", rec.Code)
	}
	rec = postRegister(t, mux, map[string]string{"name": "legit", "type": "linux", "enrollment_secret": "the-secret"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid secret must still enrol, got %d", rec.Code)
	}
}

func TestAgentRegistrationLegacyOpenFlagPreservesOldBehaviour(t *testing.T) {
	// The documented migration bridge: existing provisioning keeps
	// working while secrets are rolled out.
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	mux := newAttestationMux(t)

	rec := postRegister(t, mux, map[string]string{"name": "legacy", "type": "linux"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("open-registration flag must preserve legacy behaviour, got %d: %s", rec.Code, rec.Body.String())
	}
}
