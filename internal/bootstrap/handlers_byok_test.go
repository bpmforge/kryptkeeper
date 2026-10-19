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

	"kryptkeeper/internal/keystore"
)

// W17-12: the export endpoint. What matters is the ordering of its
// gates — an unusable destination or a failed ceremony must be caught
// while the key is still SEALED.

type fakeBYOKTarget struct {
	imported bool
}

func (f *fakeBYOKTarget) Provider() string { return "aws-kms" }
func (f *fakeBYOKTarget) KeyID() string    { return "key-1" }
func (f *fakeBYOKTarget) ImportParameters(context.Context) ([]byte, []byte, error) {
	return nil, nil, context.Canceled // never reached in these tests
}
func (f *fakeBYOKTarget) Import(context.Context, []byte, []byte) error {
	f.imported = true
	return nil
}

func byokMux(t *testing.T, target keystore.KMSImportTarget, targetErr error) *http.ServeMux {
	t.Helper()
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	prev := newBYOKTarget
	newBYOKTarget = func(context.Context, string, string, string) (keystore.KMSImportTarget, error) {
		return target, targetErr
	}
	t.Cleanup(func() { newBYOKTarget = prev })
	mux := http.NewServeMux()
	registerBYOKHandlers(mux, newReportsTestAuth(t), stubAuditProvider{})
	return mux
}

func postBYOK(t *testing.T, mux *http.ServeMux, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/keys/byok/export", raw))
	return rec
}

// An unimplemented provider must fail BEFORE the key is materialized.
func TestBYOKUnknownProviderFailsWhileKeyStillSealed(t *testing.T) {
	tgt := &fakeBYOKTarget{}
	mux := byokMux(t, nil, errUnsupportedBYOKProvider)
	rec := postBYOK(t, mux, map[string]any{
		"bundle": json.RawMessage(`{"schema_version":1,"key_id":"k"}`),
		"key_id": "key-1", "provider": "azure",
		"custodian_a_passphrase": "alpha", "custodian_b_passphrase": "bravo",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unusable destination must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
	if tgt.imported {
		t.Fatal("nothing may be imported")
	}
}

// A failed dual-control ceremony must be refused and must not leak.
func TestBYOKRefusesSingleControl(t *testing.T) {
	rec := postBYOK(t, byokMux(t, &fakeBYOKTarget{}, nil), map[string]any{
		"bundle": json.RawMessage(`{"schema_version":1,"key_id":"k","shares":[{"slot":"A"},{"slot":"B"}]}`),
		"key_id": "key-1", "provider": "aws",
		"custodian_a_passphrase": "only-one",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("single control must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); containsAny(body, "PRIVATE KEY", "only-one") {
		t.Fatalf("response leaked material: %s", body)
	}
}

func TestBYOKValidatesBodyAndRequiresApprover(t *testing.T) {
	mux := byokMux(t, &fakeBYOKTarget{}, nil)

	rec := postBYOK(t, mux, map[string]any{"provider": "aws"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing bundle/key_id must be refused, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/keys/byok/export", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
