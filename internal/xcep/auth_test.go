// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package xcep

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/wstep"
)

const getPoliciesAction = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"

// rejectAll behaves like the SPNEGO wrapper when no ticket validates.
func rejectAll(http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		http.Error(w, "Unauthorised.", http.StatusUnauthorized)
	})
}

func postAs(srv *Server, authz string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/xcep", strings.NewReader(getPoliciesSOAP(getPoliciesAction)))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestXCEPWithoutAuthenticatorChallenges(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "p")
	w := postAs(srv, "")
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Negotiate" || strings.Contains(w.Body.String(), "WebServer") {
		t.Fatalf("got %d %q; policy must not be served anonymously", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

func TestXCEPAuditsRejectedCredentialNotChallenge(t *testing.T) {
	var events []wstep.AuditEvent
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "p").
		WithAuthenticator(rejectAll).
		WithAuditFunc(func(_ context.Context, ev wstep.AuditEvent) { events = append(events, ev) })

	if w := postAs(srv, ""); w.Code != http.StatusUnauthorized || len(events) != 0 {
		t.Fatalf("challenge: got %d with %d audit rows, want 401 and none", w.Code, len(events))
	}
	if w := postAs(srv, "Negotiate TlRMTVNTUAABAAAA"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d", w.Code)
	}
	if len(events) != 1 || events[0].Action != "xcep.policy" || events[0].Outcome != "denied" {
		t.Fatalf("want one denied xcep.policy row, got %+v", events)
	}
}
