// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// W39-01: an install over an http WinRM endpoint must take discovery's sealed
// NTLM path (same agentdiscovery.WSManShell, selected by endpoint scheme) and
// must refuse, not downgrade, when the listener will not seal.
func TestWinRMExecutorOverHTTPNeverSendsBasicOrPlainBodies(t *testing.T) {
	var mu sync.Mutex
	var auths []string
	var bodies []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		n := 0
		if r.Body != nil {
			buf := make([]byte, 4096)
			n, _ = r.Body.Read(buf)
		}
		bodies = append(bodies, n)
		mu.Unlock()
		// A listener with no Negotiate/NTLM, offering only Basic.
		w.Header().Set("WWW-Authenticate", `Basic realm="WSMAN"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	e := NewRenewalExecutor(nil, nil)
	exec, err := e.winRMExecutor(pushCredentialPayload{BaseURL: srv.URL + "/wsman", Username: `CORP\svc-pki`, Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = exec.Run(context.Background(), "whoami")
	if err == nil || !strings.Contains(err.Error(), "never sent over http") {
		t.Fatalf("an http listener that offers no NTLM must be refused with a clear error, got %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(auths) == 0 {
		t.Fatal("the listener was never contacted")
	}
	for i, a := range auths {
		if strings.HasPrefix(strings.ToLower(a), "basic ") {
			t.Fatalf("request %d carried Basic credentials over http", i)
		}
		if !strings.HasPrefix(a, "Negotiate ") {
			t.Fatalf("request %d used %q, want the NTLM handshake", i, a)
		}
		if bodies[i] != 0 {
			t.Fatalf("request %d sent %d body bytes before authentication completed", i, bodies[i])
		}
	}
}
