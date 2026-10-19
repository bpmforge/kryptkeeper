// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/connectors"
)

// W26-29 acceptance #2: the EAB kid and HMAC never reach logs, API output,
// audit rows or error strings. The grep helper is proven non-vacuous first.

const (
	eabLeakKid = "kid-LEAKCHECK-7731"
	eabLeakRaw = "HMACLEAKCHECK9921xyz" // 20 bytes, padded to a 32 byte MAC below
)

func eabLeakMarkers() []string {
	mac := append([]byte(eabLeakRaw), bytes.Repeat([]byte{0x5A}, 12)...)
	return []string{
		eabLeakKid,
		eabLeakRaw,
		base64.RawURLEncoding.EncodeToString(mac),
		base64.StdEncoding.EncodeToString(mac),
		base64.URLEncoding.EncodeToString(mac),
		hex.EncodeToString(mac),
	}
}

// findLeaks returns the markers present in any named haystack.
func findLeaks(haystacks map[string]string, markers []string) []string {
	var hits []string
	for name, h := range haystacks {
		for _, m := range markers {
			if strings.Contains(h, m) {
				hits = append(hits, name+" contains "+m)
			}
		}
	}
	return hits
}

func TestACMEEABSecretsNeverLeak(t *testing.T) {
	markers := eabLeakMarkers()
	macB64 := markers[2]

	// Positive control: the grep must find a planted marker, or it proves nothing.
	for _, m := range markers {
		if got := findLeaks(map[string]string{"planted": "prefix " + m + " suffix"}, markers); len(got) == 0 {
			t.Fatalf("grep helper missed planted marker %q", m)
		}
	}
	if got := findLeaks(map[string]string{"clean": "nothing secret here"}, markers); len(got) != 0 {
		t.Fatalf("grep helper false positive: %v", got)
	}

	var logBuf bytes.Buffer
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) })

	t.Setenv("APP_ACME_EAB_REQUIRED", "true")
	keysJSON, _ := json.Marshal(map[string]string{eabLeakKid: macB64})
	t.Setenv("APP_ACME_EAB_KEYS_JSON", string(keysJSON))

	// Auth + stores + handlers on one mux.
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "eab-leak.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	creds := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("eab-leak-passphrase-32bytes-long!")}
	if err := creds.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	connStore := newConnectorTestStore(t)
	audit := &memAuditProvider{}
	mux := http.NewServeMux()
	RegisterConnectorHandlers(mux, auth, connStore, nil, creds, audit)
	registerCredentialHandlers(mux, auth, creds, audit, nil)

	var bodies []string
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		bodies = append(bodies, fmt.Sprintf("%s %s -> %d\n%s\n%v", method, path, rec.Code, rec.Body.String(), rec.Header()))
		return rec
	}

	// Upstream CAs (built after the env is set, so they enforce EAB).
	goodPort, wrongPort := freeLocalPort(t), freeLocalPort(t)
	goodCA := newARIUpstream(t, fmt.Sprintf("127.0.0.1:%d", goodPort), nil)
	wrongCA := newARIUpstream(t, fmt.Sprintf("127.0.0.1:%d", wrongPort), nil)
	var limited atomic.Bool
	limited.Store(true)
	limitedCA, limitedSolver, _ := rateLimitingCA(t, &limited, "60", "")

	newRLHarness(t, 0) // fake clock for the rate-limit gate; restores globals on cleanup

	mkCred := func(name, kid, hmac string) string {
		payload, _ := json.Marshal(acmeCredentialPayload{EABKid: kid, EABHmacB64: hmac})
		meta, err := creds.Create(context.Background(), "cred-"+name, name, CredentialTypeAPIToken, "default", payload)
		if err != nil {
			t.Fatal(err)
		}
		return meta.ID
	}
	wrongMAC := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	markers = append(markers, wrongMAC) // the bad secret must not leak either
	goodCred := mkCred("good", eabLeakKid, macB64)
	wrongCred := mkCred("wrong", eabLeakKid, wrongMAC)
	limitedCred := mkCred("limited", eabLeakKid, macB64)

	mkConn := func(name, dir, credRef string, solver int) connectors.IssuerConnector {
		cfg, _ := json.Marshal(acmeConnectorConfig{DirectoryURL: dir + "/acme/directory", Email: "ops@example.com", HTTP01Listen: fmt.Sprintf("127.0.0.1:%d", solver)})
		rec := call(http.MethodPost, "/api/v1/connectors", ConnectorRecord{Name: name, Type: "acme", ConfigJSON: string(cfg), CredentialRef: credRef})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create connector %s: %d %s", name, rec.Code, rec.Body.String())
		}
		var resp struct{ Data ConnectorRecord }
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		c := buildRuntimeConnector(resp.Data, nil, creds)
		inner := c
		if w, ok := c.(*dcvTrackedConnector); ok { // W27-24 wraps ACME connectors to record DCV
			inner = w.IssuerConnector
		}
		inner.(*acmeIssuerConnector).allowLoopbackForTest = true
		return c
	}
	good := mkConn("good", goodCA, goodCred, goodPort)
	wrong := mkConn("wrong", wrongCA, wrongCred, wrongPort)
	limitedConn := mkConn("limited", limitedCA, limitedCred, limitedSolver)

	// API surface.
	call(http.MethodGet, "/api/v1/connectors", nil)
	call(http.MethodGet, "/api/v1/connectors/"+good.ID(), nil)
	call(http.MethodGet, "/api/v1/credentials", nil)
	call(http.MethodGet, "/api/v1/credentials/"+goodCred, nil)
	call(http.MethodGet, "/api/v1/credentials/"+wrongCred, nil)
	call(http.MethodGet, "/api/v1/credentials/"+limitedCred, nil)

	// Health, success, bad-MAC failure, rate-limited failure.
	if hl := good.Health(context.Background()); hl.Status != "healthy" {
		t.Fatalf("health: %+v", hl)
	}
	bodies = append(bodies, fmt.Sprintf("%+v", good.Health(context.Background())))
	issue := func(c connectors.IssuerConnector) (connectors.IssueResult, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return c.Issue(ctx, connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)})
	}
	res, err := issue(good)
	if err != nil {
		t.Fatalf("successful issue failed: %v", err)
	}
	bodies = append(bodies, fmt.Sprintf("%+v", res))

	_, wrongErr := issue(wrong)
	if wrongErr == nil {
		t.Fatal("issue with a wrong EAB MAC must fail")
	}
	_, limitedErr := issue(limitedConn)
	if limitedErr == nil {
		t.Fatal("rate-limited issue must fail")
	}
	t.Logf("wrong-MAC error: %v", wrongErr)
	t.Logf("rate-limited error: %v", limitedErr)

	haystacks := map[string]string{
		"http responses":    strings.Join(bodies, "\n"),
		"captured log":      logBuf.String(),
		"wrong-MAC error":   wrongErr.Error(),
		"rate-limit error":  limitedErr.Error(),
		"success result":    fmt.Sprintf("%+v", res),
		"limited error log": fmt.Sprintf("%+v", limitedErr),
	}
	audit.mu.Lock()
	rows, _ := json.Marshal(audit.entries)
	nRows := len(audit.entries)
	audit.mu.Unlock()
	haystacks["audit rows"] = string(rows)
	if nRows == 0 {
		t.Fatal("no audit rows captured; the audit grep would be vacuous")
	}
	if logBuf.Len() == 0 {
		t.Fatal("no log output captured; the log grep would be vacuous")
	}
	if hits := findLeaks(haystacks, markers); len(hits) != 0 {
		t.Fatalf("EAB secret leaked: %v", hits)
	}
}
