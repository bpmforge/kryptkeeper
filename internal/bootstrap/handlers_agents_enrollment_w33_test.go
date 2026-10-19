// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// W33-24 extensions of W29-06's enrollment tokens: attach, tenant scope,
// no-oracle refusals and the audit trail. Helpers (enrollEnv, storeVariants)
// live in handlers_agents_enrollment_test.go.

const enrollTokensPath = "/api/v1/agent/enrollment-tokens"

func (e *enrollEnv) mintAs(t *testing.T, bearer, body string) (id, token string) {
	t.Helper()
	w := e.do("POST", enrollTokensPath, bearer, body, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint: %d %s", w.Code, w.Body.String())
	}
	var raw struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw.Data["token"], agentEnrollTokenPrefix) || raw.Data["id"] == "" || raw.Data["expires_at"] == "" {
		t.Fatalf("bad mint response: %s", w.Body.String())
	}
	return raw.Data["id"], raw.Data["token"]
}

func (e *enrollEnv) mint(t *testing.T) (id, token string) {
	t.Helper()
	return e.mintAs(t, e.adminTok, `{}`)
}

func (e *enrollEnv) auditJoined() string {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	var sb strings.Builder
	for _, en := range e.audit.entries {
		b, _ := json.Marshal(en)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func (e *enrollEnv) listTokens(t *testing.T, bearer string) []AgentEnrollmentToken {
	t.Helper()
	w := e.do("GET", enrollTokensPath, bearer, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []AgentEnrollmentToken `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Data
}

func TestMintToken_AdminOnly(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		e := newEnrollEnv(t, store)
		if w := e.do("POST", enrollTokensPath, "", `{}`, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("no auth: %d", w.Code)
		}
		if w := e.do("POST", enrollTokensPath, e.viewTok, `{}`, nil); w.Code != http.StatusForbidden {
			t.Fatalf("viewer: %d", w.Code)
		}
		id, token := e.mint(t)
		if !e.hasAudit("agent.token_mint", AuditOutcomeDenied) || !e.hasAudit("agent.token_mint", AuditOutcomeSuccess) {
			t.Fatalf("mint audits missing: %s", e.auditJoined())
		}
		if strings.Contains(e.auditJoined(), token) {
			t.Fatal("token secret leaked into audit rows")
		}
		if !strings.Contains(e.auditJoined(), id) {
			t.Fatal("token id not audited")
		}
		if w := e.do("GET", enrollTokensPath, e.viewTok, "", nil); w.Code != http.StatusForbidden {
			t.Fatalf("viewer list: %d", w.Code)
		}
		w := e.do("GET", enrollTokensPath, e.adminTok, "", nil)
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), token) || !strings.Contains(w.Body.String(), id) {
			t.Fatalf("list: %d %s", w.Code, w.Body.String())
		}
	})
}

// Single use, and the redeemed row names the agent it enrolled (attach).
func TestRegister_TokenSingleUse(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		e := newEnrollEnv(t, store)
		id, token := e.mintAs(t, e.adminTok, `{"label":"a1"}`)
		body := `{"name":"a1","enrollment_token":"` + token + `"}`
		w := e.do("POST", "/api/v1/agent/register", "", body, nil)
		if w.Code != http.StatusCreated {
			t.Fatalf("first: %d %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["agent_id"] == "" || resp["token"] == "" {
			t.Fatalf("no creds: %s", w.Body.String())
		}
		w = e.do("POST", "/api/v1/agent/register", "", body, nil)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "enrollment refused") {
			t.Fatalf("second: %d %s", w.Code, w.Body.String())
		}
		var row *AgentEnrollmentToken
		for _, tk := range e.listTokens(t, e.adminTok) {
			if tk.ID == id {
				row = &tk
			}
		}
		if row == nil || row.RedeemedAt == "" || row.RedeemedAgentID != resp["agent_id"] {
			t.Fatalf("redeemed row must name agent %s: %+v", resp["agent_id"], row)
		}
		if strings.Contains(e.auditJoined(), token) {
			t.Fatal("token leaked into audit")
		}
	})
}

// Used, unknown, revoked and expired tokens get byte-identical refusals.
func TestRegister_HeaderTokenAndNoOracle(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		e := newEnrollEnv(t, store)
		id, token := e.mint(t)
		hdr := func(tok string) map[string]string { return map[string]string{"X-Enrollment-Token": tok} }
		if w := e.do("POST", "/api/v1/agent/register", "", `{"name":"h"}`, hdr(token)); w.Code != http.StatusCreated {
			t.Fatalf("header token: %d", w.Code)
		}
		used := e.do("POST", "/api/v1/agent/register", "", `{"name":"h"}`, hdr(token))
		unknown := e.do("POST", "/api/v1/agent/register", "", `{"name":"h"}`, hdr(agentEnrollTokenPrefix+"nope"))
		if used.Code != http.StatusForbidden || used.Code != unknown.Code || used.Body.String() != unknown.Body.String() {
			t.Fatalf("oracle: used=%d %q unknown=%d %q", used.Code, used.Body, unknown.Code, unknown.Body)
		}
		revID, revTok := e.mint(t)
		if w := e.do("DELETE", enrollTokensPath+"/"+revID, e.adminTok, "", nil); w.Code != http.StatusNoContent {
			t.Fatalf("revoke: %d", w.Code)
		}
		rev := e.do("POST", "/api/v1/agent/register", "", `{"name":"h"}`, hdr(revTok))
		if rev.Code != used.Code || rev.Body.String() != used.Body.String() {
			t.Fatalf("revoked differs: %d %q", rev.Code, rev.Body)
		}
		_, expTok, err := store.mintEnrollmentToken("", "admin", DefaultTenant, time.Second, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		exp := e.do("POST", "/api/v1/agent/register", "", `{"name":"h"}`, hdr(expTok))
		if exp.Code != used.Code || exp.Body.String() != used.Body.String() {
			t.Fatalf("expired differs: %d %q", exp.Code, exp.Body)
		}
		if w := e.do("DELETE", enrollTokensPath+"/"+id, e.viewTok, "", nil); w.Code != http.StatusForbidden {
			t.Fatalf("viewer revoke: %d", w.Code)
		}
		if !e.hasAudit("agent.token_revoke", AuditOutcomeSuccess) || !e.hasAudit("agent.token_revoke", AuditOutcomeDenied) {
			t.Fatal("revoke audits missing")
		}
	})
}

func TestRegister_TokenExpired(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
		_, tok, err := store.mintEnrollmentToken("", "admin", DefaultTenant, 24*time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.redeemEnrollmentToken(tok, "a1", now.Add(24*time.Hour+time.Second)); err != ErrEnrollmentTokenInvalid {
			t.Fatalf("expired: %v", err)
		}
		// Expiry is the boundary: exactly at expires_at is already dead.
		if _, err := store.redeemEnrollmentToken(tok, "a1", now.Add(24*time.Hour)); err != ErrEnrollmentTokenInvalid {
			t.Fatalf("at expiry: %v", err)
		}
		_, tok2, _ := store.mintEnrollmentToken("", "admin", DefaultTenant, 24*time.Hour, now)
		if _, err := store.redeemEnrollmentToken(tok2, "a2", now.Add(23*time.Hour+59*time.Minute)); err != nil {
			t.Fatalf("23h59m: %v", err)
		}
	})
}

func TestRegister_AuditCarriesTokenID(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		e := newEnrollEnv(t, store)
		id, token := e.mint(t)
		e.do("POST", "/api/v1/agent/register", "", `{"name":"a"}`, map[string]string{"X-Enrollment-Token": token})
		e.audit.mu.Lock()
		defer e.audit.mu.Unlock()
		for _, en := range e.audit.entries {
			if en.Action == "agent.register" && en.Outcome == AuditOutcomeSuccess {
				if !strings.Contains(en.ChangeSummary, id) || strings.Contains(en.ChangeSummary, token) {
					t.Fatalf("detail: %q", en.ChangeSummary)
				}
				return
			}
		}
		t.Fatal("no agent.register success audit")
	})
}

func TestRegister_ConcurrentRedeem_ExactlyOne(t *testing.T) {
	// The sqlite variant uses the production DSN params: without busy_timeout
	// the losers fail with SQLITE_BUSY before the conditional UPDATE runs,
	// which would hide whether the UPDATE itself admits exactly one winner.
	run := func(t *testing.T, store AgentStore) {
		_, tok, err := store.mintEnrollmentToken("", "admin", DefaultTenant, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var ok int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := store.redeemEnrollmentToken(tok, "racer", time.Now()); err == nil {
					atomic.AddInt32(&ok, 1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if ok != 1 {
			t.Fatalf("want exactly 1 success, got %d", ok)
		}
	}
	t.Run("mem", func(t *testing.T) { run(t, NewAgentStore()) })
	t.Run("sqlite", func(t *testing.T) {
		run(t, openAgentDB(t, "file:"+filepath.Join(t.TempDir(), "agents.db")+sqliteDSNParams))
	})
}

// A tenant admin neither sees nor revokes another tenant's tokens; a
// cross-tenant id is answered exactly like an unknown one (404).
func TestEnrollmentTokens_TenantIsolation(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		e := newEnrollEnv(t, store)
		t.Setenv("MULTI_TENANCY", "on")
		_, acme, err := e.auth.CreateAPIKey("acme-adm", "acme-adm", "pki-admin", []string{"*"}, "", "acme", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		_, globex, err := e.auth.CreateAPIKey("globex-adm", "globex-adm", "pki-admin", []string{"*"}, "", "globex", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		acmeID, _ := e.mintAs(t, acme, `{"label":"acme-host"}`)
		globexID, _ := e.mintAs(t, globex, `{"label":"globex-host"}`)
		for _, tk := range e.listTokens(t, acme) {
			if tk.ID != acmeID {
				t.Fatalf("acme sees foreign token %s", tk.ID)
			}
		}
		if got := e.listTokens(t, globex); len(got) != 1 || got[0].ID != globexID {
			t.Fatalf("globex list: %+v", got)
		}
		cross := e.do("DELETE", enrollTokensPath+"/"+globexID, acme, "", nil)
		missing := e.do("DELETE", enrollTokensPath+"/aet-missing", acme, "", nil)
		if cross.Code != http.StatusNotFound || cross.Body.String() != missing.Body.String() {
			t.Fatalf("cross-tenant revoke: %d %q vs %d %q", cross.Code, cross.Body, missing.Code, missing.Body)
		}
		if w := e.do("DELETE", enrollTokensPath+"/"+globexID, globex, "", nil); w.Code != http.StatusNoContent {
			t.Fatalf("own-tenant revoke: %d", w.Code)
		}
	})
}

func TestEnrollmentTokens_DeleteRouteNotMistakenForAgent(t *testing.T) {
	e := newEnrollEnv(t, NewAgentStore())
	if w := e.do("DELETE", enrollTokensPath, e.adminTok, "", nil); w.Code == http.StatusNoContent {
		t.Fatalf("collection DELETE must not remove anything: %d", w.Code)
	}
	if w := e.do("DELETE", enrollTokensPath+"/aet-missing", e.adminTok, "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing token: %d", w.Code)
	}
}
