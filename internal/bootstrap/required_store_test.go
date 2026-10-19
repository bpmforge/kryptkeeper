// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// D-290-A: a configured-but-unopenable database must never turn into an
// in-memory store. These tests break one store's DSN at a time (each reads its
// own DSN env) and prove: routes 503 with a constant body, /readyz is not
// ready, nothing is served from memory, and the store recovers by itself.

const (
	bgRoute = "/api/v1/auth/breakglass/status"
	arRoute = "/api/v1/admin/access-review/campaigns"
)

// unopenableSQLiteDSN points into a directory that does not exist, so the
// open fails without touching any other store.
func unopenableSQLiteDSN(t *testing.T) string {
	t.Helper()
	return "file:" + filepath.Join(t.TempDir(), "missing-dir", "x.db")
}

type governanceHub struct {
	mux  *http.ServeMux
	auth *Authenticator
}

func newGovernanceHub(t *testing.T) governanceHub {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	audit := realSQLiteAuditProvider(t)
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForAudit{}, audit, stubCAProviderForAudit{}, stubTemplateProviderForAudit{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)
	registerGovernanceHandlers(mux, auth, audit)
	return governanceHub{mux: mux, auth: auth}
}

func (h governanceHub) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func assertUniform503(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, storeUnavailableMessage) {
		t.Fatalf("body must carry the uniform message: %s", body)
	}
	for _, leak := range []string{"missing-dir", "sqlite", "postgres", "unable to open", "DSN"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
			t.Fatalf("503 body leaks %q: %s", leak, body)
		}
	}
}

func waitReady(t *testing.T, h governanceHub, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.get("/readyz").Code == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("/readyz never reached %d; last body %s", want, h.get("/readyz").Body)
}

func TestBreakGlassDBConfiguredButDown_Fails503NotMemory(t *testing.T) {
	t.Setenv("APP_BREAKGLASS_DB_DSN", unopenableSQLiteDSN(t))
	h := newGovernanceHub(t)
	if rec := h.get("/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d with break-glass down, want 503", rec.Code)
	}
	assertUniform503(t, h.get(bgRoute))
	if _, isMem := newBreakGlassStoreFromEnv().(*memBreakGlassStore); isMem {
		t.Fatal("break-glass fell back to memory")
	}
	if _, err := activeBreakGlass().store.CreateActivationIfFree(t.Context(), BreakGlassActivation{ID: "a"}, time.Now()); err == nil {
		t.Fatal("break-glass accepted an activation while its store is down")
	}
}

func TestBreakGlassRecoversWithoutRestart(t *testing.T) {
	bad := unopenableSQLiteDSN(t)
	t.Setenv("APP_BREAKGLASS_DB_DSN", bad)
	h := newGovernanceHub(t)
	bg := activeBreakGlass().store.(lazyBreakGlassStore)
	bg.retryEvery = 0
	waitReady(t, h, http.StatusServiceUnavailable)
	t.Setenv("APP_BREAKGLASS_DB_DSN", "file:"+filepath.Join(t.TempDir(), "ok.db")+sqliteDSNParams)
	waitReady(t, h, http.StatusOK)
	if rec := h.get(bgRoute); rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("break-glass still 503 after the database recovered: %s", rec.Body)
	}
}

func TestAccessReviewDBConfiguredButDown_Fails503NotMemory(t *testing.T) {
	t.Setenv("APP_ACCESS_REVIEW_DB_DSN", unopenableSQLiteDSN(t))
	h := newGovernanceHub(t)
	if rec := h.get("/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d with access review down, want 503", rec.Code)
	}
	assertUniform503(t, h.get(arRoute))
	if _, isMem := newAccessReviewStoreFromEnv().(*memAccessReviewStore); isMem {
		t.Fatal("access review fell back to memory")
	}
}

func TestAgentStoreDBConfiguredButDown_Fails503NotMemory(t *testing.T) {
	// postgres mode with no DSN anywhere: the open fails, as with an
	// unreachable server.
	t.Setenv("KRYPTKEEPER_DB_MODE", "postgres")
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("KRYPTKEEPER_DB_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("APP_AGENT_STORE_PROVIDER", "")
	store := NewAgentStoreFromEnv()
	if _, isMem := store.(*memAgentStore); isMem {
		t.Fatal("agent store fell back to memory")
	}
	if _, _, err := store.register("a", AgentTypeLinux); err == nil {
		t.Fatal("agent registered into a store that is down")
	}
	auth := &Authenticator{}
	auth.requireStore(store)
	if auth.requiredStoresReady() == nil {
		t.Fatal("readiness must fail while the agent store is down")
	}
	mux := http.NewServeMux()
	registerAgentHandlers(gateRoutes(mux, store), auth, store, &memAuditProvider{})
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/agent/register"},
		{http.MethodPost, "/api/v1/agent/heartbeat"},
		{http.MethodGet, "/api/v1/agent/tasks"},
		{http.MethodGet, "/api/v1/agents"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(route.method, route.path, strings.NewReader("{}")))
		assertUniform503(t, rec)
	}
}

func TestAgentStoreExplicitMemoryStillWorks(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DB_MODE", "postgres")
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("KRYPTKEEPER_DB_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("APP_AGENT_STORE_PROVIDER", "memory")
	origOnce, origStore := fallbackAgentStoreOnce, fallbackAgentStore
	fallbackAgentStoreOnce, fallbackAgentStore = new(sync.Once), nil
	t.Cleanup(func() { fallbackAgentStoreOnce, fallbackAgentStore = origOnce, origStore })
	store := NewAgentStoreFromEnv()
	if _, isMem := store.(*memAgentStore); !isMem {
		t.Fatalf("explicit memory mode returned %T", store)
	}
	if _, _, err := store.register("a", AgentTypeLinux); err != nil {
		t.Fatalf("explicit memory store refused a registration: %v", err)
	}
}

func TestBreakGlassAndAccessReviewExplicitMemoryStillWork(t *testing.T) {
	t.Setenv("APP_BREAKGLASS_DB_DSN", unopenableSQLiteDSN(t))
	t.Setenv("APP_ACCESS_REVIEW_DB_DSN", unopenableSQLiteDSN(t))
	t.Setenv("APP_BREAKGLASS_PROVIDER", "memory")
	t.Setenv("APP_ACCESS_REVIEW_PROVIDER", "memory")
	if _, ok := newBreakGlassStoreFromEnv().(*memBreakGlassStore); !ok {
		t.Fatal("APP_BREAKGLASS_PROVIDER=memory did not select memory")
	}
	if _, ok := newAccessReviewStoreFromEnv().(*memAccessReviewStore); !ok {
		t.Fatal("APP_ACCESS_REVIEW_PROVIDER=memory did not select memory")
	}
}

func TestAgentChangeSinkAppliedOnLateOpen(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DB_MODE", "sqlite")
	t.Setenv("APP_AUDIT_DB_DSN", unopenableSQLiteDSN(t))
	t.Setenv("APP_AGENT_STORE_PROVIDER", "")
	l := NewAgentStoreFromEnv().(*lazyAgentStore)
	l.retryEvery = 0
	l.SetAgentChangeSink(func(context.Context, agentChangeEvent) {})
	t.Setenv("APP_AUDIT_DB_DSN", "file:"+filepath.Join(t.TempDir(), "ok.db")+sqliteDSNParams)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s, err := l.get(); err == nil {
			db, ok := s.(*dbAgentStore)
			if !ok || db.changeSink == nil {
				t.Fatalf("late open lost the change sink (%T)", s)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("agent store never recovered")
}

// Rescan R-02: a lazy store retries its open every storeRetryInterval, so a
// pool opened for a store whose EnsureSchema then failed must be closed, or
// every retry leaks a held SQLite connection. A shared Postgres pool must
// survive (other holders use it).
func TestReleaseFailedOpenDBClosesOnlyUnsharedPools(t *testing.T) {
	open := func(t *testing.T) *sql.DB {
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "r.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	closed := func(db *sql.DB) bool { return db.PingContext(context.Background()) != nil }

	cases := []struct {
		mode, service string
		wantClosed    bool
	}{
		{dbModeSQLite, "breakglass", true},
		{dbModePostgres, "breakglass", false},
		{dbModePostgres, "compliance-attestation", true},
	}
	for _, c := range cases {
		t.Setenv(dbModeEnv, c.mode)
		db := open(t)
		releaseFailedOpenDB(c.service, db)
		if got := closed(db); got != c.wantClosed {
			t.Fatalf("mode=%s service=%s: closed=%v, want %v", c.mode, c.service, got, c.wantClosed)
		}
	}
	releaseFailedOpenDB("breakglass", nil) // no pool: no panic
}
