// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W38-07 (D-324): external credentials resolved from a Vault or OpenBao KV v2
// server. The fake speaks the documented read API (GET /v1/<mount>/data/<path>
// with ?version=, data.data and data.metadata, 403 and 404 answers) and the
// AppRole login, and records every request so the tests can assert what the
// hub sent, how often, and that nothing it audited carries a value.
// https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
)

const (
	fakeKVToken     = "hvs.fake-token-for-tests-0123456789"
	fakeKVSecretKey = "FAKE-SSH-PRIVATE-KEY-MATERIAL-9f8e7d6c"
	fakeKVHostKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEHOSTKEYFORTESTSONLY0000000000000000 host"
)

// fakeVault is a KV v2 mount "secret" holding versioned secrets.
type fakeVault struct {
	ts *httptest.Server

	mu         sync.Mutex
	secrets    map[string][]map[string]any // path -> versions (index 0 = version 1)
	denied     map[string]bool
	reads      int
	logins     int
	lastNS     string
	lastToken  string
	lastQuery  string
	roleID     string
	secretID   string
	clientTok  string
	failStatus int
}

func newFakeVault(t *testing.T) *fakeVault {
	v := &fakeVault{secrets: map[string][]map[string]any{}, denied: map[string]bool{}, clientTok: "hvs.approle-client-token-1"}
	v.ts = httptest.NewTLSServer(http.HandlerFunc(v.serve))
	t.Cleanup(v.ts.Close)
	return v
}

func (v *fakeVault) put(path string, versions ...map[string]any) {
	v.mu.Lock()
	v.secrets[path] = versions
	v.mu.Unlock()
}

func (v *fakeVault) counts() (reads, logins int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.reads, v.logins
}

func (v *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/v1/auth/approle/login" && r.Method == http.MethodPost {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		v.logins++
		if in["role_id"] != v.roleID || in["secret_id"] != v.secretID || v.roleID == "" {
			w.WriteHeader(http.StatusBadRequest)
			// A misbehaving server that reflects the login it was sent.
			_, _ = fmt.Fprintf(w, `{"errors":["invalid login %s %s"]}`, in["role_id"], in["secret_id"])
			return
		}
		_, _ = fmt.Fprintf(w, `{"auth":{"client_token":%q,"lease_duration":3600}}`, v.clientTok)
		return
	}
	prefix := "/v1/secret/data/"
	if !strings.HasPrefix(r.URL.Path, prefix) || r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
		return
	}
	v.reads++
	v.lastNS, v.lastToken, v.lastQuery = r.Header.Get("X-Vault-Namespace"), r.Header.Get("X-Vault-Token"), r.URL.RawQuery
	if v.failStatus != 0 {
		w.WriteHeader(v.failStatus)
		return
	}
	if v.lastToken != fakeKVToken && v.lastToken != v.clientTok {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if v.denied[path] {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`))
		return
	}
	versions, ok := v.secrets[path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
		return
	}
	ver := len(versions)
	if q := r.URL.Query().Get("version"); q != "" {
		if _, err := fmt.Sscan(q, &ver); err != nil || ver < 1 || ver > len(versions) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
	}
	body, _ := json.Marshal(map[string]any{"data": map[string]any{
		"data":     versions[ver-1],
		"metadata": map[string]any{"version": ver, "created_time": "2026-10-25T10:00:00Z", "deletion_time": "", "destroyed": false},
	}})
	_, _ = w.Write(body)
}

func (v *fakeVault) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.ts.Certificate().Raw}))
}

// extEnv is a migrated sqlite hub database with a credential store, a source
// store, and an audit capture.
type extEnv struct {
	t       *testing.T
	db      *sql.DB
	store   *sqliteOutboundCredentialStore
	sources *dbCredentialSourceStore
	vault   *fakeVault

	mu    sync.Mutex
	audit []AuditEntry
}

func newExtEnv(t *testing.T) *extEnv {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "external-credentials.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	e := &extEnv{t: t, db: db, vault: newFakeVault(t)}
	e.store = &sqliteOutboundCredentialStore{db: db, passphrase: []byte("test-passphrase")}
	if err := e.store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.sources = &dbCredentialSourceStore{db: db}
	r := e.store.external()
	r.audit = func(_ context.Context, a AuditEntry) { e.mu.Lock(); e.audit = append(e.audit, a); e.mu.Unlock() }
	// The fake's certificate is for example.com and 127.0.0.1; the hub's
	// client is built the production way (egress guard, pinned CA), with the
	// loopback seam so the test server is reachable.
	prevLoopback := egressAllowLoopback
	egressAllowLoopback = true
	t.Cleanup(func() { egressAllowLoopback = prevLoopback })
	return e
}

func (e *extEnv) auditRows() []AuditEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]AuditEntry(nil), e.audit...)
}

// source creates a vault_kv2 source whose login is a local api_token
// credential holding loginJSON.
func (e *extEnv) source(tenant, loginJSON string, mutate func(*CredentialSourceConfig)) CredentialSource {
	e.t.Helper()
	ctx := context.Background()
	login, err := e.store.Create(ctx, "cred-login-"+tenant+fmt.Sprint(time.Now().UnixNano()), "vault login", CredentialTypeAPIToken, tenant, []byte(loginJSON))
	if err != nil {
		e.t.Fatal(err)
	}
	cfg := CredentialSourceConfig{BaseURL: e.vault.ts.URL, CACertPEM: e.vault.caPEM()}
	if mutate != nil {
		mutate(&cfg)
	}
	src, err := e.sources.Create(ctx, CredentialSource{ID: "src-" + login.ID, Name: "Vault", Kind: CredentialSourceVaultKV2, Tenant: tenant, CredentialRef: login.ID, Config: cfg})
	if err != nil {
		e.t.Fatal(err)
	}
	return src
}

var sshStatic = map[string]string{"host_public_key": fakeKVHostKey}

func (e *extEnv) sshCredential(src CredentialSource, ref map[string]string) OutboundCredentialMeta {
	e.t.Helper()
	m, err := e.store.CreateExternal(context.Background(), "cred-ssh-"+fmt.Sprint(time.Now().UnixNano()), "web1", CredentialTypeSSHKey, src.Tenant, src.ID,
		ExternalReference{Reference: ref, Static: sshStatic})
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

func sshSecret() map[string]any {
	return map[string]any{"private_key_pem": fakeKVSecretKey, "user": "svc-kk", "port": 2222, "notes": "not part of the payload"}
}

func TestExternalSSHCredentialResolvesFromKV2(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("ssh/web1", sshSecret())
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, func(c *CredentialSourceConfig) { c.Namespace = "team-a" })
	cred := e.sshCredential(src, map[string]string{"path": "ssh/web1"})

	got, err := e.store.Resolve(context.Background(), cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	var p sshCredentialPayload
	if err := json.Unmarshal(got, &p); err != nil || p.PrivateKeyPEM != fakeKVSecretKey || p.User != "svc-kk" || p.Port != 2222 || p.HostPublicKey != fakeKVHostKey {
		t.Fatalf("payload %+v err %v", p, err)
	}
	if strings.Contains(string(got), "not part of the payload") {
		t.Error("a stray secret field reached the payload")
	}
	if e.vault.lastToken != fakeKVToken || e.vault.lastNS != "team-a" {
		t.Errorf("vault saw token %q namespace %q", e.vault.lastToken, e.vault.lastNS)
	}

	// The row holds a reference and nothing else: no envelope, no secret.
	var envelope, ref string
	if err := e.db.QueryRow(`SELECT envelope, source_ref FROM outbound_credentials WHERE id = ?`, cred.ID).Scan(&envelope, &ref); err != nil {
		t.Fatal(err)
	}
	if envelope != "" || strings.Contains(ref, fakeKVSecretKey) || strings.Contains(ref, "svc-kk") {
		t.Fatalf("stored row carries material: envelope %q ref %q", envelope, ref)
	}
	meta, _ := e.store.Get(context.Background(), cred.ID)
	raw, _ := json.Marshal(meta)
	if meta.Source != CredentialSourceExternal || meta.SourceID != src.ID || meta.Reference["path"] != "ssh/web1" || strings.Contains(string(raw), fakeKVSecretKey) {
		t.Fatalf("meta %s", raw)
	}
}

func TestExternalVersionPinning(t *testing.T) {
	e := newExtEnv(t)
	v1, v2 := sshSecret(), sshSecret()
	v1["private_key_pem"], v2["private_key_pem"] = "FAKE-KEY-VERSION-ONE-1111", "FAKE-KEY-VERSION-TWO-2222"
	e.vault.put("ssh/web1", v1, v2)
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, nil)

	for ref, want := range map[string]string{"": "FAKE-KEY-VERSION-TWO-2222", "1": "FAKE-KEY-VERSION-ONE-1111", "2": "FAKE-KEY-VERSION-TWO-2222"} {
		r := map[string]string{"path": "ssh/web1"}
		if ref != "" {
			r["version"] = ref
		}
		got, err := e.store.Resolve(context.Background(), e.sshCredential(src, r).ID)
		if err != nil || !strings.Contains(string(got), want) {
			t.Fatalf("version %q: err %v payload has wanted key %v", ref, err, strings.Contains(string(got), want))
		}
		if ref != "" && e.vault.lastQuery != "version="+ref {
			t.Errorf("version %q: query %q", ref, e.vault.lastQuery)
		}
	}
	// A version Vault does not have is a clear not-found, not a fallback to latest.
	_, err := e.store.Resolve(context.Background(), e.sshCredential(src, map[string]string{"path": "ssh/web1", "version": "9"}).ID)
	var re *CredentialResolveError
	if !errors.As(err, &re) || re.Class != resolveClassNotFound || !strings.Contains(re.Msg, "version 9") {
		t.Fatalf("version 9: %v", err)
	}
}

func TestExternalFailuresAreClearAndAuditedWithoutValues(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("ssh/web1", sshSecret())
	e.vault.put("ssh/locked", sshSecret())
	e.vault.denied["ssh/locked"] = true
	short := sshSecret()
	delete(short, "user")
	e.vault.put("ssh/short", short)
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, nil)
	badLogin := e.source(DefaultTenant, `{"token":"hvs.wrong-token"}`, nil)

	cases := []struct {
		name, class string
		cred        OutboundCredentialMeta
		wantMsg     string
	}{
		{"missing key", resolveClassNotFound, e.sshCredential(src, map[string]string{"path": "ssh/nope"}), "nothing at secret/ssh/nope"},
		{"forbidden path", resolveClassDenied, e.sshCredential(src, map[string]string{"path": "ssh/locked"}), "no read policy"},
		{"bad token", resolveClassDenied, e.sshCredential(badLogin, map[string]string{"path": "ssh/web1"}), "denied"},
		{"field missing", resolveClassInvalid, e.sshCredential(src, map[string]string{"path": "ssh/short"}), "missing required field(s): user"},
	}
	for _, c := range cases {
		got, err := e.store.Resolve(context.Background(), c.cred.ID)
		var re *CredentialResolveError
		if err == nil || got != nil || !errors.As(err, &re) || re.Class != c.class || !strings.Contains(err.Error(), c.wantMsg) {
			t.Errorf("%s: payload %v err %v (want class %s containing %q)", c.name, got != nil, err, c.class, c.wantMsg)
		}
		for _, secret := range []string{fakeKVSecretKey, fakeKVToken, "hvs.wrong-token"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error text carries a secret", c.name)
			}
		}
	}

	// An outage is a failure too, with a message that names the source.
	e.vault.mu.Lock()
	e.vault.failStatus = http.StatusInternalServerError
	e.vault.mu.Unlock()
	_, err := e.store.Resolve(context.Background(), e.sshCredential(src, map[string]string{"path": "ssh/web1"}).ID)
	var re *CredentialResolveError
	if !errors.As(err, &re) || re.Class != resolveClassUnavailable || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("outage: %v", err)
	}

	rows := e.auditRows()
	if len(rows) != len(cases)+1 {
		t.Fatalf("%d audit rows, want %d", len(rows), len(cases)+1)
	}
	for _, r := range rows {
		blob, _ := json.Marshal(r)
		if r.Action != "credential.resolve" || r.Outcome != AuditOutcomeFailure || !strings.Contains(r.ChangeSummary, "source=vault_kv2:src-") || !strings.Contains(r.ChangeSummary, "class=") {
			t.Errorf("row %+v", r)
		}
		for _, secret := range []string{fakeKVSecretKey, fakeKVToken, "svc-kk", "hvs.wrong-token", fakeKVHostKey} {
			if strings.Contains(string(blob), secret) {
				t.Errorf("an audit row carries %q: %s", secret, blob)
			}
		}
	}
}

func TestExternalSuccessIsAuditedWithoutValues(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("ssh/web1", sshSecret())
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, nil)
	cred := e.sshCredential(src, map[string]string{"path": "ssh/web1"})
	if _, err := e.store.Resolve(context.Background(), cred.ID); err != nil {
		t.Fatal(err)
	}
	rows := e.auditRows()
	if len(rows) != 1 || rows[0].Action != "credential.resolve" || rows[0].Outcome != AuditOutcomeSuccess || rows[0].ResourceID != cred.ID ||
		rows[0].ActorID != "credential-resolver" || !strings.Contains(rows[0].ChangeSummary, "source=vault_kv2:"+src.ID) || !strings.Contains(rows[0].ChangeSummary, "outcome=ok") {
		t.Fatalf("rows %+v", rows)
	}
	blob, _ := json.Marshal(rows[0])
	for _, secret := range []string{fakeKVSecretKey, fakeKVToken, "svc-kk"} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("audit row carries %q", secret)
		}
	}
}

// Default: nothing is kept. Every use fetches again, and the bytes a caller
// zeroizes are its own copy.
func TestExternalFetchesPerUseAndHandsOutAFreshCopy(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("ssh/web1", sshSecret())
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, nil)
	cred := e.sshCredential(src, map[string]string{"path": "ssh/web1"})

	first, err := e.store.Resolve(context.Background(), cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := string(first)
	zeroize(first)
	second, err := e.store.Resolve(context.Background(), cred.ID)
	if err != nil || string(second) != want {
		t.Fatalf("second resolve after the caller zeroized the first: %v", err)
	}
	if reads, _ := e.vault.counts(); reads != 2 {
		t.Fatalf("%d reads for 2 uses: the default must not cache", reads)
	}
	if n := len(e.store.external().cache); n != 0 {
		t.Fatalf("%d cache entries with no TTL configured", n)
	}
}

func TestExternalOptInCacheIsShortAndWipedOnExpiry(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("ssh/web1", sshSecret())
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, func(c *CredentialSourceConfig) { c.CacheTTLSeconds = 30 })
	cred := e.sshCredential(src, map[string]string{"path": "ssh/web1"})
	r := e.store.external()
	now := time.Now()
	r.now = func() time.Time { return now }

	first, _ := e.store.Resolve(context.Background(), cred.ID)
	zeroize(first) // a caller wiping its copy must not corrupt the cache
	second, err := e.store.Resolve(context.Background(), cred.ID)
	if err != nil || !strings.Contains(string(second), fakeKVSecretKey) {
		t.Fatalf("cached resolve: %v", err)
	}
	if reads, _ := e.vault.counts(); reads != 1 {
		t.Fatalf("%d reads inside the TTL, want 1", reads)
	}
	if rows := e.auditRows(); len(rows) != 2 || !strings.Contains(rows[1].ChangeSummary, "cached=true") {
		t.Fatalf("a cache hit is still audited: %+v", rows)
	}

	r.mu.Lock()
	held := r.cache[cred.ID].payload
	r.mu.Unlock()
	now = now.Add(31 * time.Second)
	if _, err := e.store.Resolve(context.Background(), cred.ID); err != nil {
		t.Fatal(err)
	}
	if reads, _ := e.vault.counts(); reads != 2 {
		t.Fatalf("%d reads after the TTL, want 2", reads)
	}
	if strings.Contains(string(held), fakeKVSecretKey) {
		t.Fatal("an expired cache entry was not zeroized")
	}
}

func TestExternalAppRoleLoginIsPerUse(t *testing.T) {
	e := newExtEnv(t)
	e.vault.roleID, e.vault.secretID = "role-123", "secret-id-456"
	e.vault.put("ssh/web1", sshSecret())
	src := e.source(DefaultTenant, `{"role_id":"role-123","secret_id":"secret-id-456"}`, nil)
	cred := e.sshCredential(src, map[string]string{"path": "ssh/web1"})
	for range 2 {
		if _, err := e.store.Resolve(context.Background(), cred.ID); err != nil {
			t.Fatal(err)
		}
	}
	reads, logins := e.vault.counts()
	if reads != 2 || logins != 2 {
		t.Fatalf("%d reads %d logins: an AppRole token must not be reused across uses", reads, logins)
	}
	if e.vault.lastToken != e.vault.clientTok {
		t.Fatalf("read used token %q, want the AppRole client token", e.vault.lastToken)
	}

	bad := e.source(DefaultTenant, `{"role_id":"role-123","secret_id":"wrong-secret-id-echoed"}`, nil)
	_, err := e.store.Resolve(context.Background(), e.sshCredential(bad, map[string]string{"path": "ssh/web1"}).ID)
	var re *CredentialResolveError
	if !errors.As(err, &re) || re.Class != resolveClassAuth || strings.Contains(err.Error(), "wrong-secret-id-echoed") || strings.Contains(err.Error(), "role-123") {
		t.Fatalf("bad AppRole: %v", err)
	}
}

// The source connection goes through the egress guard: with the loopback seam
// off (production), a source at 127.0.0.1 is refused before any request, and
// so is the cloud metadata address.
func TestExternalSourceUsesTheEgressGuard(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("ssh/web1", sshSecret())
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, nil)
	cred := e.sshCredential(src, map[string]string{"path": "ssh/web1"})

	egressAllowLoopback = false
	_, err := e.store.Resolve(context.Background(), cred.ID)
	var re *CredentialResolveError
	if !errors.As(err, &re) || re.Class != resolveClassUnavailable {
		t.Fatalf("loopback source: %v", err)
	}
	if reads, _ := e.vault.counts(); reads != 0 {
		t.Fatalf("the guard let %d request(s) through to a loopback address", reads)
	}

	meta := e.source(DefaultTenant, `{"token":"x"}`, func(c *CredentialSourceConfig) { c.BaseURL = "https://169.254.169.254:8200"; c.CACertPEM = "" })
	_, err = e.store.Resolve(context.Background(), e.sshCredential(meta, map[string]string{"path": "ssh/web1"}).ID)
	if err == nil {
		t.Fatal("a metadata-address source must be refused")
	}

	// Plain http is refused too: the login and the secret ride on the request.
	plain := e.source(DefaultTenant, `{"token":"x"}`, func(c *CredentialSourceConfig) { c.BaseURL = "http://vault.example.com:8200"; c.CACertPEM = "" })
	_, err = e.store.Resolve(context.Background(), e.sshCredential(plain, map[string]string{"path": "ssh/web1"}).ID)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("plain http source: %v", err)
	}
}

func TestExternalTenancy(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("ssh/web1", sshSecret())
	acme := e.source("acme", `{"token":"`+fakeKVToken+`"}`, nil)

	// Another tenant's credential cannot attach to acme's source.
	_, err := e.store.CreateExternal(context.Background(), "cred-x", "x", CredentialTypeSSHKey, "globex", acme.ID,
		ExternalReference{Reference: map[string]string{"path": "ssh/web1"}, Static: sshStatic})
	if !errors.Is(err, errCredentialSourceNotFound) {
		t.Fatalf("cross-tenant create: %v", err)
	}
	// The same tenant can.
	if _, err := e.store.CreateExternal(context.Background(), "cred-y", "y", CredentialTypeSSHKey, "acme", acme.ID,
		ExternalReference{Reference: map[string]string{"path": "ssh/web1"}, Static: sshStatic}); err != nil {
		t.Fatal(err)
	}
	// And if a row were forced across (a restore, a bug), Resolve still refuses.
	if _, err := e.db.Exec(`UPDATE outbound_credentials SET tenant = 'globex' WHERE id = 'cred-y'`); err != nil {
		t.Fatal(err)
	}
	_, err = e.store.Resolve(context.Background(), "cred-y")
	var re *CredentialResolveError
	if !errors.As(err, &re) || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("forced cross-tenant resolve: %v", err)
	}
	if reads, _ := e.vault.counts(); reads != 0 {
		t.Fatalf("a cross-tenant resolve reached the manager %d time(s)", reads)
	}
}

func TestExternalReferenceAndStaticValidation(t *testing.T) {
	e := newExtEnv(t)
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, nil)
	create := func(ref ExternalReference) error {
		_, err := e.store.CreateExternal(context.Background(), fmt.Sprint("cred-v", time.Now().UnixNano()), "v", CredentialTypeSSHKey, DefaultTenant, src.ID, ref)
		return err
	}
	for name, ref := range map[string]ExternalReference{
		"no reference":       {},
		"no path":            {Reference: map[string]string{"version": "1"}},
		"path traversal":     {Reference: map[string]string{"path": "ssh/../../etc"}},
		"bad version":        {Reference: map[string]string{"path": "ssh/web1", "version": "latest"}},
		"unknown key":        {Reference: map[string]string{"path": "ssh/web1", "key": "x"}},
		"secret in static":   {Reference: map[string]string{"path": "ssh/web1"}, Static: map[string]string{"private_key_pem": "FAKE"}},
		"password in static": {Reference: map[string]string{"path": "ssh/web1"}, Static: map[string]string{"sudo_password": "x"}},
	} {
		if err := create(ref); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if err := create(ExternalReference{Reference: map[string]string{"path": "ssh/web1"}, Static: map[string]string{"secret_name": "gateway-tls", "namespace": "edge"}}); err != nil {
		t.Fatalf("a k8s secret's name is not a secret: %v", err)
	}
	for _, name := range []string{"client_secret", "secret", "secret_key", "bearer_token"} {
		if err := create(ExternalReference{Reference: map[string]string{"path": "ssh/web1"}, Static: map[string]string{name: "x"}}); err == nil {
			t.Errorf("static %q must be refused", name)
		}
	}
	if err := create(ExternalReference{Reference: map[string]string{"path": "ssh/web1", "version": "3"}, Static: sshStatic}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.CreateExternal(context.Background(), "cred-z", "z", "no_such_type", DefaultTenant, src.ID, ExternalReference{Reference: map[string]string{"path": "p"}}); !errors.Is(err, errOutboundCredentialInvalidType) {
		t.Fatalf("invalid type: %v", err)
	}
}

// A source's own login must be local, or resolving it would loop through
// another external fetch.
func TestExternalSourceLoginMustBeLocal(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("login/token", map[string]any{"token": fakeKVToken})
	inner := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, nil)
	ctx := context.Background()
	extLogin, err := e.store.CreateExternal(ctx, "cred-extlogin", "ext login", CredentialTypeAPIToken, DefaultTenant, inner.ID,
		ExternalReference{Reference: map[string]string{"path": "login/token"}})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := e.sources.Create(ctx, CredentialSource{ID: "src-outer", Name: "outer", Kind: CredentialSourceVaultKV2, Tenant: DefaultTenant,
		CredentialRef: extLogin.ID, Config: CredentialSourceConfig{BaseURL: e.vault.ts.URL, CACertPEM: e.vault.caPEM()}})
	if err != nil {
		t.Fatal(err)
	}
	e.vault.put("ssh/web1", sshSecret())
	_, err = e.store.Resolve(ctx, e.sshCredential(outer, map[string]string{"path": "ssh/web1"}).ID)
	if err == nil || !strings.Contains(err.Error(), "must be a local credential") {
		t.Fatalf("external login: %v", err)
	}
}

func TestSourceStoreValidationAndInUse(t *testing.T) {
	e := newExtEnv(t)
	ctx := context.Background()
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, nil)
	for name, s := range map[string]CredentialSource{
		"no name":         {Kind: CredentialSourceVaultKV2, CredentialRef: "c", Config: CredentialSourceConfig{BaseURL: "https://v.example.com"}},
		"bad kind":        {Name: "n", Kind: "ldap", CredentialRef: "c"},
		"no url":          {Name: "n", Kind: CredentialSourceVaultKV2, CredentialRef: "c"},
		"url creds":       {Name: "n", Kind: CredentialSourceVaultKV2, CredentialRef: "c", Config: CredentialSourceConfig{BaseURL: "https://u:p@v.example.com"}},
		"no login":        {Name: "n", Kind: CredentialSourceVaultKV2, Config: CredentialSourceConfig{BaseURL: "https://v.example.com"}},
		"ttl too long":    {Name: "n", Kind: CredentialSourceVaultKV2, CredentialRef: "c", Config: CredentialSourceConfig{BaseURL: "https://v.example.com", CacheTTLSeconds: 3600}},
		"plugin no id":    {Name: "n", Kind: CredentialSourcePlugin, CredentialRef: "c"},
		"plugin with url": {Name: "n", Kind: CredentialSourcePlugin, CredentialRef: "c", Config: CredentialSourceConfig{PluginID: "p.q", BaseURL: "https://x"}},
	} {
		s.ID = "src-bad"
		if _, err := e.sources.Create(ctx, s); !errors.Is(err, errCredentialSourceInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.vault.put("ssh/web1", sshSecret())
	cred := e.sshCredential(src, map[string]string{"path": "ssh/web1"})
	if err := e.sources.Delete(ctx, src.ID); !errors.Is(err, errCredentialSourceInUse) {
		t.Fatalf("delete of a source in use: %v", err)
	}
	if err := e.store.Delete(ctx, cred.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.sources.Delete(ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.sources.Get(ctx, src.ID); !errors.Is(err, errCredentialSourceNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestAssemblePayloadShapes(t *testing.T) {
	win, err := assemblePayload(CredentialTypeWindowsPassword, map[string]string{"username": "Administrator", "password": "pw-1234"},
		map[string]string{"base_url": "https://win1:5986/wsman", "ipport": "0.0.0.0:443", "sql_instance": "SQLEXPRESS"})
	if err != nil || !strings.Contains(string(win), `"base_url":"https://win1:5986/wsman"`) ||
		!strings.Contains(string(win), `"ipport":"0.0.0.0:443"`) || !strings.Contains(string(win), `"sql_instance":"SQLEXPRESS"`) {
		t.Fatalf("windows: the installers' per-target fields must survive: %s %v", win, err)
	}
	if _, err := assemblePayload(CredentialTypeWindowsPassword, map[string]string{"username": "a"}, nil); err == nil || !strings.Contains(err.Error(), "base_url, password") {
		t.Fatalf("windows missing fields: %v", err)
	}
	if raw, err := assemblePayload(CredentialTypeAPIToken, map[string]string{"value": "tok-123"}, nil); err != nil || string(raw) != "tok-123" {
		t.Fatalf("raw api token: %q %v", raw, err)
	}
	obj, err := assemblePayload(CredentialTypeAPIToken, map[string]string{"api_key": "k", "base_url": "https://x"}, nil)
	var m map[string]string
	if err != nil || json.Unmarshal(obj, &m) != nil || m["api_key"] != "k" {
		t.Fatalf("api token object: %s %v", obj, err)
	}
	if _, err := assemblePayload(CredentialTypeCloudIAM, nil, nil); err == nil {
		t.Fatal("an empty cloud_iam secret must be refused")
	}
	for name, f := range map[string]map[string]string{
		"bad port":      {"private_key_pem": "k", "user": "u", "host_public_key": "h", "port": "99999"},
		"sudo mismatch": {"private_key_pem": "k", "user": "u", "host_public_key": "h", "sudo_mode": "password"},
	} {
		if _, err := assemblePayload(CredentialTypeSSHKey, f, nil); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if _, err := assemblePayload("martian", map[string]string{"a": "b"}, nil); err == nil {
		t.Fatal("an unknown credential type has no external shape")
	}
}

// httptest servers all share one certificate, so a CA that does not chain to it
// is generated here.
func unrelatedCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestExternalPinnedCAIsEnforced(t *testing.T) {
	e := newExtEnv(t)
	e.vault.put("ssh/web1", sshSecret())
	src := e.source(DefaultTenant, `{"token":"`+fakeKVToken+`"}`, func(c *CredentialSourceConfig) { c.CACertPEM = unrelatedCAPEM(t) })
	_, err := e.store.Resolve(context.Background(), e.sshCredential(src, map[string]string{"path": "ssh/web1"}).ID)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a server that does not chain to the pinned CA must be refused: %v", err)
	}
	if reads, _ := e.vault.counts(); reads != 0 {
		t.Fatalf("%d request(s) reached a server the hub does not trust", reads)
	}
}
