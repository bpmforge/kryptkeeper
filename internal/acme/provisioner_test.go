// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	kkdb "kryptkeeper/internal/db"
)

func TestAllows(t *testing.T) {
	p := &Provisioner{AllowNames: []string{"host.example.com", "*.internal"}}
	cases := map[string]bool{
		"host.example.com":       true,
		"*.host.example.com":     false,
		"other.example.com":      false,
		"example.com":            false,
		"a.internal":             true,
		"a.b.internal":           true,
		"*.a.internal":           true,
		"internal":               false,
		"evil-internal":          false,
		"a.evil-internal":        false,
		"a.internal.example.com": false,
	}
	for name, want := range cases {
		if got := p.Allows(name); got != want {
			t.Errorf("Allows(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestValidateProvisioner(t *testing.T) {
	ok := Provisioner{Name: "internal-tls", CAID: "ca-1", AllowNames: []string{"*.internal"}, Challenges: []string{"dns-01"}}
	if err := ValidateProvisioner(ok); err != nil {
		t.Fatalf("valid provisioner: %v", err)
	}
	mut := func(f func(*Provisioner)) Provisioner { p := ok; f(&p); return p }
	bad := map[string]Provisioner{
		"reserved name":    mut(func(p *Provisioner) { p.Name = "order" }),
		"reserved acme":    mut(func(p *Provisioner) { p.Name = "acme" }),
		"uppercase name":   mut(func(p *Provisioner) { p.Name = "Prod" }),
		"leading hyphen":   mut(func(p *Provisioner) { p.Name = "-x" }),
		"no ca":            mut(func(p *Provisioner) { p.CAID = " " }),
		"empty list":       mut(func(p *Provisioner) { p.AllowNames = nil }),
		"uppercase entry":  mut(func(p *Provisioner) { p.AllowNames = []string{"*.Internal"} }),
		"ip entry":         mut(func(p *Provisioner) { p.AllowNames = []string{"10.0.0.1"} }),
		"double wildcard":  mut(func(p *Provisioner) { p.AllowNames = []string{"*.*.internal"} }),
		"bare star":        mut(func(p *Provisioner) { p.AllowNames = []string{"*"} }),
		"unknown chal":     mut(func(p *Provisioner) { p.Challenges = []string{"dns-02"} }),
		"tls-alpn-01":      mut(func(p *Provisioner) { p.Challenges = []string{"tls-alpn-01"} }),
		"too many entries": mut(func(p *Provisioner) { p.AllowNames = make([]string, 101) }),
	}
	for name, p := range bad {
		if err := ValidateProvisioner(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	err := ValidateProvisioner(mut(func(p *Provisioner) { p.AllowNames = []string{"good.internal", "Bad.Example"} }))
	if err == nil || !strings.Contains(err.Error(), "Bad.Example") {
		t.Errorf("error should name the bad entry, got %v", err)
	}
}

// provServer returns a test ACME server with provisioner internal-tls.
func provServer(t *testing.T, p Provisioner) (*Server, *httptest.Server, *MemProvisionerStore) {
	t.Helper()
	srv, ts := newTestACMEServer(t)
	t.Cleanup(ts.Close)
	store := NewMemProvisionerStore()
	if p.Name != "" {
		if p.CAID == "" {
			p.CAID = srv.caID
		}
		if err := store.Create(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	srv.WithProvisioners(store, nil)
	return srv, ts, store
}

func internalTLS(allow []string, challenges ...string) Provisioner {
	return Provisioner{Name: "internal-tls", AllowNames: allow, Challenges: challenges, CreatedBy: "t", CreatedAt: time.Now(), UpdatedAt: time.Now()}
}

func provAccount(t *testing.T, ts *httptest.Server, name string) *acmeTestClient {
	t.Helper()
	c := newACMETestClient(t)
	resp := c.postJWS(t, ts, ts.URL+"/acme/"+name+"/acme/new-account", []byte(`{"termsOfServiceAgreed":true}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("new-account under %s: %d %s", name, resp.StatusCode, b)
	}
	c.kid = resp.Header.Get("Location")
	return c
}

func provOrder(t *testing.T, ts *httptest.Server, name string, c *acmeTestClient, ids ...string) (*http.Response, []byte) {
	t.Helper()
	var idents []map[string]string
	for _, id := range ids {
		idents = append(idents, map[string]string{"type": "dns", "value": id})
	}
	payload, _ := json.Marshal(map[string]any{"identifiers": idents})
	resp := c.postJWS(t, ts, ts.URL+"/acme/"+name+"/acme/new-order", payload)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// challengeTypes returns the challenge types of the one authorization of order.
func challengeTypes(t *testing.T, ts *httptest.Server, c *acmeTestClient, orderBody []byte, n int) []string {
	t.Helper()
	var order Order
	if err := json.Unmarshal(orderBody, &order); err != nil {
		t.Fatal(err)
	}
	resp := c.postJWS(t, ts, order.Authorizations[n], nil)
	defer resp.Body.Close()
	var authz Authorization
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, ch := range authz.Challenges {
		types = append(types, ch.Type)
	}
	return types
}

func TestProvisionerDirectoryBoundAndDefaultUnchanged(t *testing.T) {
	srv, ts, _ := provServer(t, internalTLS([]string{"*.internal"}))
	get := func(path string) (int, Directory) {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var d Directory
		_ = json.NewDecoder(resp.Body).Decode(&d)
		return resp.StatusCode, d
	}
	code, d := get("/acme/internal-tls/directory")
	if code != http.StatusOK || d.NewOrder != ts.URL+"/acme/internal-tls/acme/new-order" || d.NewAccount != ts.URL+"/acme/internal-tls/acme/new-account" {
		t.Fatalf("provisioner directory = %d %+v", code, d)
	}
	code, d = get("/acme/directory")
	if code != http.StatusOK || d.NewOrder != ts.URL+"/acme/new-order" || d.NewNonce != ts.URL+"/acme/new-nonce" {
		t.Fatalf("default directory changed: %d %+v", code, d)
	}
	// The view is scoped to the provisioner's CA.
	v := srv.forProvisioner(Provisioner{Name: "x", CAID: "other-ca"})
	if v.caID != "other-ca" || srv.caID == "other-ca" || v.mu != srv.mu {
		t.Fatal("view must override the CA but share the mutex")
	}
}

func TestProvisionerRejectsNameOutsideAllowList(t *testing.T) {
	_, ts, _ := provServer(t, internalTLS([]string{"*.internal"}))
	c := provAccount(t, ts, "internal-tls")

	resp, body := provOrder(t, ts, "internal-tls", c, "example.com")
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "rejectedIdentifier") ||
		!strings.Contains(string(body), "not permitted by this provisioner") {
		t.Fatalf("example.com: %d %s", resp.StatusCode, body)
	}
	if resp, body := provOrder(t, ts, "internal-tls", c, "host.internal", "example.com"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("one bad name must reject the whole order: %d %s", resp.StatusCode, body)
	}
	if resp, body := provOrder(t, ts, "internal-tls", c, "host.internal"); resp.StatusCode != http.StatusCreated {
		t.Fatalf("host.internal: %d %s", resp.StatusCode, body)
	}
}

func TestDNS01OnlyNeverOffersHTTP01(t *testing.T) {
	_, ts, _ := provServer(t, internalTLS([]string{"*.internal"}, "dns-01"))
	c := provAccount(t, ts, "internal-tls")
	resp, body := provOrder(t, ts, "internal-tls", c, "host.internal")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("order: %d %s", resp.StatusCode, body)
	}
	if got := challengeTypes(t, ts, c, body, 0); len(got) != 1 || got[0] != "dns-01" {
		t.Fatalf("challenges = %v, want [dns-01]", got)
	}
}

func TestWildcardNeverGetsHTTP01(t *testing.T) {
	_, ts, _ := provServer(t, internalTLS([]string{"*.internal"}))
	c := provAccount(t, ts, "internal-tls")
	resp, body := provOrder(t, ts, "internal-tls", c, "*.a.internal")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("wildcard order: %d %s", resp.StatusCode, body)
	}
	if got := challengeTypes(t, ts, c, body, 0); len(got) != 1 || got[0] != "dns-01" {
		t.Fatalf("wildcard challenges = %v, want [dns-01]", got)
	}
}

func TestHTTP01OnlyProvisionerRefusesWildcard(t *testing.T) {
	_, ts, _ := provServer(t, internalTLS([]string{"*.internal"}, "http-01"))
	c := provAccount(t, ts, "internal-tls")
	resp, body := provOrder(t, ts, "internal-tls", c, "*.a.internal")
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "rejectedIdentifier") {
		t.Fatalf("wildcard on http-01-only provisioner: %d %s", resp.StatusCode, body)
	}
}

func TestPostToUnofferedChallenge404(t *testing.T) {
	_, ts, _ := provServer(t, internalTLS([]string{"*.internal"}, "dns-01"))
	c := provAccount(t, ts, "internal-tls")
	_, body := provOrder(t, ts, "internal-tls", c, "host.internal")
	var order Order
	_ = json.Unmarshal(body, &order)
	authzID := order.Authorizations[0][strings.LastIndex(order.Authorizations[0], "/")+1:]
	resp := c.postJWS(t, ts, ts.URL+"/acme/internal-tls/acme/challenge/"+authzID+"/http-01", []byte("{}"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("http-01 on dns-01-only provisioner: %d, want 404", resp.StatusCode)
	}
}

func TestDefaultAccountCannotUseProvisioner(t *testing.T) {
	_, ts, _ := provServer(t, internalTLS([]string{"*.internal"}))
	c := newACMEAccount(t, ts) // account on the default directory
	resp, body := provOrder(t, ts, "internal-tls", c, "host.internal")
	if resp.StatusCode == http.StatusCreated || !strings.Contains(string(body), "accountDoesNotExist") {
		t.Fatalf("default-directory account on a provisioner: %d %s", resp.StatusCode, body)
	}
}

func TestUnknownProvisioner404SameAsReserved(t *testing.T) {
	_, ts, _ := provServer(t, internalTLS([]string{"*.internal"}))
	bodies := map[string]string{}
	for _, path := range []string{"/acme/nope/directory", "/acme/order/directory", "/acme/account/directory", "/acme/internal-tls/other", "/acme/Internal-TLS/directory"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, resp.StatusCode)
		}
		bodies[path] = string(b)
	}
	if bodies["/acme/nope/directory"] != bodies["/acme/order/directory"] {
		t.Errorf("unknown and reserved names must answer identically: %q vs %q", bodies["/acme/nope/directory"], bodies["/acme/order/directory"])
	}

	// No store configured: still the same 404.
	srv, ts2 := newTestACMEServer(t)
	defer ts2.Close()
	_ = srv
	resp, err := http.Get(ts2.URL + "/acme/internal-tls/directory")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("no provisioner store: %d, want 404", resp.StatusCode)
	}
}

func TestEABKeyBoundToOtherProvisionerRejected(t *testing.T) {
	srv, ts, _ := provServer(t, internalTLS([]string{"*.internal"}))
	admin := NewMemEABAdmin()
	mac := []byte("admin-minted-mac-key-32-bytes!!!")
	for _, k := range []EABAdminKey{
		{KID: "kk-eab-other", Provisioner: "prod", CreatedAt: time.Now().UTC()},
		{KID: "kk-eab-mine", Provisioner: "internal-tls", CreatedAt: time.Now().UTC()},
		{KID: "kk-eab-free", CreatedAt: time.Now().UTC()},
	} {
		if err := admin.Create(context.Background(), k, string(mac)); err != nil {
			t.Fatal(err)
		}
	}
	rec := &eabAuditRec{}
	srv.WithEABAdmin(admin).WithAuditFunc(rec.fn)

	register := func(name, kid string) *http.Response {
		c := newACMETestClient(t)
		base := srv.baseURL
		if name != "" {
			base += "/acme/" + name
		}
		eab := buildEAB(t, kid, mac, base+"/acme/new-account", c.jwk)
		payload, _ := json.Marshal(map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": eab})
		path := "/acme/new-account"
		if name != "" {
			path = "/acme/" + name + "/acme/new-account"
		}
		return c.postJWS(t, ts, ts.URL+path, payload)
	}
	if resp := register("internal-tls", "kk-eab-other"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("key bound to another provisioner: %d, want 401", resp.StatusCode)
	}
	if resp := register("", "kk-eab-mine"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("provisioner-bound key on the default directory: %d, want 401", resp.StatusCode)
	}
	if resp := register("internal-tls", "kk-eab-mine"); resp.StatusCode != http.StatusCreated {
		t.Errorf("key bound to this provisioner: %d, want 201", resp.StatusCode)
	}
	if resp := register("internal-tls", "kk-eab-free"); resp.StatusCode != http.StatusCreated {
		t.Errorf("unbound key: %d, want 201", resp.StatusCode)
	}
	rejects := rec.rejects()
	if len(rejects) != 2 || !strings.Contains(rejects[0].Detail, "key bound to provisioner prod") {
		t.Errorf("reject audit = %+v", rejects)
	}
}

func TestDBProvisionerStoreRoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	s := NewDBProvisionerStore(db, false)
	if err := s.EnsureSchema(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	p := Provisioner{Name: "a", CAID: "ca", AllowNames: []string{"*.internal"}, CreatedBy: "u", CreatedAt: now, UpdatedAt: now}
	if err := s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, p); err != ErrProvisionerExists {
		t.Fatalf("duplicate: %v", err)
	}
	got, found, err := s.Get(ctx, "a")
	if err != nil || !found || got.CAID != "ca" || len(got.AllowNames) != 1 || got.Challenges == nil {
		t.Fatalf("get = %+v %v %v", got, found, err)
	}
	p.CAID, p.Challenges, p.UpdatedAt = "ca2", []string{"dns-01"}, now.Add(time.Minute)
	if err := s.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Get(ctx, "a"); got.CAID != "ca2" || len(got.Challenges) != 1 || !got.CreatedAt.Equal(now) {
		t.Fatalf("after update = %+v", got)
	}
	if err := s.Update(ctx, Provisioner{Name: "zz", UpdatedAt: now}); err != ErrProvisionerNotFound {
		t.Fatalf("update missing: %v", err)
	}
	if list, _ := s.List(ctx); len(list) != 1 {
		t.Fatalf("list = %d", len(list))
	}
	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "a"); err != ErrProvisionerNotFound {
		t.Fatalf("delete twice: %v", err)
	}
}
