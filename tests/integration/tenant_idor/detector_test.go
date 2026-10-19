// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tenantidor

import "testing"

var (
	acmeViewer = Principal{Tenant: "acme", Role: "viewer", Token: "x"}
	victim     = VictimSet{Marker: "idor-abc123", IDs: map[string]bool{"ca-victim-1": true}, Tenant: "globex"}
)

func TestDetectBodyLeak(t *testing.T) {
	cases := []struct {
		name string
		body string
		leak bool
	}{
		{"marker", `{"data":[{"name":"idor-abc123-ca"}]}`, true},
		{"victim id", `{"data":[{"id":"ca-victim-1"}]}`, true},
		{"own data only", `{"data":[{"name":"acme-ca"}]}`, false},
	}
	for _, c := range cases {
		got := Detect(acmeViewer, "GET", "/api/v1/cas", 200, []byte(c.body), victim)
		if (got != nil) != c.leak {
			t.Errorf("%s: leak=%v want %v (%v)", c.name, got != nil, c.leak, got)
		}
	}
}

func TestDetectCrossTenantWrite(t *testing.T) {
	if Detect(acmeViewer, "DELETE", "/api/v1/cas/ca-victim-1", 204, nil, victim) == nil {
		t.Error("2xx DELETE on a victim id must be a leak")
	}
	if DetectExchange(acmeViewer, "POST", "/api/v1/api-keys", []byte(`{"tenant":"globex"}`), 201, []byte(`{}`), victim, false) == nil {
		t.Error("2xx write naming the victim tenant must be a leak")
	}
	if DetectExchange(acmeViewer, "POST", "/api/v1/x", []byte(`{"id":"ca-victim-1"}`), 200, []byte(`{}`), victim, false) == nil {
		t.Error("2xx write carrying a victim id in the body must be a leak")
	}
	if DetectExchange(acmeViewer, "GET", "/api/v1/cas/ca-victim-1", nil, 200, []byte(`{}`), victim, true) == nil {
		t.Error("2xx on a victim-substituted path must be a leak")
	}
	if DetectExchange(acmeViewer, "GET", "/api/v1/cas/idor-nonexistent", nil, 200, []byte(`{}`), victim, false) != nil {
		t.Error("2xx on a non-victim path is not a leak")
	}
}

func TestDetectBatchRefusalIsNotALeak(t *testing.T) {
	refused := []byte(`{"succeeded":[],"failed":[{"fingerprint":"ca-victim-1","error":"not visible in your tenant"}]}`)
	req := []byte(`{"fingerprints":["ca-victim-1"]}`)
	if l := DetectExchange(acmeViewer, "POST", "/api/v1/certificates/bulk-revoke", req, 200, refused, victim, false); l != nil {
		t.Errorf("a refused batch item echoing the id is isolated, got %v", l)
	}
	done := []byte(`{"succeeded":[{"fingerprint":"ca-victim-1"}],"failed":[]}`)
	if DetectExchange(acmeViewer, "POST", "/api/v1/certificates/bulk-revoke", req, 200, done, victim, false) == nil {
		t.Error("a batch that revoked the victim's item must be a leak")
	}
}

func TestDetectIsolated403(t *testing.T) {
	for _, st := range []int{401, 403, 404, 400, 405} {
		if l := DetectExchange(acmeViewer, "DELETE", "/api/v1/cas/ca-victim-1", []byte(`{"tenant":"globex"}`), st, []byte(`idor-abc123`), victim, true); l != nil {
			t.Errorf("status %d must be isolated, got %v", st, l)
		}
	}
}

func TestDetectAllowlist(t *testing.T) {
	al, err := ParseAllowlist([]byte("# c\nGET /healthz\tliveness\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !al.Allows("GET", "/healthz") || al.Allows("POST", "/healthz") || al.Allows("GET", "/readyz") {
		t.Errorf("allowlist matching wrong: %v", al)
	}
	if _, err := ParseAllowlist([]byte("GET /healthz\n")); err == nil {
		t.Error("an entry without a reason must be rejected")
	}
	if _, err := ParseAllowlist([]byte("GET /healthz\t \n")); err == nil {
		t.Error("an entry with a blank reason must be rejected")
	}
}

// TestSeededLeakIsDetected proves the harness is not vacuous: against an
// in-process hub that deliberately returns the victim's CA to acme on one
// route, the whole pipeline (seed, probe, detect) must report that leak and
// only that route.
func TestSeededLeakIsDetected(t *testing.T) {
	res := runAgainstLeakyHub(t)
	if len(res.Leaks) < 1 {
		t.Fatal("seeded leak on GET /api/v1/cas was not detected")
	}
	for _, l := range res.Leaks {
		if l.Path != "/api/v1/cas" || l.Method != "GET" {
			t.Errorf("unexpected leak beyond the seeded one: %s", l)
		}
	}
	if want := len(Roles); len(res.Leaks) != want {
		t.Errorf("leaks=%d, want one per attacker role (%d)", len(res.Leaks), want)
	}
}

func TestDetectOwnDeniedAuditRowIsNotALeak(t *testing.T) {
	v := VictimSet{Marker: "idor-x", IDs: map[string]bool{"key-v1": true}, Tenant: "globex"}
	p := Principal{Tenant: "acme", Role: "auditor"}
	own := []byte(`{"data":[{"action":"key.op","resource_id":"key-v1","outcome":"denied","tenant":"acme"}]}`)
	if l := DetectExchange(p, "GET", "/api/v1/audit", nil, 200, own, v, false); l != nil {
		t.Fatalf("own denied probe flagged: %v", l)
	}
	foreign := []byte(`{"data":[{"action":"key.op","resource_id":"key-v1","outcome":"success","tenant":"globex"}]}`)
	if l := DetectExchange(p, "GET", "/api/v1/audit", nil, 200, foreign, v, false); l == nil {
		t.Fatal("victim tenant audit row not flagged")
	}
	ownSuccess := []byte(`{"data":[{"action":"key.op","resource_id":"key-v1","outcome":"success","tenant":"acme"}]}`)
	if l := DetectExchange(p, "GET", "/api/v1/audit", nil, 200, ownSuccess, v, false); l == nil {
		t.Fatal("successful action on victim id in attacker tenant not flagged")
	}
}

func TestDetectOwnDeniedAuditExportRowIsNotALeak(t *testing.T) {
	v := VictimSet{Marker: "idor-x", IDs: map[string]bool{"tpl-idor-x-1": true}, Tenant: "globex"}
	p := Principal{Tenant: "acme", Role: "auditor"}
	csvOwn := []byte("id,timestamp,action,actor_type,actor_id,resource_type,resource_id,trace_id,outcome,tenant\n" +
		"66,t,template.get,user,atk-acme,template,tpl-idor-x-1,,denied,acme\n")
	if l := DetectExchange(p, "GET", "/api/v1/audit/export?format=csv", nil, 200, csvOwn, v, false); l != nil {
		t.Fatalf("own denied CSV row flagged: %v", l)
	}
	csvForeign := []byte("id,timestamp,action,actor_type,actor_id,resource_type,resource_id,trace_id,outcome,tenant\n" +
		"67,t,template.create,user,svc-globex,template,tpl-idor-x-1,,success,globex\n")
	if l := DetectExchange(p, "GET", "/api/v1/audit/export", nil, 200, csvForeign, v, false); l == nil {
		t.Fatal("victim tenant CSV row not flagged")
	}
	jsonOwn := []byte(`[{"resource_id":"tpl-idor-x-1","outcome":"denied","tenant":"acme"}]`)
	if l := DetectExchange(p, "GET", "/api/v1/audit/export?format=json", nil, 200, jsonOwn, v, false); l != nil {
		t.Fatalf("own denied JSON row flagged: %v", l)
	}
	jsonForeign := []byte(`[{"resource_id":"tpl-idor-x-1","outcome":"success","tenant":"globex"}]`)
	if l := DetectExchange(p, "GET", "/api/v1/audit/export?format=json", nil, 200, jsonForeign, v, false); l == nil {
		t.Fatal("victim tenant JSON row not flagged")
	}
}
