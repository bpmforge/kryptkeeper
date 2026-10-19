// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

const (
	testToken = "hvs.test-token-0123456789"
	keyMarker = "TOP-SECRET-KEY-BYTES"
)

func newCert(t *testing.T, cn string) (certPEM, fp string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

// fakeVault models the documented KV v2 endpoints (api-docs/secret/kv/kv-v2):
// read version, create/update with options.cas, read metadata, delete
// versions, read config, plus auth/token/lookup-self.
type fakeVault struct {
	t         *testing.T
	versions  map[int]map[string]any // version -> data
	deleted   map[int]bool
	current   int
	posts     int
	failPost  bool           // data POST answers 500
	tamperNew bool           // reading back the newest version returns a different cert
	failGet   map[int]bool   // GET data?version=N answers 500
	seen      []string       // "METHOD path" log
	other     map[string]any // content tamperNew serves
	badToken  bool
}

func newFakeVault(t *testing.T) *fakeVault {
	return &fakeVault{t: t, versions: map[int]map[string]any{}, deleted: map[int]bool{}, failGet: map[int]bool{}}
}

func (f *fakeVault) seed(certPEM string) {
	f.current++
	f.versions[f.current] = map[string]any{"certificate": certPEM, "private_key": "old-key"}
}

func (f *fakeVault) host() *delivery.Host { return delivery.NewHost(f.call) }

func (f *fakeVault) call(op string, in []byte) ([]byte, error) {
	{
		if op != abi.HostHTTP {
			return json.Marshal(abi.HostReply{})
		}
		var req abi.HTTPRequest
		if err := json.Unmarshal(in, &req); err != nil {
			f.t.Fatal(err)
		}
		status, body := f.serve(req)
		resp, _ := json.Marshal(abi.HTTPResponse{Status: status, Body: body})
		return json.Marshal(abi.HostReply{Result: resp})
	}
}

func jsonBody(v any) []byte { b, _ := json.Marshal(v); return b }

func (f *fakeVault) serve(req abi.HTTPRequest) (int, []byte) {
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" || u.Host != "vault.example.com:8200" {
		f.t.Fatalf("unexpected URL %s", req.URL)
	}
	f.seen = append(f.seen, req.Method+" "+u.Path)
	if req.Headers["X-Vault-Token"] != testToken {
		return 403, []byte(`{"errors":["permission denied"]}`)
	}
	if req.Headers["X-Vault-Namespace"] != "team-a" {
		f.t.Errorf("namespace header = %q", req.Headers["X-Vault-Namespace"])
	}
	if req.Body != nil && req.Headers["Content-Type"] != "application/json" {
		f.t.Errorf("content-type = %q", req.Headers["Content-Type"])
	}
	p := strings.TrimPrefix(u.Path, "/v1/")
	switch {
	case req.Method == "GET" && p == "auth/token/lookup-self":
		return 200, jsonBody(map[string]any{"data": map[string]any{"id": "redacted"}})
	case req.Method == "GET" && p == "kv/config":
		return 200, jsonBody(map[string]any{"data": map[string]any{"cas_required": false, "delete_version_after": "0s", "max_versions": 0}})
	case req.Method == "GET" && p == "kv/metadata/certs/shop":
		if f.current == 0 {
			return 404, []byte(`{"errors":[]}`)
		}
		return 200, jsonBody(map[string]any{"data": map[string]any{"current_version": f.current, "oldest_version": 0}})
	case req.Method == "GET" && p == "kv/data/certs/shop":
		n, _ := strconv.Atoi(u.Query().Get("version"))
		if n == 0 {
			n = f.current
		}
		if f.failGet[n] {
			return 500, []byte("boom " + keyMarker)
		}
		d, ok := f.versions[n]
		if !ok || f.deleted[n] {
			return 404, []byte(`{"errors":[]}`)
		}
		if f.tamperNew && n == f.current && f.other != nil {
			d = f.other
		}
		return 200, jsonBody(map[string]any{"data": map[string]any{"data": d, "metadata": map[string]any{"version": n, "destroyed": false, "deletion_time": ""}}})
	case req.Method == "POST" && p == "kv/data/certs/shop":
		f.posts++
		if f.failPost {
			return 500, []byte(`{"errors":["internal"]}`)
		}
		var b struct {
			Options struct {
				Cas *int `json:"cas"`
			} `json:"options"`
			Data map[string]any `json:"data"`
		}
		_ = json.Unmarshal(req.Body, &b)
		if b.Options.Cas == nil || *b.Options.Cas != f.current {
			return 400, []byte(`{"errors":["check-and-set parameter did not match the current version"]}`)
		}
		f.current++
		f.versions[f.current] = b.Data
		return 200, jsonBody(map[string]any{"data": map[string]any{"version": f.current, "destroyed": false, "created_time": "2018-03-22T02:36:43.986212308Z"}})
	case req.Method == "POST" && p == "kv/delete/certs/shop":
		var b struct {
			Versions []int `json:"versions"`
		}
		_ = json.Unmarshal(req.Body, &b)
		for _, v := range b.Versions {
			f.deleted[v] = true
		}
		return 204, nil
	}
	f.t.Fatalf("unexpected request %s %s", req.Method, u.Path)
	return 0, nil
}

func inv() abi.Invocation {
	return abi.Invocation{
		Credential: map[string]string{"base_url": "https://vault.example.com:8200", "token": testToken, "namespace": "team-a"},
		Target:     map[string]string{"mount": "kv", "path": "certs/shop"},
	}
}

func push(f *fakeVault, certPEM string) (abi.PushResult, error) {
	return kv{}.Push(f.host(), abi.PushRequest{Invocation: inv(), Name: "shop", CertPEM: certPEM, KeyPEM: "-----BEGIN PRIVATE KEY-----\n" + keyMarker + "\n-----END PRIVATE KEY-----\n"})
}

func noSecrets(t *testing.T, ss ...string) {
	t.Helper()
	for _, s := range ss {
		if strings.Contains(s, testToken) || strings.Contains(s, keyMarker) || strings.Contains(s, "BEGIN") {
			t.Errorf("secret material in %q", s)
		}
	}
}

func TestValidate(t *testing.T) {
	f := newFakeVault(t)
	if err := (kv{}).Validate(f.host(), abi.ValidateRequest{Invocation: inv()}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	bad := inv()
	bad.Credential["token"] = "wrong"
	if err := (kv{}).Validate(f.host(), abi.ValidateRequest{Invocation: bad}); err == nil {
		t.Fatal("bad token accepted")
	}
}

func TestPushWritesNewVersionAndReadsBack(t *testing.T) {
	f := newFakeVault(t)
	oldPEM, _ := newCert(t, "old")
	f.seed(oldPEM)
	newPEM, newFP := newCert(t, "new")
	res, err := push(f, newPEM)
	if err != nil || !res.Installed || res.Outcome != abi.OutcomeInstalled {
		t.Fatalf("push: %+v %v", res, err)
	}
	if f.current != 2 || f.posts != 1 {
		t.Fatalf("current=%d posts=%d", f.current, f.posts)
	}
	if fingerprintOf(f.versions[2]["certificate"].(string)) != newFP {
		t.Fatal("stored version is not the new leaf")
	}
	if f.versions[2]["fingerprint_sha256"] != newFP || f.versions[2]["private_key"] == "" {
		t.Fatalf("stored fields %v", f.versions[2])
	}
	var hd handle
	if err := json.Unmarshal([]byte(res.RollbackHandle), &hd); err != nil || hd.Prior != 1 || hd.New != 2 {
		t.Fatalf("handle %q", res.RollbackHandle)
	}
	// Verify returns the exact version Push wrote, even if a newer one lands.
	f.seed("someone else wrote after us")
	vr, err := kv{}.Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Name: "shop", Handle: res.RollbackHandle})
	if err != nil || fingerprintOf(vr.CertPEM) != newFP {
		t.Fatalf("verify: %+v %v", vr, err)
	}
	noSecrets(t, res.Detail)
}

func fingerprintOf(p string) string { return fingerprint(p) }

func TestPushFirstWriteHasCas0(t *testing.T) {
	f := newFakeVault(t)
	pemData, _ := newCert(t, "first")
	res, err := push(f, pemData)
	if err != nil || !res.Installed {
		t.Fatalf("push: %+v %v", res, err)
	}
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	if hd.Prior != 0 || hd.New != 1 || f.current != 1 {
		t.Fatalf("handle %+v current %d", hd, f.current)
	}
}

func TestWriteFailureLeavesPreviousCurrent(t *testing.T) {
	f := newFakeVault(t)
	oldPEM, _ := newCert(t, "old")
	f.seed(oldPEM)
	f.failPost = true
	newPEM, _ := newCert(t, "new")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeWriteFailed || res.Installed || f.current != 1 || f.posts != 1 {
		t.Fatalf("%+v current=%d posts=%d", res, f.current, f.posts)
	}
	noSecrets(t, res.Detail)
}

func TestCasConflictIsWriteFailed(t *testing.T) {
	f := newFakeVault(t)
	oldPEM, _ := newCert(t, "old")
	f.seed(oldPEM)
	h := delivery.NewHost(func(op string, in []byte) ([]byte, error) {
		// A concurrent writer lands between our metadata read and our write.
		var req abi.HTTPRequest
		_ = json.Unmarshal(in, &req)
		if req.Method == "POST" {
			f.seed("concurrent")
		}
		return f.call(op, in)
	})
	newPEM, _ := newCert(t, "new")
	res, _ := kv{}.Push(h, abi.PushRequest{Invocation: inv(), CertPEM: newPEM, KeyPEM: "k"})
	if res.Outcome != abi.OutcomeWriteFailed || f.current != 2 || f.versions[2]["certificate"] != "concurrent" {
		t.Fatalf("a concurrent writer was overwritten: %+v current=%d", res, f.current)
	}
}

func TestReadbackMismatchRestoresPrevious(t *testing.T) {
	f := newFakeVault(t)
	oldPEM, oldFP := newCert(t, "old")
	f.seed(oldPEM)
	otherPEM, _ := newCert(t, "other")
	f.tamperNew, f.other = true, map[string]any{"certificate": otherPEM}
	newPEM, _ := newCert(t, "new")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeBindingFailed || res.Installed {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("restore failed: %s", res.Detail)
	}
	// Restore wrote the old content as the newest version.
	if f.current != 3 || fingerprintOf(f.versions[3]["certificate"].(string)) != oldFP {
		t.Fatalf("current=%d", f.current)
	}
	noSecrets(t, res.Detail)
}

func TestReadbackMismatchFirstWriteDeletesNew(t *testing.T) {
	f := newFakeVault(t)
	otherPEM, _ := newCert(t, "other")
	f.tamperNew, f.other = true, map[string]any{"certificate": otherPEM}
	newPEM, _ := newCert(t, "new")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeBindingFailed || !f.deleted[1] {
		t.Fatalf("%+v deleted=%v", res, f.deleted)
	}
}

func TestRestoreFailureIsReported(t *testing.T) {
	f := newFakeVault(t)
	oldPEM, _ := newCert(t, "old")
	f.seed(oldPEM)
	f.failGet[1] = true // the prior version cannot be read for the restore
	otherPEM, _ := newCert(t, "other")
	f.tamperNew, f.other = true, map[string]any{"certificate": otherPEM}
	newPEM, _ := newCert(t, "new")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeBindingFailed || !strings.HasSuffix(res.Detail, "RESTORE FAILED: GET /v1/kv/data/certs/shop?version=1: HTTP 500") {
		t.Fatalf("%+v", res)
	}
	noSecrets(t, res.Detail)
}

func TestRollbackRewritesPrior(t *testing.T) {
	f := newFakeVault(t)
	oldPEM, oldFP := newCert(t, "old")
	f.seed(oldPEM)
	newPEM, _ := newCert(t, "new")
	res, _ := push(f, newPEM)
	rb, err := kv{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if err != nil || !rb.RolledBack {
		t.Fatalf("%+v %v", rb, err)
	}
	if f.current != 3 || fingerprintOf(f.versions[3]["certificate"].(string)) != oldFP {
		t.Fatalf("latest is not the previous content (current=%d)", f.current)
	}
}

func TestRollbackFirstWriteSoftDeletes(t *testing.T) {
	f := newFakeVault(t)
	newPEM, _ := newCert(t, "new")
	res, _ := push(f, newPEM)
	rb, _ := kv{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if !rb.RolledBack || !f.deleted[1] {
		t.Fatalf("%+v deleted=%v", rb, f.deleted)
	}
}

func TestRollbackFailureReportsNotRolledBack(t *testing.T) {
	f := newFakeVault(t)
	oldPEM, _ := newCert(t, "old")
	f.seed(oldPEM)
	newPEM, _ := newCert(t, "new")
	res, _ := push(f, newPEM)
	f.failPost = true
	rb, _ := kv{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if rb.RolledBack || rb.Detail == "" {
		t.Fatalf("%+v", rb)
	}
	// A concurrent write after Push makes the cas fail: also not rolled back.
	f.failPost = false
	f.seed("concurrent")
	if rb, _ = (kv{}).Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle}); rb.RolledBack {
		t.Fatalf("rollback claimed success over a concurrent write: %+v", rb)
	}
	if rb, _ = (kv{}).Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: "garbage"}); rb.RolledBack {
		t.Fatal("garbage handle rolled back")
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	f := newFakeVault(t)
	if _, err := (kv{}).Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Handle: "nope"}); err == nil {
		t.Error("bad handle accepted")
	}
	if _, err := (kv{}).Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Handle: `{"prior":0,"new":9}`}); err == nil {
		t.Error("missing version returned no error")
	}
}

func TestNoSecretInDetailOrErrors(t *testing.T) {
	f := newFakeVault(t)
	pemData, _ := newCert(t, "x")
	f.failGet[1] = true // read-back GET answers 500 with a body containing key text
	res, _ := push(f, pemData)
	noSecrets(t, res.Detail, res.Outcome)
	bad := inv()
	bad.Credential["token"] = "wrong"
	r2, _ := kv{}.Push(f.host(), abi.PushRequest{Invocation: bad, CertPEM: pemData, KeyPEM: "k"})
	noSecrets(t, r2.Detail)
}

func TestRejectsPathTraversal(t *testing.T) {
	f := newFakeVault(t)
	pemData, _ := newCert(t, "x")
	for _, p := range []string{"../etc", "a/../b", "/abs", "a?x=1", "a#f", "", "a//b", "a b", "a/"} {
		i := inv()
		i.Target["path"] = p
		res, _ := kv{}.Push(f.host(), abi.PushRequest{Invocation: i, CertPEM: pemData, KeyPEM: "k"})
		if res.Outcome != abi.OutcomeWriteFailed || res.Installed {
			t.Errorf("path %q accepted: %+v", p, res)
		}
	}
	for _, m := range []string{"../kv", "kv?x", "a b"} {
		i := inv()
		i.Target["mount"] = m
		if _, _, err := locate(i); err == nil {
			t.Errorf("mount %q accepted", m)
		}
	}
	if len(f.seen) != 0 {
		t.Errorf("requests sent for rejected input: %v", f.seen)
	}
}
