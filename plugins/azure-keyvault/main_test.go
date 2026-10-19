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
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

const (
	clientSecret = "azure-client-secret-xyz"
	accessTok    = "eyJ0eXAi.access-token-abc"
	keyMarker    = "TOP-SECRET-KEY-BYTES"
	vaultHost    = "kv1.vault.azure.net"
)

func newCert(t *testing.T, cn string) (certPEM string) {
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
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func fpOf(certPEM string) string {
	b, _ := pem.Decode([]byte(certPEM))
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

type ver struct {
	id      string
	value   string
	enabled bool
}

// fakeKV models the 7.4 Set/Get/Update Secret shapes and the token endpoint.
type fakeKV struct {
	t         *testing.T
	versions  []ver
	failPut   bool
	tamperNew bool // reading back the newest version returns other content
	failToken bool
	failPatch bool
	puts      int
	patches   int
	seen      []string
	logs      []string
}

func (f *fakeKV) seed(certPEM string) {
	f.versions = append(f.versions, ver{id: fmt.Sprintf("%032x", len(f.versions)+1), value: certPEM + "\nold-key", enabled: true})
}

func (f *fakeKV) host() *delivery.Host { return delivery.NewHost(f.call) }

func (f *fakeKV) call(op string, in []byte) ([]byte, error) {
	if op != abi.HostHTTP {
		if op == abi.HostLog {
			f.logs = append(f.logs, string(in))
		}
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

func js(v any) []byte { b, _ := json.Marshal(v); return b }

func (f *fakeKV) bundle(v ver) map[string]any {
	return map[string]any{"value": v.value, "id": "https://" + vaultHost + "/secrets/shop-cert/" + v.id,
		"attributes": map[string]any{"enabled": v.enabled, "created": 1493938410}}
}

func (f *fakeKV) serve(req abi.HTTPRequest) (int, []byte) {
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" {
		f.t.Fatalf("unexpected URL %s", req.URL)
	}
	f.seen = append(f.seen, req.Method+" "+u.Host+u.Path)
	if u.Host == "login.microsoftonline.com" {
		form, _ := url.ParseQuery(string(req.Body))
		if u.Path != "/tenant-1/oauth2/v2.0/token" || req.Method != "POST" ||
			form.Get("grant_type") != "client_credentials" || form.Get("client_id") != "client-1" ||
			form.Get("client_secret") != clientSecret || form.Get("scope") != "https://vault.azure.net/.default" ||
			req.Headers["Content-Type"] != "application/x-www-form-urlencoded" {
			f.t.Errorf("bad token request %s %s %q", req.Method, u.Path, req.Body)
		}
		if f.failToken {
			return 401, []byte(`{"error":"invalid_client","error_description":"` + clientSecret + `"}`)
		}
		return 200, js(map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": accessTok})
	}
	if u.Host != vaultHost {
		f.t.Fatalf("unexpected host %s", u.Host)
	}
	if req.Headers["Authorization"] != "Bearer "+accessTok {
		return 401, []byte(`{"error":{"code":"Unauthorized"}}`)
	}
	if u.Query().Get("api-version") != "7.4" {
		f.t.Errorf("api-version = %q", u.Query().Get("api-version"))
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	switch {
	case req.Method == "GET" && u.Path == "/secrets":
		return 200, js(map[string]any{"value": []any{}, "nextLink": nil})
	case len(parts) >= 2 && parts[0] == "secrets" && parts[1] == "shop-cert":
	default:
		f.t.Fatalf("unexpected request %s %s", req.Method, u.Path)
	}
	find := func() (int, bool) {
		if len(parts) == 2 {
			return len(f.versions) - 1, len(f.versions) > 0
		}
		for i, v := range f.versions {
			if v.id == parts[2] {
				return i, true
			}
		}
		return 0, false
	}
	switch req.Method {
	case "GET":
		i, ok := find()
		if !ok {
			return 404, []byte(`{"error":{"code":"SecretNotFound"}}`)
		}
		v := f.versions[i]
		if !v.enabled {
			return 403, []byte(`{"error":{"code":"Forbidden","message":"Operation get is not allowed on a disabled secret."}}`)
		}
		if f.tamperNew && i == len(f.versions)-1 {
			v.value = newCertForTamper + "\n" + keyMarker
		}
		return 200, js(f.bundle(v))
	case "PUT":
		f.puts++
		if f.failPut {
			return 500, []byte(`{"error":{"code":"InternalServerError"}}`)
		}
		var b struct{ Value, ContentType string }
		_ = json.Unmarshal(req.Body, &b)
		if b.ContentType != "application/x-pem-file" {
			f.t.Errorf("contentType = %q", b.ContentType)
		}
		f.versions = append(f.versions, ver{id: fmt.Sprintf("%032x", len(f.versions)+1), value: b.Value, enabled: true})
		return 200, js(f.bundle(f.versions[len(f.versions)-1]))
	case "PATCH":
		f.patches++
		i, ok := find()
		if !ok || f.failPatch {
			return 500, []byte(`{"error":{"code":"InternalServerError"}}`)
		}
		var b struct {
			Attributes struct {
				Enabled *bool `json:"enabled"`
			} `json:"attributes"`
		}
		_ = json.Unmarshal(req.Body, &b)
		if b.Attributes.Enabled == nil {
			f.t.Error("PATCH without attributes.enabled")
			return 400, nil
		}
		f.versions[i].enabled = *b.Attributes.Enabled
		return 200, js(f.bundle(f.versions[i]))
	}
	f.t.Fatalf("unexpected request %s %s", req.Method, u.Path)
	return 0, nil
}

var newCertForTamper string

func inv() abi.Invocation {
	return abi.Invocation{
		Credential: map[string]string{"vault_url": "https://" + vaultHost, "tenant_id": "tenant-1", "client_id": "client-1", "client_secret": clientSecret},
		Target:     map[string]string{"secret_name": "shop-cert"},
	}
}

func push(f *fakeKV, certPEM string) (abi.PushResult, error) {
	return akv{}.Push(f.host(), abi.PushRequest{Invocation: inv(), Name: "shop", CertPEM: certPEM, KeyPEM: "-----BEGIN PRIVATE KEY-----\n" + keyMarker + "\n-----END PRIVATE KEY-----\n"})
}

// newest is the version a reader of the unversioned secret gets.
func (f *fakeKV) newest() (ver, bool) {
	if len(f.versions) == 0 {
		return ver{}, false
	}
	v := f.versions[len(f.versions)-1]
	return v, v.enabled
}

func noSecrets(t *testing.T, f *fakeKV, ss ...string) {
	t.Helper()
	ss = append(ss, f.logs...)
	for _, s := range ss {
		if strings.Contains(s, clientSecret) || strings.Contains(s, accessTok) || strings.Contains(s, keyMarker) || strings.Contains(s, "BEGIN") {
			t.Errorf("secret material in %q", s)
		}
	}
}

func TestValidate(t *testing.T) {
	f := &fakeKV{t: t}
	if err := (akv{}).Validate(f.host(), abi.ValidateRequest{Invocation: inv()}); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestPushAddsVersionAndReadsBack(t *testing.T) {
	f := &fakeKV{t: t}
	f.seed(newCert(t, "old"))
	newPEM := newCert(t, "new")
	res, err := push(f, newPEM)
	if err != nil || !res.Installed || res.Outcome != abi.OutcomeInstalled {
		t.Fatalf("push: %+v %v", res, err)
	}
	if len(f.versions) != 2 || f.puts != 1 || f.patches != 0 {
		t.Fatalf("versions=%d puts=%d patches=%d", len(f.versions), f.puts, f.patches)
	}
	if !strings.HasPrefix(f.versions[1].value, newPEM) || !strings.Contains(f.versions[1].value, keyMarker) {
		t.Fatal("stored value is not certificate then key")
	}
	var hd handle
	if json.Unmarshal([]byte(res.RollbackHandle), &hd) != nil || hd.Prior != f.versions[0].id || hd.New != f.versions[1].id {
		t.Fatalf("handle %q", res.RollbackHandle)
	}
	// Verify returns the exact version Push wrote, certificate blocks only.
	f.seed(newCert(t, "someone else wrote after us"))
	vr, err := akv{}.Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Name: "shop", Handle: res.RollbackHandle})
	if err != nil || fpOf(vr.CertPEM) != fpOf(newPEM) || strings.Contains(vr.CertPEM, "PRIVATE") || strings.Contains(vr.CertPEM, keyMarker) {
		t.Fatalf("verify: %+v %v", vr, err)
	}
	noSecrets(t, f, res.Detail)
}

func TestPushFirstVersion(t *testing.T) {
	f := &fakeKV{t: t}
	res, err := push(f, newCert(t, "first"))
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	if err != nil || !res.Installed || hd.Prior != "" || hd.New == "" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestWriteFailureLeavesPreviousCurrent(t *testing.T) {
	f := &fakeKV{t: t, failPut: true}
	oldPEM := newCert(t, "old")
	f.seed(oldPEM)
	res, _ := push(f, newCert(t, "new"))
	cur, ok := f.newest()
	if res.Outcome != abi.OutcomeWriteFailed || res.Installed || f.patches != 0 || len(f.versions) != 1 || !ok || !strings.HasPrefix(cur.value, oldPEM) {
		t.Fatalf("%+v patches=%d", res, f.patches)
	}
	noSecrets(t, f, res.Detail)
}

func TestReadbackMismatchRestoresPrevious(t *testing.T) {
	f := &fakeKV{t: t, tamperNew: true}
	newCertForTamper = newCert(t, "other")
	oldPEM := newCert(t, "old")
	f.seed(oldPEM)
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || res.Installed || strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("%+v", res)
	}
	f.tamperNew = false
	cur, ok := f.newest()
	// v2 (bad) disabled, v3 is the restored old content and is what readers get.
	if len(f.versions) != 3 || f.versions[1].enabled || !ok || fpOf(cur.value) != fpOf(oldPEM) {
		t.Fatalf("versions=%+v", f.versions)
	}
	noSecrets(t, f, res.Detail)
}

func TestReadbackMismatchFirstVersionDisablesNew(t *testing.T) {
	f := &fakeKV{t: t, tamperNew: true}
	newCertForTamper = newCert(t, "other")
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || f.versions[0].enabled || f.patches != 1 {
		t.Fatalf("%+v %+v", res, f.versions)
	}
}

func TestRollbackRestoresPrior(t *testing.T) {
	f := &fakeKV{t: t}
	oldPEM := newCert(t, "old")
	f.seed(oldPEM)
	res, _ := push(f, newCert(t, "new"))
	rb, err := akv{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	cur, ok := f.newest()
	if err != nil || !rb.RolledBack || f.versions[1].enabled || !ok || fpOf(cur.value) != fpOf(oldPEM) {
		t.Fatalf("%+v %v %+v", rb, err, f.versions)
	}
	noSecrets(t, f, rb.Detail)
}

func TestRollbackWithoutPriorDisablesNew(t *testing.T) {
	f := &fakeKV{t: t}
	res, _ := push(f, newCert(t, "first"))
	rb, _ := akv{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if !rb.RolledBack || f.versions[0].enabled || !strings.Contains(rb.Detail, "no previous version") {
		t.Fatalf("%+v %+v", rb, f.versions)
	}
	// A later push still works although the newest version is disabled (403 on read).
	res2, _ := push(f, newCert(t, "again"))
	if !res2.Installed {
		t.Fatalf("%+v", res2)
	}
}

func TestRollbackFailureNotReportedAsRolledBack(t *testing.T) {
	f := &fakeKV{t: t}
	f.seed(newCert(t, "old"))
	res, _ := push(f, newCert(t, "new"))
	f.failPut = true
	rb, _ := akv{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if rb.RolledBack || rb.Detail == "" {
		t.Fatalf("%+v", rb)
	}
	first := &fakeKV{t: t, failPatch: true}
	res, _ = push(first, newCert(t, "first"))
	rb, _ = akv{}.Rollback(first.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if rb.RolledBack {
		t.Fatalf("disable failure reported as rolled back: %+v", rb)
	}
	noSecrets(t, f, rb.Detail)
}

func TestTokenFailureIsWriteFailed(t *testing.T) {
	f := &fakeKV{t: t, failToken: true}
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeWriteFailed || res.Detail != "token request: HTTP 401" {
		t.Fatalf("%+v", res)
	}
	noSecrets(t, f, res.Detail)
	if err := (akv{}).Validate(f.host(), abi.ValidateRequest{Invocation: inv()}); err == nil || err.Error() != "token request: HTTP 401" {
		t.Fatalf("validate: %v", err)
	}
}

func TestCredentialsNeverAppearInOutput(t *testing.T) {
	f := &fakeKV{t: t, tamperNew: true, failPatch: true}
	newCertForTamper = newCert(t, "other")
	f.seed(newCert(t, "old"))
	res, _ := push(f, newCert(t, "new"))
	vr, verr := akv{}.Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Handle: `{"prior":"","new":"` + f.versions[0].id + `"}`})
	errText := ""
	if verr != nil {
		errText = verr.Error()
	}
	noSecrets(t, f, res.Detail, errText)
	if strings.Contains(vr.CertPEM, "PRIVATE") || strings.Contains(vr.CertPEM, keyMarker) {
		t.Error("Verify returned key material")
	}
}

func TestRejectsBadSecretNameAndHandle(t *testing.T) {
	f := &fakeKV{t: t}
	bad := inv()
	bad.Target["secret_name"] = "../x"
	if res, _ := (akv{}).Push(f.host(), abi.PushRequest{Invocation: bad, CertPEM: newCert(t, "x")}); res.Outcome != abi.OutcomeWriteFailed || len(f.seen) != 0 {
		t.Fatalf("%+v seen=%v", res, f.seen)
	}
	if _, err := (akv{}).Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Handle: `{"new":"../../x"}`}); err == nil {
		t.Fatal("bad handle accepted")
	}
}
