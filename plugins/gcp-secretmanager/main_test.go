// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	accessTok = "ya29.access-token-abc"
	keyMarker = "TOP-SECRET-KEY-BYTES"
	saEmail   = "kk@proj-1.iam.gserviceaccount.com"
	sec       = "projects/proj-1/secrets/shop-cert"
)

var (
	testKey  *rsa.PrivateKey
	saJSON   string
	fixedNow = time.Unix(1_800_000_000, 0)
	otherPEM string
)

func init() {
	var err error
	if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(testKey)
	pk := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": saEmail, "private_key": pk, "token_uri": "https://evil.example/token"})
	saJSON = string(b)
	now = func() time.Time { return fixedNow }
}

func newCert(t *testing.T, cn string) string {
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
	value string
	state string
}

// fakeSM models secrets.get/create, versions.get/access/disable and
// secrets.addVersion (SecretVersion.name, state; payload.data base64).
type fakeSM struct {
	t          *testing.T
	exists     bool
	versions   []ver
	failAdd    bool
	tamperNew  bool
	failToken  bool
	failDis    bool
	adds       int
	disables   int
	creates    int
	tokenCalls int
	logs       []string
}

func (f *fakeSM) seed(certPEM string) {
	f.exists = true
	f.versions = append(f.versions, ver{value: certPEM + "\nold-key", state: "ENABLED"})
}

func (f *fakeSM) host() *delivery.Host { return delivery.NewHost(f.call) }

func (f *fakeSM) call(op string, in []byte) ([]byte, error) {
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

func (f *fakeSM) checkJWT(assertion string) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		f.t.Fatalf("assertion has %d parts", len(parts))
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cl, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if string(hdr) != `{"alg":"RS256","typ":"JWT"}` {
		f.t.Errorf("header %s", hdr)
	}
	var c struct {
		Iss, Scope, Aud string
		Iat, Exp        int64
	}
	_ = json.Unmarshal(cl, &c)
	if c.Iss != saEmail || c.Scope != "https://www.googleapis.com/auth/cloud-platform" || c.Aud != "https://oauth2.googleapis.com/token" ||
		c.Iat != fixedNow.Unix() || c.Exp != fixedNow.Unix()+3600 {
		f.t.Errorf("claims %+v", c)
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, d[:], sig); err != nil {
		f.t.Errorf("bad signature: %v", err)
	}
}

func (f *fakeSM) version(n string) (int, bool) {
	var i int
	if _, err := fmt.Sscanf(n, "%d", &i); err != nil || i < 1 || i > len(f.versions) {
		return 0, false
	}
	return i - 1, true
}

func (f *fakeSM) serve(req abi.HTTPRequest) (int, []byte) {
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" {
		f.t.Fatalf("unexpected URL %s", req.URL)
	}
	if u.Host == "oauth2.googleapis.com" {
		f.tokenCalls++
		form, _ := url.ParseQuery(string(req.Body))
		if u.Path != "/token" || req.Method != "POST" || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			f.t.Errorf("bad token request %s %s", req.Method, u.Path)
		}
		f.checkJWT(form.Get("assertion"))
		if f.failToken {
			return 400, []byte(`{"error":"invalid_grant","error_description":"` + form.Get("assertion") + `"}`)
		}
		return 200, js(map[string]any{"access_token": accessTok, "expires_in": 3599, "token_type": "Bearer"})
	}
	if u.Host != "secretmanager.googleapis.com" {
		f.t.Fatalf("unexpected host %s", u.Host)
	}
	if req.Headers["Authorization"] != "Bearer "+accessTok {
		return 401, []byte(`{"error":{"status":"UNAUTHENTICATED"}}`)
	}
	path := strings.TrimPrefix(u.Path, "/v1/")
	notFound := []byte(`{"error":{"code":404,"status":"NOT_FOUND"}}`)
	switch {
	case req.Method == "GET" && path == "projects/proj-1/secrets":
		return 200, js(map[string]any{"secrets": []any{}})
	case req.Method == "GET" && path == sec:
		if !f.exists {
			return 404, notFound
		}
		return 200, js(map[string]any{"name": sec})
	case req.Method == "POST" && path == "projects/proj-1/secrets":
		f.creates++
		var b struct {
			Replication struct {
				Automatic *struct{} `json:"automatic"`
			} `json:"replication"`
		}
		_ = json.Unmarshal(req.Body, &b)
		if u.Query().Get("secretId") != "shop-cert" || b.Replication.Automatic == nil {
			f.t.Errorf("bad create %s %s", u.RawQuery, req.Body)
		}
		f.exists = true
		return 200, js(map[string]any{"name": sec})
	case req.Method == "GET" && path == sec+"/versions/latest":
		if len(f.versions) == 0 {
			return 404, notFound
		}
		i := len(f.versions) - 1
		return 200, js(map[string]any{"name": fmt.Sprintf("%s/versions/%d", sec, i+1), "state": f.versions[i].state})
	case req.Method == "POST" && path == sec+":addVersion":
		f.adds++
		if f.failAdd {
			return 500, []byte(`{"error":{"status":"INTERNAL"}}`)
		}
		var b struct {
			Payload struct {
				Data string `json:"data"`
			} `json:"payload"`
		}
		_ = json.Unmarshal(req.Body, &b)
		raw, err := base64.StdEncoding.DecodeString(b.Payload.Data)
		if err != nil {
			f.t.Errorf("payload.data not base64")
		}
		f.versions = append(f.versions, ver{value: string(raw), state: "ENABLED"})
		return 200, js(map[string]any{"name": fmt.Sprintf("%s/versions/%d", sec, len(f.versions)), "state": "ENABLED"})
	case req.Method == "GET" && strings.HasPrefix(path, sec+"/versions/") && strings.HasSuffix(path, ":access"):
		n := strings.TrimSuffix(strings.TrimPrefix(path, sec+"/versions/"), ":access")
		i, ok := f.version(n)
		if !ok {
			return 404, notFound
		}
		if f.versions[i].state != "ENABLED" {
			return 400, []byte(`{"error":{"status":"FAILED_PRECONDITION"}}`)
		}
		val := f.versions[i].value
		if f.tamperNew && i == len(f.versions)-1 {
			val = otherPEM + "\n" + keyMarker
		}
		return 200, js(map[string]any{"name": fmt.Sprintf("%s/versions/%d", sec, i+1),
			"payload": map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(val))}})
	case req.Method == "POST" && strings.HasSuffix(path, ":disable"):
		f.disables++
		n := strings.TrimSuffix(strings.TrimPrefix(path, sec+"/versions/"), ":disable")
		i, ok := f.version(n)
		if !ok || f.failDis {
			return 500, []byte(`{"error":{"status":"INTERNAL"}}`)
		}
		f.versions[i].state = "DISABLED"
		return 200, js(map[string]any{"name": fmt.Sprintf("%s/versions/%d", sec, i+1), "state": "DISABLED"})
	}
	f.t.Fatalf("unexpected request %s %s", req.Method, u.Path)
	return 0, nil
}

func inv() abi.Invocation {
	return abi.Invocation{
		Credential: map[string]string{"service_account_json": saJSON, "project_id": "proj-1"},
		Target:     map[string]string{"secret_id": "shop-cert"},
	}
}

func push(f *fakeSM, certPEM string) (abi.PushResult, error) {
	return gcp{}.Push(f.host(), abi.PushRequest{Invocation: inv(), Name: "shop", CertPEM: certPEM, KeyPEM: "-----BEGIN PRIVATE KEY-----\n" + keyMarker + "\n-----END PRIVATE KEY-----\n"})
}

func (f *fakeSM) latestEnabled() (ver, bool) {
	if len(f.versions) == 0 {
		return ver{}, false
	}
	v := f.versions[len(f.versions)-1]
	return v, v.state == "ENABLED"
}

func noSecrets(t *testing.T, f *fakeSM, ss ...string) {
	t.Helper()
	ss = append(ss, f.logs...)
	pk := strings.Split(saJSON, "private_key")[1][:60]
	for _, s := range ss {
		if strings.Contains(s, accessTok) || strings.Contains(s, keyMarker) || strings.Contains(s, "BEGIN") ||
			strings.Contains(s, pk) || strings.Contains(s, "eyJ") {
			t.Errorf("secret material in %q", s)
		}
	}
}

func TestValidate(t *testing.T) {
	f := &fakeSM{t: t}
	if err := (gcp{}).Validate(f.host(), abi.ValidateRequest{Invocation: inv()}); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestPushAddsVersionAndReadsBack(t *testing.T) {
	f := &fakeSM{t: t}
	f.seed(newCert(t, "old"))
	newPEM := newCert(t, "new")
	res, err := push(f, newPEM)
	if err != nil || !res.Installed || res.Outcome != abi.OutcomeInstalled {
		t.Fatalf("push: %+v %v", res, err)
	}
	if len(f.versions) != 2 || f.adds != 1 || f.disables != 0 || f.creates != 0 {
		t.Fatalf("versions=%d adds=%d disables=%d creates=%d", len(f.versions), f.adds, f.disables, f.creates)
	}
	if !strings.HasPrefix(f.versions[1].value, newPEM) || !strings.Contains(f.versions[1].value, keyMarker) {
		t.Fatal("stored payload is not certificate then key")
	}
	var hd handle
	if json.Unmarshal([]byte(res.RollbackHandle), &hd) != nil || hd.Prior != "1" || hd.New != "2" {
		t.Fatalf("handle %q", res.RollbackHandle)
	}
	f.versions = append(f.versions, ver{value: "someone else wrote after us", state: "ENABLED"})
	vr, err := gcp{}.Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Name: "shop", Handle: res.RollbackHandle})
	if err != nil || fpOf(vr.CertPEM) != fpOf(newPEM) || strings.Contains(vr.CertPEM, "PRIVATE") || strings.Contains(vr.CertPEM, keyMarker) {
		t.Fatalf("verify: %+v %v", vr, err)
	}
	noSecrets(t, f, res.Detail)
}

func TestPushCreatesMissingSecret(t *testing.T) {
	f := &fakeSM{t: t}
	res, err := push(f, newCert(t, "first"))
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	if err != nil || !res.Installed || f.creates != 1 || hd.Prior != "" || hd.New != "1" {
		t.Fatalf("%+v %v creates=%d", res, err, f.creates)
	}
}

func TestTokenIgnoresKeyFileTokenURI(t *testing.T) {
	f := &fakeSM{t: t}
	if _, err := push(f, newCert(t, "x")); err != nil || f.tokenCalls == 0 {
		t.Fatal("token endpoint not used") // serve() fatals on any host other than the two granted
	}
}

func TestWriteFailureLeavesPreviousCurrent(t *testing.T) {
	f := &fakeSM{t: t, failAdd: true}
	oldPEM := newCert(t, "old")
	f.seed(oldPEM)
	res, _ := push(f, newCert(t, "new"))
	cur, ok := f.latestEnabled()
	if res.Outcome != abi.OutcomeWriteFailed || res.Installed || f.disables != 0 || len(f.versions) != 1 || !ok || !strings.HasPrefix(cur.value, oldPEM) {
		t.Fatalf("%+v disables=%d", res, f.disables)
	}
	noSecrets(t, f, res.Detail)
}

func TestReadbackMismatchRestoresPrevious(t *testing.T) {
	otherPEM = newCert(t, "other")
	f := &fakeSM{t: t, tamperNew: true}
	oldPEM := newCert(t, "old")
	f.seed(oldPEM)
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || res.Installed || strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("%+v", res)
	}
	f.tamperNew = false
	cur, ok := f.latestEnabled()
	if len(f.versions) != 3 || f.versions[1].state != "DISABLED" || !ok || fpOf(cur.value) != fpOf(oldPEM) {
		t.Fatalf("versions=%+v", f.versions)
	}
	noSecrets(t, f, res.Detail)
}

func TestReadbackMismatchFirstVersionDisablesNew(t *testing.T) {
	otherPEM = newCert(t, "other")
	f := &fakeSM{t: t, tamperNew: true}
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || f.versions[0].state != "DISABLED" || f.disables != 1 {
		t.Fatalf("%+v %+v", res, f.versions)
	}
}

func TestRollbackRestoresPrior(t *testing.T) {
	f := &fakeSM{t: t}
	oldPEM := newCert(t, "old")
	f.seed(oldPEM)
	res, _ := push(f, newCert(t, "new"))
	rb, err := gcp{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	cur, ok := f.latestEnabled()
	if err != nil || !rb.RolledBack || f.versions[1].state != "DISABLED" || !ok || fpOf(cur.value) != fpOf(oldPEM) {
		t.Fatalf("%+v %v %+v", rb, err, f.versions)
	}
	noSecrets(t, f, rb.Detail)
}

func TestRollbackWithoutPriorDisablesNew(t *testing.T) {
	f := &fakeSM{t: t}
	res, _ := push(f, newCert(t, "first"))
	rb, _ := gcp{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if !rb.RolledBack || f.versions[0].state != "DISABLED" || !strings.Contains(rb.Detail, "no previous version") {
		t.Fatalf("%+v %+v", rb, f.versions)
	}
	// A later push works although the latest version is disabled.
	if res2, _ := push(f, newCert(t, "again")); !res2.Installed {
		t.Fatalf("%+v", res2)
	}
}

func TestRollbackFailureNotReportedAsRolledBack(t *testing.T) {
	f := &fakeSM{t: t}
	f.seed(newCert(t, "old"))
	res, _ := push(f, newCert(t, "new"))
	f.failAdd = true
	rb, _ := gcp{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if rb.RolledBack || rb.Detail == "" {
		t.Fatalf("%+v", rb)
	}
	first := &fakeSM{t: t, failDis: true}
	res, _ = push(first, newCert(t, "first"))
	rb, _ = gcp{}.Rollback(first.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if rb.RolledBack {
		t.Fatalf("disable failure reported as rolled back: %+v", rb)
	}
	noSecrets(t, f, rb.Detail)
}

func TestTokenFailureIsWriteFailed(t *testing.T) {
	f := &fakeSM{t: t, failToken: true}
	res, _ := push(f, newCert(t, "new"))
	if res.Outcome != abi.OutcomeWriteFailed || res.Detail != "token request: HTTP 400" {
		t.Fatalf("%+v", res)
	}
	noSecrets(t, f, res.Detail)
}

func TestBadServiceAccountKey(t *testing.T) {
	f := &fakeSM{t: t}
	bad := inv()
	bad.Credential["service_account_json"] = `{"client_email":"a@b","private_key":"nope"}`
	res, _ := gcp{}.Push(f.host(), abi.PushRequest{Invocation: bad, CertPEM: newCert(t, "x")})
	if res.Outcome != abi.OutcomeWriteFailed || f.tokenCalls != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestCredentialsNeverAppearInOutput(t *testing.T) {
	otherPEM = newCert(t, "other")
	f := &fakeSM{t: t, tamperNew: true, failDis: true}
	f.seed(newCert(t, "old"))
	res, _ := push(f, newCert(t, "new"))
	vr, verr := gcp{}.Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Handle: `{"prior":"","new":"1"}`})
	errText := ""
	if verr != nil {
		errText = verr.Error()
	}
	noSecrets(t, f, res.Detail, errText)
	if strings.Contains(vr.CertPEM, "PRIVATE") || strings.Contains(vr.CertPEM, keyMarker) {
		t.Error("Verify returned key material")
	}
}

func TestRejectsBadSecretIDAndHandle(t *testing.T) {
	f := &fakeSM{t: t}
	bad := inv()
	bad.Target["secret_id"] = "a/b"
	if res, _ := (gcp{}).Push(f.host(), abi.PushRequest{Invocation: bad, CertPEM: newCert(t, "x")}); res.Outcome != abi.OutcomeWriteFailed || f.tokenCalls != 0 {
		t.Fatalf("%+v", res)
	}
	if _, err := (gcp{}).Verify(f.host(), abi.VerifyRequest{Invocation: inv(), Handle: `{"new":"1/../2"}`}); err == nil {
		t.Fatal("bad handle accepted")
	}
}
