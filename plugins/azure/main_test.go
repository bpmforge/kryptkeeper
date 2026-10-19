// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

const (
	clientSecret = "azure-client-secret-xyz-123"
	kvToken      = "kv-access-token-AAAA"
	armToken     = "arm-access-token-BBBB"
	keyMarker    = "TOP-SECRET-KEY-BYTES"
	sub          = "11111111-2222-3333-4444-555555555555"
	vaultHost    = "myvault.vault.azure.net"
	vaultURL     = "https://" + vaultHost
	gwPath       = "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.Network/applicationGateways/gw1"
	fdPath       = "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.Cdn/profiles/prof1/secrets/sec1"
	oldVersion   = "0000000000000000000000000000aaaa"
)

var oldSID = vaultURL + "/secrets/shop-cert/" + oldVersion

func init() { sleep = func(time.Duration) {} }

func newCert(t *testing.T, cn string) (certPEM string, keyPEM string, ecKeyPEM string) {
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
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	sec1, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
}

func fp(certPEM string) string {
	b, _ := pem.Decode([]byte(certPEM))
	s := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(s[:])
}

const gwJSON = `{"name":"gw1","etag":"W/\"abc\"","location":"westeurope","tags":{"env":"prod"},"properties":{"provisioningState":"Succeeded","sku":{"name":"WAF_v2","capacity":2},
"gatewayIPConfigurations":[{"name":"ipc","properties":{"subnet":{"id":"/s"}}}],
"sslCertificates":[{"name":"other","properties":{"data":"x"}},{"name":"web-cert","properties":{"keyVaultSecretId":"%s","publicCertData":"zzz"}}],
"httpListeners":[{"name":"l1","properties":{"sslCertificate":{"id":"/c"},"requireServerNameIndication":true}}],"bigNumber":12345678901234567890}}`

const fdJSON = `{"id":"` + fdPath + `","name":"sec1","type":"Microsoft.Cdn/profiles/secrets","properties":{"provisioningState":"Succeeded","deploymentStatus":"NotStarted",
"parameters":{"type":"CustomerCertificate","secretSource":{"id":"/subscriptions/` + sub + `/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/myvault/secrets/shop-cert"},"secretVersion":"%s","useLatestVersion":false,"subjectAlternativeNames":["a.example.com"]}}}`

type fakeAz struct {
	t        *testing.T
	versions map[string]string // KV version -> cert fp
	next     int
	gw, fd   doc
	state    string // provisioningState served after a PUT settles
	updating int    // polls answered "Updating" after a PUT
	pending  int
	// failure switches
	importStatus int
	badCer       bool
	putStatus    func(value string) int // non-zero = fail a PUT whose binding value matches
	badState     func(value string) string
	redirectPut  string // PUT stores this value instead of the requested one
	foreverBusy  bool

	puts      []doc
	rawPuts   []string
	putValues []string
	imports   int
	logs      []string
	origGW    doc
}

func newFakeAz(t *testing.T) *fakeAz {
	f := &fakeAz{t: t, versions: map[string]string{}, state: "Succeeded"}
	f.gw = mustJSON(fmt.Sprintf(gwJSON, oldSID))
	f.origGW = mustJSON(fmt.Sprintf(gwJSON, oldSID))
	f.fd = mustJSON(fmt.Sprintf(fdJSON, oldVersion))
	return f
}

func mustJSON(s string) doc {
	d, err := decodeDoc([]byte(s))
	if err != nil {
		panic(err)
	}
	return d
}

func decodeDoc(b []byte) (doc, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var d doc
	return d, dec.Decode(&d)
}

func js(v any) []byte { b, _ := json.Marshal(v); return b }

func (f *fakeAz) host() *delivery.Host { return delivery.NewHost(f.call) }

func (f *fakeAz) call(op string, in []byte) ([]byte, error) {
	if op != abi.HostHTTP {
		f.logs = append(f.logs, string(in))
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

func azErr(status int, code string) (int, []byte) {
	return status, js(map[string]any{"error": map[string]string{"code": code, "message": "leaky " + keyMarker}})
}

func (f *fakeAz) serve(req abi.HTTPRequest) (int, []byte) {
	u, _ := url.Parse(req.URL)
	switch u.Host {
	case "login.microsoftonline.com":
		form, _ := url.ParseQuery(string(req.Body))
		if u.Path != "/tenant-1/oauth2/v2.0/token" || form.Get("client_secret") != clientSecret || form.Get("grant_type") != "client_credentials" {
			return 401, []byte(`{"error":"invalid_client","error_description":"` + clientSecret + `"}`)
		}
		switch form.Get("scope") {
		case vaultScope:
			return 200, js(map[string]any{"access_token": kvToken, "token_type": "Bearer", "expires_in": 3599})
		case armScope:
			return 200, js(map[string]any{"access_token": armToken, "token_type": "Bearer", "expires_in": 3599})
		}
		f.t.Errorf("unexpected scope %q", form.Get("scope"))
		return 400, nil
	case vaultHost:
		return f.vault(req, u)
	case "management.azure.com":
		return f.arm(req, u)
	}
	f.t.Fatalf("unexpected host %s", u.Host)
	return 0, nil
}

func (f *fakeAz) vault(req abi.HTTPRequest, u *url.URL) (int, []byte) {
	if req.Headers["Authorization"] != "Bearer "+kvToken || u.Query().Get("api-version") != "7.4" {
		return azErr(401, "Unauthorized")
	}
	if req.Method == "GET" && u.Path == "/certificates" {
		return 200, js(map[string]any{"value": []any{}})
	}
	if req.Method != "POST" || u.Path != "/certificates/shop-cert/import" {
		f.t.Fatalf("unexpected KV request %s %s", req.Method, u.Path)
	}
	f.imports++
	if f.importStatus != 0 {
		return azErr(f.importStatus, "Forbidden")
	}
	var b struct {
		Value  string
		Policy struct {
			SecretProps struct {
				ContentType string `json:"contentType"`
			} `json:"secret_props"`
		}
	}
	_ = json.Unmarshal(req.Body, &b)
	raw, err := base64.StdEncoding.DecodeString(b.Value)
	if err != nil || b.Policy.SecretProps.ContentType != "application/x-pem-file" {
		f.t.Errorf("bad import body: %v %q", err, b.Policy.SecretProps.ContentType)
	}
	blk, rest := pem.Decode(raw)
	keyBlk, _ := pem.Decode(rest)
	if blk == nil || blk.Type != "CERTIFICATE" || keyBlk == nil || keyBlk.Type != "PRIVATE KEY" {
		f.t.Errorf("import value must be certificate then PKCS#8 key")
		return azErr(400, "BadParameter")
	}
	f.next++
	ver := fmt.Sprintf("%032x", f.next)
	cer := blk.Bytes
	f.versions[ver] = hex.EncodeToString(func() []byte { s := sha256.Sum256(cer); return s[:] }())
	if f.badCer {
		cer = []byte("not the same certificate")
	}
	id := vaultURL + "/certificates/shop-cert/" + ver
	return 200, js(map[string]any{"id": id, "sid": vaultURL + "/secrets/shop-cert/" + ver, "kid": "k", "cer": base64.StdEncoding.EncodeToString(cer)})
}

// value is the binding value in a gateway or Front Door document.
func (f *fakeAz) value(d doc, isGW bool) string {
	if isGW {
		l := d["properties"].(map[string]any)["sslCertificates"].([]any)
		return l[1].(map[string]any)["properties"].(map[string]any)["keyVaultSecretId"].(string)
	}
	return d["properties"].(map[string]any)["parameters"].(map[string]any)["secretVersion"].(string)
}

func (f *fakeAz) arm(req abi.HTTPRequest, u *url.URL) (int, []byte) {
	if req.Headers["Authorization"] != "Bearer "+armToken {
		return azErr(401, "AuthenticationFailed")
	}
	var cur doc
	var isGW bool
	var want string
	switch u.Path {
	case gwPath:
		cur, isGW, want = f.gw, true, "2023-09-01"
	case fdPath:
		cur, isGW, want = f.fd, false, "2023-05-01"
	default:
		return azErr(404, "ResourceNotFound")
	}
	if u.Query().Get("api-version") != want {
		f.t.Errorf("api-version %q", u.Query().Get("api-version"))
	}
	switch req.Method {
	case "GET":
		out := cur
		props := out["properties"].(map[string]any)
		if f.pending > 0 {
			f.pending--
			props["provisioningState"] = "Updating"
		} else if f.foreverBusy {
			props["provisioningState"] = "Updating"
		} else {
			props["provisioningState"] = f.state
		}
		return 200, js(out)
	case "PUT":
		d, err := decodeDoc(req.Body)
		if err != nil {
			return azErr(400, "BadRequest")
		}
		v := f.value(d, isGW)
		f.puts, f.putValues = append(f.puts, d), append(f.putValues, v)
		f.rawPuts = append(f.rawPuts, string(req.Body))
		if f.putStatus != nil {
			if s := f.putStatus(v); s != 0 {
				return azErr(s, "InternalServerError")
			}
		}
		if f.redirectPut != "" && v != oldSID && v != oldVersion {
			// stored value differs from the requested one
			if isGW {
				d["properties"].(map[string]any)["sslCertificates"].([]any)[1].(map[string]any)["properties"].(map[string]any)["keyVaultSecretId"] = f.redirectPut
			} else {
				d["properties"].(map[string]any)["parameters"].(map[string]any)["secretVersion"] = f.redirectPut
			}
		}
		if isGW {
			f.gw = d
		} else {
			f.fd = d
		}
		f.pending = f.updating
		f.state = "Succeeded"
		if f.badState != nil {
			if s := f.badState(v); s != "" {
				f.state = s
			}
		}
		return 200, js(d)
	}
	f.t.Fatalf("unexpected ARM method %s", req.Method)
	return 0, nil
}

func inv(mode string) abi.Invocation {
	t := map[string]string{"mode": mode, "subscription_id": sub, "resource_group": "rg1", "keyvault_cert_name": "shop-cert"}
	if mode == modeAppGW {
		t["gateway_name"], t["ssl_certificate_name"] = "gw1", "web-cert"
	} else {
		t["profile_name"], t["secret_name"] = "prof1", "sec1"
	}
	return abi.Invocation{
		Credential: map[string]string{"vault_url": vaultURL, "tenant_id": "tenant-1", "client_id": "client-1", "client_secret": clientSecret},
		Target:     t,
	}
}

func push(f *fakeAz, mode, certPEM, keyPEM string) (abi.PushResult, error) {
	return (azure{}).Push(f.host(), abi.PushRequest{Invocation: inv(mode), Name: "shop", CertPEM: certPEM, KeyPEM: keyPEM})
}

func TestValidate(t *testing.T) {
	f := newFakeAz(t)
	for _, m := range []string{modeAppGW, modeFrontDoor} {
		if err := (azure{}).Validate(f.host(), abi.ValidateRequest{Invocation: inv(m)}); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
}

func TestImportThenBindAppGW(t *testing.T) {
	f := newFakeAz(t)
	f.updating = 2
	cert, key, _ := newCert(t, "new")
	res, err := push(f, modeAppGW, cert, key)
	if err != nil || !res.Installed || res.Outcome != abi.OutcomeInstalled {
		t.Fatalf("%+v %v", res, err)
	}
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	newSID := vaultURL + "/secrets/shop-cert/" + fmt.Sprintf("%032x", 1)
	if hd.Mode != modeAppGW || hd.Prior != oldSID || hd.New != newSID || hd.SID != newSID {
		t.Fatalf("handle %+v", hd)
	}
	if got := f.value(f.gw, true); got != newSID {
		t.Fatalf("gateway references %s", got)
	}
}

func TestImportThenBindFrontDoorSecretVersion(t *testing.T) {
	f := newFakeAz(t)
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeFrontDoor, cert, key)
	if !res.Installed {
		t.Fatalf("%+v", res)
	}
	p := f.fd["properties"].(map[string]any)["parameters"].(map[string]any)
	if p["secretVersion"] != fmt.Sprintf("%032x", 1) || p["useLatestVersion"] != false || p["type"] != "CustomerCertificate" ||
		p["secretSource"].(map[string]any)["id"] == "" {
		t.Fatalf("parameters %v", p)
	}
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	if hd.Prior != oldVersion || hd.New != p["secretVersion"] || hd.SID != vaultURL+"/secrets/shop-cert/"+hd.New {
		t.Fatalf("handle %+v", hd)
	}
}

func TestImportRejectsFingerprintMismatch(t *testing.T) {
	f := newFakeAz(t)
	f.badCer = true
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeAppGW, cert, key)
	if res.Outcome != abi.OutcomeWriteFailed || res.Installed || len(f.puts) != 0 {
		t.Fatalf("%+v puts %d", res, len(f.puts))
	}
}

func TestImportFailureIsWriteFailed(t *testing.T) {
	f := newFakeAz(t)
	f.importStatus = 403
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeAppGW, cert, key)
	if res.Outcome != abi.OutcomeWriteFailed || len(f.puts) != 0 || !strings.Contains(res.Detail, "HTTP 403 Forbidden") {
		t.Fatalf("%+v", res)
	}
}

func TestBindFailureLeavesPreviousBinding(t *testing.T) {
	f := newFakeAz(t)
	f.putStatus = func(v string) int {
		if v != oldSID {
			return 500
		}
		return 0
	}
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeAppGW, cert, key)
	if res.Outcome != abi.OutcomeBindingFailed || res.Installed || f.value(f.gw, true) != oldSID || strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("%+v bound %s", res, f.value(f.gw, true))
	}
}

func TestRestoreFailureIsReported(t *testing.T) {
	f := newFakeAz(t)
	f.putStatus = func(string) int { return 500 }
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeAppGW, cert, key)
	if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("%+v", res)
	}
}

func TestProvisioningFailedRestoresPrior(t *testing.T) {
	for _, mode := range []string{modeAppGW, modeFrontDoor} {
		f := newFakeAz(t)
		f.badState = func(v string) string {
			if v != oldSID && v != oldVersion {
				return "Failed"
			}
			return ""
		}
		cert, key, _ := newCert(t, "new")
		res, _ := push(f, mode, cert, key)
		isGW := mode == modeAppGW
		cur := f.gw
		if !isGW {
			cur = f.fd
		}
		if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "provisioning Failed") {
			t.Fatalf("%s %+v", mode, res)
		}
		if got := f.value(cur, isGW); got != oldSID && got != oldVersion {
			t.Fatalf("%s still bound to %s", mode, got)
		}
	}
}

func TestReadbackMismatchRestoresPrior(t *testing.T) {
	f := newFakeAz(t)
	f.redirectPut = vaultURL + "/secrets/shop-cert/" + strings.Repeat("e", 32)
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeAppGW, cert, key)
	if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "read back") {
		t.Fatalf("%+v", res)
	}
	if f.putValues[len(f.putValues)-1] != oldSID {
		t.Errorf("last PUT %s, want restore to prior", f.putValues[len(f.putValues)-1])
	}
}

func TestPollBudgetExceededRestores(t *testing.T) {
	f := newFakeAz(t)
	f.foreverBusy = true
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeAppGW, cert, key)
	if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "provisioning still Updating after 20 polls") {
		t.Fatalf("%+v", res)
	}
	if f.putValues[len(f.putValues)-1] != oldSID {
		t.Error("prior not restored")
	}
}

func TestRollbackRestoresPrior(t *testing.T) {
	for _, mode := range []string{modeAppGW, modeFrontDoor} {
		f := newFakeAz(t)
		cert, key, _ := newCert(t, "new")
		res, _ := push(f, mode, cert, key)
		rb, _ := (azure{}).Rollback(f.host(), abi.RollbackRequest{Invocation: inv(mode), Handle: res.RollbackHandle})
		cur := f.gw
		if mode == modeFrontDoor {
			cur = f.fd
		}
		got := f.value(cur, mode == modeAppGW)
		if !rb.RolledBack || (got != oldSID && got != oldVersion) {
			t.Fatalf("%s %+v bound %s", mode, rb, got)
		}
	}
}

func TestRollbackWithoutPriorIsNotRolledBack(t *testing.T) {
	f := newFakeAz(t)
	f.fd["properties"].(map[string]any)["parameters"].(map[string]any)["secretVersion"] = ""
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeFrontDoor, cert, key)
	if !res.Installed {
		t.Fatalf("%+v", res)
	}
	n := len(f.puts)
	rb, _ := (azure{}).Rollback(f.host(), abi.RollbackRequest{Invocation: inv(modeFrontDoor), Handle: res.RollbackHandle})
	if rb.RolledBack || rb.Detail != "no previous binding" || len(f.puts) != n {
		t.Fatalf("%+v", rb)
	}
}

func TestPutPreservesUnknownFields(t *testing.T) {
	f := newFakeAz(t)
	cert, key, _ := newCert(t, "new")
	res, _ := push(f, modeAppGW, cert, key)
	if !res.Installed {
		t.Fatalf("%+v", res)
	}
	want := mustJSON(fmt.Sprintf(gwJSON, f.value(f.puts[0], true)))
	if !reflect.DeepEqual(f.puts[0], want) {
		t.Fatalf("PUT document differs from the GET document beyond keyVaultSecretId:\n%v\n%v", f.puts[0], want)
	}
	if !strings.Contains(f.rawPuts[0], "12345678901234567890") {
		t.Error("large number was reformatted")
	}
}

func TestECKeyIsConvertedToPKCS8(t *testing.T) {
	f := newFakeAz(t)
	cert, _, ec := newCert(t, "new")
	res, _ := push(f, modeAppGW, cert, ec)
	if !res.Installed {
		t.Fatalf("%+v", res) // the fake fails the import unless the key block is PRIVATE KEY
	}
}

func TestParseRejects(t *testing.T) {
	for name, mut := range map[string]func(*abi.Invocation){
		"bad mode":      func(i *abi.Invocation) { i.Target["mode"] = "cdn" },
		"bad sub":       func(i *abi.Invocation) { i.Target["subscription_id"] = "nope" },
		"no cert name":  func(i *abi.Invocation) { i.Target["keyvault_cert_name"] = "bad name!" },
		"no gateway":    func(i *abi.Invocation) { delete(i.Target, "gateway_name") },
		"no credential": func(i *abi.Invocation) { delete(i.Credential, "tenant_id") },
	} {
		in := inv(modeAppGW)
		mut(&in)
		if _, err := parse(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	in := inv(modeFrontDoor)
	delete(in.Target, "secret_name")
	if _, err := parse(in); err == nil {
		t.Error("frontdoor without secret_name accepted")
	}
	if _, err := parseHandle(`{"mode":"appgw","new":"not a secret id"}`, mustParse(t, modeAppGW)); err == nil {
		t.Error("bad handle accepted")
	}
}

func mustParse(t *testing.T, mode string) config {
	c, err := parse(inv(mode))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTokenFailureIsWriteFailed(t *testing.T) {
	f := newFakeAz(t)
	in := inv(modeAppGW)
	in.Credential["client_secret"] = "wrong-secret-value"
	cert, key, _ := newCert(t, "new")
	res, _ := (azure{}).Push(f.host(), abi.PushRequest{Invocation: in, CertPEM: cert, KeyPEM: key})
	if res.Outcome != abi.OutcomeWriteFailed || strings.Contains(res.Detail, "wrong-secret-value") || strings.Contains(res.Detail, clientSecret) {
		t.Fatalf("%+v", res)
	}
}

func TestSecretsNeverInOutput(t *testing.T) {
	f := newFakeAz(t)
	cert, key, _ := newCert(t, "new")
	var out []string
	f.importStatus = 403
	res, _ := push(f, modeAppGW, cert, key)
	out = append(out, res.Detail)
	f.importStatus = 0
	f.putStatus = func(string) int { return 500 }
	res, _ = push(f, modeAppGW, cert, key)
	out = append(out, res.Detail)
	f.putStatus = nil
	res, _ = push(f, modeFrontDoor, cert, key)
	out = append(out, res.Detail, res.RollbackHandle)
	bad := inv(modeAppGW)
	bad.Target["gateway_name"] = "gw-missing"
	err := (azure{}).Validate(f.host(), abi.ValidateRequest{Invocation: bad})
	if err != nil {
		out = append(out, err.Error())
	}
	for _, s := range out {
		for _, secret := range []string{clientSecret, kvToken, armToken, keyMarker, "BEGIN"} {
			if strings.Contains(s, secret) {
				t.Errorf("%q leaked in %q", secret, s)
			}
		}
	}
	for _, l := range f.logs {
		if strings.Contains(l, clientSecret) || strings.Contains(l, "PRIVATE KEY") {
			t.Error("secret in log")
		}
	}
}
