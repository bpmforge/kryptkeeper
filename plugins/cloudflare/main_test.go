// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

const (
	apiToken  = "cf-api-token-0123456789abcdef"
	keyMarker = "TOP-SECRET-KEY-BYTES"
	zone      = "0123456789abcdef0123456789abcdef"
)

func newCert(t *testing.T, cn string, sans ...string) (certPEM string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter = time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: sans,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), notAfter
}

type cert struct {
	ID        string   `json:"id"`
	Hosts     []string `json:"hosts"`
	Status    string   `json:"status"`
	Priority  float64  `json:"priority"`
	ExpiresOn string   `json:"expires_on"`
	pending   int      // GETs answered "pending" before active
}

// fakeCF models the custom_certificates endpoints and the response envelope.
type fakeCF struct {
	t             *testing.T
	certs         []*cert
	failUpload    bool
	uploadMsg     string
	uploadPending int  // GETs answered "pending" before the upload is active
	failPrio      bool // every prioritize call fails
	failPrioOnce  bool
	badExpiry     bool // new cert reports a different expiry
	neverActive   bool
	uploadHosts   []string
	next          int
	uploads       int
	prioCalls     []string
	deletes       []string
	gets          int
	logs          []string
}

func (f *fakeCF) host() *delivery.Host { return delivery.NewHost(f.call) }

func (f *fakeCF) call(op string, in []byte) ([]byte, error) {
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

func ok(result any) (int, []byte) {
	return 200, js(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
}

func cfErr(status int, msg string) (int, []byte) {
	return status, js(map[string]any{"success": false, "errors": []map[string]any{{"code": 1001, "message": msg}}, "result": nil})
}

func (f *fakeCF) seed(id string, hosts []string, prio float64, expires time.Time) *cert {
	c := &cert{ID: id, Hosts: hosts, Status: "active", Priority: prio, ExpiresOn: expires.Format(time.RFC3339)}
	f.certs = append(f.certs, c)
	return c
}

func (f *fakeCF) find(id string) *cert {
	for _, c := range f.certs {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// served is what the edge serves for hostname: highest priority among active.
func (f *fakeCF) served(hostname string) string {
	best := ""
	bp := -1.0
	for _, c := range f.certs {
		if c.Status == "active" && coversAny(c.Hosts, hostname) && c.Priority > bp {
			best, bp = c.ID, c.Priority
		}
	}
	return best
}

func (f *fakeCF) serve(req abi.HTTPRequest) (int, []byte) {
	const base = "https://api.example.test/client/v4"
	if !strings.HasPrefix(req.URL, base) {
		f.t.Fatalf("unexpected URL %s", req.URL)
	}
	if req.Headers["Authorization"] != "Bearer "+apiToken {
		return cfErr(403, "Authentication error")
	}
	path := strings.TrimPrefix(req.URL, base)
	list := "/zones/" + zone + "/custom_certificates"
	switch {
	case req.Method == "GET" && strings.HasPrefix(path, list+"?per_page="):
		return ok(f.certs)
	case req.Method == "POST" && path == list:
		f.uploads++
		var b struct{ Certificate, PrivateKey, BundleMethod string }
		_ = json.Unmarshal(req.Body, &b)
		var raw map[string]string
		_ = json.Unmarshal(req.Body, &raw)
		if raw["bundle_method"] != "ubiquitous" || raw["certificate"] == "" || raw["private_key"] == "" {
			f.t.Errorf("upload body keys %v", raw)
		}
		if f.failUpload {
			if f.uploadMsg != "" {
				return cfErr(400, f.uploadMsg)
			}
			return cfErr(400, "custom certificate quota exceeded "+keyMarker)
		}
		blk, _ := pem.Decode([]byte(raw["certificate"]))
		l, _ := x509.ParseCertificate(blk.Bytes)
		f.next++
		c := &cert{ID: fmt.Sprintf("new%d", f.next), Hosts: f.uploadHosts, Status: "active", ExpiresOn: l.NotAfter.UTC().Format(time.RFC3339)}
		if f.badExpiry {
			c.ExpiresOn = l.NotAfter.Add(48 * time.Hour).UTC().Format(time.RFC3339)
		}
		if f.uploadPending > 0 {
			c.Status, c.pending = "pending", f.uploadPending
		}
		if f.neverActive {
			c.Status = "pending"
			c.pending = 1 << 30
		}
		f.certs = append(f.certs, c)
		return ok(c)
	case req.Method == "PUT" && path == list+"/prioritize":
		var b struct {
			Certificates []struct {
				ID       string
				Priority float64
			}
		}
		_ = json.Unmarshal(req.Body, &b)
		line := ""
		for _, it := range b.Certificates {
			line += fmt.Sprintf("%s=%v ", it.ID, it.Priority)
		}
		f.prioCalls = append(f.prioCalls, strings.TrimSpace(line))
		if f.failPrio || f.failPrioOnce {
			f.failPrioOnce = false
			return cfErr(500, "prioritize failed")
		}
		for _, it := range b.Certificates {
			if c := f.find(it.ID); c != nil {
				c.Priority = it.Priority
			}
		}
		return ok(f.certs)
	case strings.HasPrefix(path, list+"/"):
		id := strings.TrimPrefix(path, list+"/")
		c := f.find(id)
		if c == nil {
			return cfErr(404, "certificate not found")
		}
		switch req.Method {
		case "GET":
			f.gets++
			out := *c
			if c.pending > 0 {
				c.pending--
				out.Status = "pending"
				if c.pending == 0 {
					c.Status = "active"
				}
			}
			return ok(out)
		case "DELETE":
			f.deletes = append(f.deletes, id)
			for i, x := range f.certs {
				if x.ID == id {
					f.certs = append(f.certs[:i], f.certs[i+1:]...)
					break
				}
			}
			return ok(map[string]string{"id": id})
		}
	}
	f.t.Fatalf("unexpected request %s %s", req.Method, path)
	return 0, nil
}

func inv() abi.Invocation {
	return abi.Invocation{
		Credential: map[string]string{"api_base": "https://api.example.test/client/v4/", "api_token": apiToken},
		Target:     map[string]string{"zone_id": zone, "hostname": "shop.example.com"},
	}
}

func push(f *fakeCF, certPEM string) (abi.PushResult, error) {
	return cf{}.Push(f.host(), abi.PushRequest{Invocation: inv(), Name: "shop", CertPEM: certPEM, KeyPEM: "-----BEGIN PRIVATE KEY-----\n" + keyMarker + "\n-----END PRIVATE KEY-----\n"})
}

func setup(t *testing.T) (*fakeCF, time.Time) {
	sleep = func(time.Duration) {}
	f := &fakeCF{t: t, uploadHosts: []string{"shop.example.com", "example.com"}}
	_, exp := newCert(t, "old")
	f.seed("old1", []string{"shop.example.com"}, 5, exp)
	return f, exp
}

func noSecrets(t *testing.T, f *fakeCF, ss ...string) {
	t.Helper()
	ss = append(ss, f.logs...)
	for _, s := range ss {
		if strings.Contains(s, apiToken) || strings.Contains(s, keyMarker) || strings.Contains(s, "BEGIN") {
			t.Errorf("secret material in %q", s)
		}
	}
}

func TestCovers(t *testing.T) {
	for _, c := range []struct {
		p, n string
		want bool
	}{
		{"shop.example.com", "shop.example.com", true}, {"Shop.Example.com", "shop.example.COM", true},
		{"*.example.com", "shop.example.com", true}, {"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false}, {"*.example.com", "*.example.com", true},
		{"*.example.com", "*.b.example.com", false}, {"example.com", "shop.example.com", false},
		{"*.example.com", "xexample.com", false},
	} {
		if got := covers(c.p, c.n); got != c.want {
			t.Errorf("covers(%q,%q)=%v", c.p, c.n, got)
		}
	}
}

func TestValidateSurfacesAPIError(t *testing.T) {
	f, _ := setup(t)
	if err := (cf{}).Validate(f.host(), abi.ValidateRequest{Invocation: inv()}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	bad := inv()
	bad.Credential["api_token"] = "wrong"
	err := (cf{}).Validate(f.host(), abi.ValidateRequest{Invocation: bad})
	if err == nil || !strings.Contains(err.Error(), "Authentication error") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("validate: %v", err)
	}
}

func TestUploadActivateSwap(t *testing.T) {
	f, _ := setup(t)
	newPEM, _ := newCert(t, "new", "shop.example.com", "example.com")
	res, err := push(f, newPEM)
	if err != nil || !res.Installed || res.Outcome != abi.OutcomeInstalled {
		t.Fatalf("push: %+v %v", res, err)
	}
	if f.uploads != 1 || len(f.prioCalls) != 1 || f.prioCalls[0] != "new1=6 old1=5" {
		t.Fatalf("uploads=%d prio=%v", f.uploads, f.prioCalls)
	}
	if f.served("shop.example.com") != "new1" || f.find("old1") == nil {
		t.Fatal("new cert is not served or the old one was removed")
	}
	var hd handle
	if json.Unmarshal([]byte(res.RollbackHandle), &hd) != nil || hd.Prior != "old1" || hd.New != "new1" || hd.PriorPriority != 5 || hd.Zone != zone {
		t.Fatalf("handle %q", res.RollbackHandle)
	}
	noSecrets(t, f, res.Detail)
}

func TestActivationWaitsThenSucceeds(t *testing.T) {
	f, _ := setup(t)
	sleeps := 0
	sleep = func(d time.Duration) {
		if d != 5*time.Second {
			t.Errorf("poll interval %v", d)
		}
		sleeps++
	}
	f.uploadPending = 3
	f.uploadHosts = []string{"shop.example.com"}
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	if !res.Installed || sleeps != 3 {
		t.Fatalf("%+v sleeps=%d", res, sleeps)
	}
}

func TestUploadFailureChangesNothing(t *testing.T) {
	f, _ := setup(t)
	f.failUpload = true
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeWriteFailed || res.Installed || len(f.certs) != 1 || len(f.prioCalls) != 0 || len(f.deletes) != 0 {
		t.Fatalf("%+v certs=%d", res, len(f.certs))
	}
	if !strings.Contains(res.Detail, "withheld") {
		t.Fatalf("echoed key line not withheld: %q", res.Detail)
	}
	f.failUpload = false
	noSecrets(t, f, res.Detail)
}

func TestUploadErrorTextReachesOperator(t *testing.T) {
	f, _ := setup(t)
	f.failUpload, f.uploadMsg = true, "not entitled: custom certificates need a paid plan"
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeWriteFailed || !strings.HasSuffix(res.Detail, "not entitled: custom certificates need a paid plan") {
		t.Fatalf("%+v", res)
	}
}

func TestActivationTimeoutDeletesNew(t *testing.T) {
	f, _ := setup(t)
	f.neverActive = true
	sleeps := 0
	sleep = func(time.Duration) { sleeps++ }
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeWriteFailed || res.Installed || f.gets != maxPolls || sleeps != maxPolls-1 ||
		len(f.deletes) != 1 || f.deletes[0] != "new1" || len(f.prioCalls) != 0 || f.served("shop.example.com") != "old1" {
		t.Fatalf("%+v gets=%d sleeps=%d deletes=%v", res, f.gets, sleeps, f.deletes)
	}
}

func TestSwapFailureKeepsPrior(t *testing.T) {
	f, _ := setup(t)
	f.failPrio = true
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeBindingFailed || res.Installed || f.served("shop.example.com") != "old1" ||
		len(f.deletes) != 1 || f.deletes[0] != "new1" || len(f.prioCalls) != 1 {
		t.Fatalf("%+v prio=%v deletes=%v", res, f.prioCalls, f.deletes)
	}
}

func TestReadbackExpiryMismatchRestores(t *testing.T) {
	f, _ := setup(t)
	f.badExpiry = true
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeBindingFailed || res.Installed || strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("%+v", res)
	}
	if f.served("shop.example.com") != "old1" || f.find("new1") != nil || len(f.prioCalls) != 2 || f.prioCalls[1] != "old1=6 new1=5" {
		t.Fatalf("served=%s prio=%v", f.served("shop.example.com"), f.prioCalls)
	}
}

func TestReadbackHostCoverageMismatchRestores(t *testing.T) {
	f, _ := setup(t)
	f.uploadHosts = []string{"shop.example.com"} // the leaf also names example.com
	newPEM, _ := newCert(t, "new", "shop.example.com", "example.com")
	res, _ := push(f, newPEM)
	if res.Outcome != abi.OutcomeBindingFailed || f.served("shop.example.com") != "old1" {
		t.Fatalf("%+v", res)
	}
}

func TestPriorPicksHighestCoveringActive(t *testing.T) {
	f, exp := setup(t)
	f.seed("wild", []string{"*.example.com"}, 9, exp)
	f.seed("other", []string{"other.example.com"}, 50, exp)
	inactive := f.seed("expired", []string{"shop.example.com"}, 99, exp)
	inactive.Status = "expired"
	newPEM, _ := newCert(t, "new", "shop.example.com")
	f.uploadHosts = []string{"shop.example.com"}
	res, _ := push(f, newPEM)
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	if hd.Prior != "wild" || hd.PriorPriority != 9 || f.prioCalls[0] != "new1=10 wild=9" {
		t.Fatalf("handle %+v prio=%v", hd, f.prioCalls)
	}
}

func TestPushWithoutPriorSendsOnlyNew(t *testing.T) {
	f, _ := setup(t)
	f.certs = nil
	f.uploadHosts = []string{"shop.example.com"}
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	if !res.Installed || len(f.prioCalls) != 1 || f.prioCalls[0] != "new1=1" {
		t.Fatalf("%+v prio=%v", res, f.prioCalls)
	}
}

func TestRollbackRestoresPriorID(t *testing.T) {
	f, _ := setup(t)
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	rb, err := cf{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if err != nil || !rb.RolledBack || f.served("shop.example.com") != "old1" || f.find("new1") != nil || f.prioCalls[1] != "old1=6 new1=5" {
		t.Fatalf("%+v %v served=%s", rb, err, f.served("shop.example.com"))
	}
}

func TestRollbackWithoutPrior(t *testing.T) {
	f, _ := setup(t)
	f.certs = nil
	f.uploadHosts = []string{"shop.example.com"}
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	rb, _ := cf{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if !rb.RolledBack || rb.Detail != "no previous certificate; new one removed" || f.find("new1") != nil || len(f.prioCalls) != 1 {
		t.Fatalf("%+v", rb)
	}
}

func TestRollbackFailureNotReportedAsRolledBack(t *testing.T) {
	f, _ := setup(t)
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	f.failPrio = true
	rb, _ := cf{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: res.RollbackHandle})
	if rb.RolledBack || rb.Detail == "" || len(f.deletes) != 0 || f.served("shop.example.com") != "new1" {
		t.Fatalf("%+v deletes=%v", rb, f.deletes)
	}
}

func TestRollbackRejectsForeignHandle(t *testing.T) {
	f, _ := setup(t)
	rb, _ := cf{}.Rollback(f.host(), abi.RollbackRequest{Invocation: inv(), Handle: `{"zone":"../x","new":"a"}`})
	if rb.RolledBack || len(f.prioCalls) != 0 {
		t.Fatalf("%+v", rb)
	}
}

func TestTokenNeverInOutput(t *testing.T) {
	f, _ := setup(t)
	f.failUpload = true
	newPEM, _ := newCert(t, "new", "shop.example.com")
	res, _ := push(f, newPEM)
	bad := inv()
	bad.Credential["api_token"] = apiToken + "x" // server echoes nothing, but errors must not carry it either
	res2, _ := cf{}.Push(f.host(), abi.PushRequest{Invocation: bad, CertPEM: newPEM, KeyPEM: "k"})
	f.failUpload, f.failPrio = false, true
	res3, _ := push(f, newPEM)
	noSecrets(t, f, res.Detail, res2.Detail, res3.Detail)
	if strings.Contains(res2.Detail, apiToken) {
		t.Fatal("token in detail")
	}
}

func TestRejectsBadTarget(t *testing.T) {
	f, _ := setup(t)
	for _, tc := range []map[string]string{
		{"zone_id": "zz", "hostname": "shop.example.com"},
		{"zone_id": zone, "hostname": "../x"},
		{"zone_id": zone, "hostname": "*.example.com"},
		{"zone_id": zone, "hostname": "shop.example.com", "bundle_method": "evil"},
	} {
		bad := inv()
		bad.Target = tc
		newPEM, _ := newCert(t, "x")
		if res, _ := (cf{}).Push(f.host(), abi.PushRequest{Invocation: bad, CertPEM: newPEM}); res.Outcome != abi.OutcomeWriteFailed {
			t.Errorf("%v accepted: %+v", tc, res)
		}
	}
	if f.uploads != 0 {
		t.Fatal("upload attempted")
	}
}
