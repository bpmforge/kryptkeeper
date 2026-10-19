// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certmanagerissuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// buildFakeCSRDER returns a minimal DER-encoded CSR for testing.
func buildFakeCSRDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

// buildFakeCertPEM returns a self-signed cert PEM for testing.
func buildFakeCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestController_Reconcile_IssuedSuccessfully(t *testing.T) {
	csrDER := buildFakeCSRDER(t)
	certPEM := buildFakeCertPEM(t)

	var patchedStatus StatusPatch
	var kryptRequestBody map[string]string

	// Mock Kryptkeeper Hub.
	hubMux := http.NewServeMux()
	hubMux.HandleFunc("POST /api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&kryptRequestBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]string{"certificate_pem": certPEM},
		})
	})
	hubSrv := httptest.NewServer(hubMux)
	defer hubSrv.Close()

	// Mock k8s API server.
	cr := CertificateRequest{
		APIVersion: "cert-manager.io/v1",
		Kind:       "CertificateRequest",
		Metadata:   Metadata{Name: "test-cr", Namespace: "default", ResourceVersion: "1"},
		Spec: CRSpec{
			Request:   base64.StdEncoding.EncodeToString(csrDER),
			IssuerRef: IssuerRef{Name: "my-issuer", Kind: "KryptKeeperIssuer", Group: IssuerGroup},
		},
	}
	list := CertificateRequestList{Items: []CertificateRequest{cr}}

	k8sMux := http.NewServeMux()
	k8sMux.HandleFunc("/apis/cert-manager.io/v1/namespaces/default/certificaterequests", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	})
	k8sMux.HandleFunc("/apis/cert-manager.io/v1/namespaces/default/certificaterequests/test-cr/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&patchedStatus)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cr) // echo back
	})
	k8sSrv := httptest.NewServer(k8sMux)
	defer k8sSrv.Close()

	k8sClient := NewK8sClient(k8sSrv.URL, "test-token", nil)
	ctrl := NewController(k8sClient, IssuerConfig{
		HubURL:     hubSrv.URL,
		APIToken:   "hub-token",
		CAID:       "ca-1",
		TemplateID: "tpl-1",
	}, []string{"default"})

	if err := ctrl.reconcileAll(context.Background()); err != nil {
		t.Fatalf("reconcileAll: %v", err)
	}

	// Kryptkeeper should have received the right fields.
	if kryptRequestBody["ca_id"] != "ca-1" {
		t.Errorf("expected ca_id=ca-1, got %q", kryptRequestBody["ca_id"])
	}
	if kryptRequestBody["template_id"] != "tpl-1" {
		t.Errorf("expected template_id=tpl-1, got %q", kryptRequestBody["template_id"])
	}
	if kryptRequestBody["csr_pem"] == "" {
		t.Error("expected non-empty csr_pem in kryptkeeper request")
	}

	// Status patch should include the certificate.
	if len(patchedStatus.Status.Certificate) == 0 {
		t.Error("expected certificate to be patched into CertificateRequest status")
	}

	// Ready condition should be True.
	var readyCond *Condition
	for i := range patchedStatus.Status.Conditions {
		if patchedStatus.Status.Conditions[i].Type == "Ready" {
			readyCond = &patchedStatus.Status.Conditions[i]
		}
	}
	if readyCond == nil || readyCond.Status != "True" {
		t.Errorf("expected Ready=True condition, got %+v", readyCond)
	}
	// The hub is the approver: an unapproved request is approved on success.
	if a := condOf(patchedStatus, "Approved"); a == nil || a.Status != "True" {
		t.Errorf("expected Approved=True condition, got %+v", a)
	}
}

func TestController_Reconcile_SkipsAlreadyReady(t *testing.T) {
	called := false

	hubMux := http.NewServeMux()
	hubMux.HandleFunc("POST /api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	})
	hubSrv := httptest.NewServer(hubMux)
	defer hubSrv.Close()

	cr := CertificateRequest{
		APIVersion: "cert-manager.io/v1",
		Metadata:   Metadata{Name: "already-done", Namespace: "default"},
		Spec: CRSpec{
			IssuerRef: IssuerRef{Group: IssuerGroup},
		},
		Status: CRStatus{
			Certificate: []byte("cert-data"),
			Conditions: []Condition{
				{Type: "Ready", Status: "True"},
			},
		},
	}
	list := CertificateRequestList{Items: []CertificateRequest{cr}}

	k8sMux := http.NewServeMux()
	k8sMux.HandleFunc("/apis/cert-manager.io/v1/namespaces/default/certificaterequests", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(list)
	})
	k8sSrv := httptest.NewServer(k8sMux)
	defer k8sSrv.Close()

	ctrl := NewController(
		NewK8sClient(k8sSrv.URL, "", nil),
		IssuerConfig{HubURL: hubSrv.URL},
		[]string{"default"},
	)

	_ = ctrl.reconcileAll(context.Background())
	if called {
		t.Error("expected hub NOT to be called for already-Ready CertificateRequest")
	}
}

func TestController_Reconcile_SkipsDifferentIssuerGroup(t *testing.T) {
	called := false

	hubMux := http.NewServeMux()
	hubMux.HandleFunc("POST /api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	})
	hubSrv := httptest.NewServer(hubMux)
	defer hubSrv.Close()

	cr := CertificateRequest{
		Metadata: Metadata{Name: "other-issuer", Namespace: "default"},
		Spec: CRSpec{
			IssuerRef: IssuerRef{Group: "cert-manager.io"}, // different group
		},
	}
	list := CertificateRequestList{Items: []CertificateRequest{cr}}

	k8sMux := http.NewServeMux()
	k8sMux.HandleFunc("/apis/cert-manager.io/v1/namespaces/default/certificaterequests", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(list)
	})
	k8sSrv := httptest.NewServer(k8sMux)
	defer k8sSrv.Close()

	ctrl := NewController(
		NewK8sClient(k8sSrv.URL, "", nil),
		IssuerConfig{HubURL: hubSrv.URL},
		[]string{"default"},
	)

	_ = ctrl.reconcileAll(context.Background())
	if called {
		t.Error("expected hub NOT to be called for CertificateRequest with different issuer group")
	}
}

func TestController_Reconcile_HubFailurePatches_FailedCondition(t *testing.T) {
	csrDER := buildFakeCSRDER(t)
	var patchedStatus StatusPatch

	hubMux := http.NewServeMux()
	hubMux.HandleFunc("POST /api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})
	hubSrv := httptest.NewServer(hubMux)
	defer hubSrv.Close()

	cr := CertificateRequest{
		Metadata: Metadata{Name: "fail-cr", Namespace: "default"},
		Spec: CRSpec{
			Request:   base64.StdEncoding.EncodeToString(csrDER),
			IssuerRef: IssuerRef{Group: IssuerGroup},
		},
	}
	list := CertificateRequestList{Items: []CertificateRequest{cr}}

	k8sMux := http.NewServeMux()
	k8sMux.HandleFunc("/apis/cert-manager.io/v1/namespaces/default/certificaterequests", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(list)
	})
	k8sMux.HandleFunc("/apis/cert-manager.io/v1/namespaces/default/certificaterequests/fail-cr/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&patchedStatus)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(cr)
	})
	k8sSrv := httptest.NewServer(k8sMux)
	defer k8sSrv.Close()

	ctrl := NewController(
		NewK8sClient(k8sSrv.URL, "", nil),
		IssuerConfig{HubURL: hubSrv.URL, CAID: "ca-1", TemplateID: "tpl-1"},
		[]string{"default"},
	)

	_ = ctrl.reconcileAll(context.Background())

	var readyCond *Condition
	for i := range patchedStatus.Status.Conditions {
		if patchedStatus.Status.Conditions[i].Type == "Ready" {
			readyCond = &patchedStatus.Status.Conditions[i]
		}
	}
	if readyCond == nil || readyCond.Status != "False" {
		t.Errorf("expected Ready=False condition after hub failure, got %+v", readyCond)
	}
}

func TestNeedsIssuance(t *testing.T) {
	cases := []struct {
		name   string
		cr     CertificateRequest
		expect bool
	}{
		{
			name: "pending our group",
			cr: CertificateRequest{
				Spec: CRSpec{IssuerRef: IssuerRef{Group: IssuerGroup}},
			},
			expect: true,
		},
		{
			name: "wrong group",
			cr: CertificateRequest{
				Spec: CRSpec{IssuerRef: IssuerRef{Group: "cert-manager.io"}},
			},
			expect: false,
		},
		{
			name: "already ready",
			cr: CertificateRequest{
				Spec:   CRSpec{IssuerRef: IssuerRef{Group: IssuerGroup}},
				Status: CRStatus{Conditions: []Condition{{Type: "Ready", Status: "True"}}},
			},
			expect: false,
		},
		{
			name: "already has cert",
			cr: CertificateRequest{
				Spec:   CRSpec{IssuerRef: IssuerRef{Group: IssuerGroup}},
				Status: CRStatus{Certificate: []byte("pem")},
			},
			expect: false,
		},
		{
			name: "denied",
			cr: CertificateRequest{
				Spec:   CRSpec{IssuerRef: IssuerRef{Group: IssuerGroup}},
				Status: CRStatus{Conditions: []Condition{{Type: "Denied", Status: "True"}}},
			},
			expect: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cr.needsIssuance()
			if got != tc.expect {
				t.Errorf("needsIssuance() = %v, want %v", got, tc.expect)
			}
		})
	}
}

func TestK8sClient_CRURL(t *testing.T) {
	c := NewK8sClient("https://k8s.example.com", "", nil)
	cases := []struct {
		ns, name, want string
	}{
		{"default", "", "https://k8s.example.com/apis/cert-manager.io/v1/namespaces/default/certificaterequests"},
		{"default", "my-cr", "https://k8s.example.com/apis/cert-manager.io/v1/namespaces/default/certificaterequests/my-cr"},
		{"", "", "https://k8s.example.com/apis/cert-manager.io/v1/certificaterequests"},
	}
	for _, tc := range cases {
		got := c.crURL(tc.ns, tc.name)
		if got != tc.want {
			t.Errorf("crURL(%q, %q) = %q, want %q", tc.ns, tc.name, got, tc.want)
		}
	}
}

// ---- W26-17: watch, failure conditions, backoff, alert ----

// fakeK8s serves a CertificateRequest list, a controllable watch stream and a
// status endpoint. Each watch request pops the next script from watches.
type fakeK8s struct {
	srv     *httptest.Server
	lists   chan struct{} // one send per list request
	watches chan chan string
	patches chan StatusPatch
}

func newFakeK8s(t *testing.T, crName string) *fakeK8s {
	t.Helper()
	f := &fakeK8s{
		lists:   make(chan struct{}, 16),
		watches: make(chan chan string, 16),
		patches: make(chan StatusPatch, 16),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/apis/cert-manager.io/v1/namespaces/default/certificaterequests", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			f.lists <- struct{}{}
			_ = json.NewEncoder(w).Encode(CertificateRequestList{Metadata: ListMeta{ResourceVersion: "10"}})
			return
		}
		var feed chan string
		select {
		case feed = <-f.watches:
		case <-r.Context().Done():
			return
		}
		fl := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		fl.Flush()
		for {
			select {
			case line, ok := <-feed:
				if !ok {
					return
				}
				_, _ = w.Write([]byte(line + "\n"))
				fl.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("/apis/cert-manager.io/v1/namespaces/default/certificaterequests/"+crName+"/status", func(w http.ResponseWriter, r *http.Request) {
		var p StatusPatch
		_ = json.NewDecoder(r.Body).Decode(&p)
		f.patches <- p
		_, _ = w.Write([]byte("{}"))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func watchLine(t *testing.T, typ string, cr CertificateRequest) string {
	t.Helper()
	obj, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(WatchEvent{Type: typ, Object: obj})
	return string(b)
}

func newPendingCR(t *testing.T, name string) CertificateRequest {
	t.Helper()
	return CertificateRequest{
		Metadata: Metadata{Name: name, Namespace: "default", ResourceVersion: "11"},
		Spec: CRSpec{
			Request:   base64.StdEncoding.EncodeToString(buildFakeCSRDER(t)),
			IssuerRef: IssuerRef{Group: IssuerGroup},
		},
	}
}

func hubReturning(status int, body string, calls *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			atomic.AddInt32(calls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func condOf(p StatusPatch, typ string) *Condition {
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == typ {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

func TestController_WatchReactsWithin5s(t *testing.T) {
	hub := hubReturning(http.StatusCreated, `{"data":{"certificate_pem":"`+strings.ReplaceAll(buildFakeCertPEM(t), "\n", `\n`)+`"}}`, nil)
	defer hub.Close()
	k8s := newFakeK8s(t, "new-cr")
	feed := make(chan string, 4)
	k8s.watches <- feed

	ctrl := NewController(NewK8sClient(k8s.srv.URL, "", nil),
		IssuerConfig{HubURL: hub.URL, CAID: "ca", TemplateID: "tpl"}, []string{"default"})
	ctrl.ResyncInterval = time.Hour // only the watch can explain a prompt reaction
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ctrl.Run(ctx) }()

	select {
	case <-k8s.lists:
	case <-time.After(5 * time.Second):
		t.Fatal("no initial list")
	}
	time.Sleep(100 * time.Millisecond) // let the watch establish
	sent := time.Now()
	feed <- watchLine(t, "ADDED", newPendingCR(t, "new-cr"))

	select {
	case p := <-k8s.patches:
		if time.Since(sent) > 5*time.Second {
			t.Errorf("reaction took %s", time.Since(sent))
		}
		if len(p.Status.Certificate) == 0 {
			t.Error("expected certificate in status patch")
		}
		if c := condOf(p, "Ready"); c == nil || c.Status != "True" {
			t.Errorf("expected Ready=True, got %+v", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no status patch within 5s of the watch event")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v, want context.Canceled", err)
	}
}

func TestController_WatchRelistOn410(t *testing.T) {
	k8s := newFakeK8s(t, "x")
	first := make(chan string, 1)
	first <- `{"type":"ERROR","object":{"kind":"Status","code":410,"message":"too old"}}`
	k8s.watches <- first
	second := make(chan string)
	k8s.watches <- second

	ctrl := NewController(NewK8sClient(k8s.srv.URL, "", nil), IssuerConfig{HubURL: "http://unused"}, []string{"default"})
	ctrl.ResyncInterval = time.Hour
	ctrl.retryBase = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	for i := 0; i < 2; i++ {
		select {
		case <-k8s.lists:
		case <-time.After(5 * time.Second):
			t.Fatalf("expected list #%d after 410", i+1)
		}
	}
	// The second watch (after the re-list) must have consumed its feed channel.
	deadline := time.After(5 * time.Second)
	for len(k8s.watches) != 0 {
		select {
		case <-deadline:
			t.Fatal("no new watch after re-list")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestController_PolicyDenial_SetsDeniedCondition(t *testing.T) {
	var hubCalls int32
	hub := hubReturning(http.StatusUnprocessableEntity, `{"error":"policy_violation","message":"rule min_key_size"}`, &hubCalls)
	defer hub.Close()
	k8s := newFakeK8s(t, "deny-cr")

	var gotAction, gotRes, gotDetail string
	old := certManagerAuditHook
	certManagerAuditHook = func(a, r, d string) { gotAction, gotRes, gotDetail = a, r, d }
	defer func() { certManagerAuditHook = old }()

	ctrl := NewController(NewK8sClient(k8s.srv.URL, "", nil), IssuerConfig{HubURL: hub.URL}, []string{"default"})
	cr := newPendingCR(t, "deny-cr")
	ctrl.process(context.Background(), &cr)

	p := <-k8s.patches
	for _, typ := range []string{"Denied", "Ready"} {
		c := condOf(p, typ)
		if c == nil || !strings.Contains(c.Message, "min_key_size") || !strings.Contains(c.Message, "policy_violation") {
			t.Fatalf("%s condition missing reason: %+v", typ, c)
		}
		if c.Reason != "Denied" {
			t.Errorf("%s reason = %q", typ, c.Reason)
		}
	}
	if condOf(p, "Denied").Status != "True" || condOf(p, "Ready").Status != "False" {
		t.Errorf("wrong statuses: %+v", p.Status.Conditions)
	}
	if gotAction != "certmanager.request.deny" || gotRes != "default/deny-cr" || !strings.Contains(gotDetail, "min_key_size") {
		t.Errorf("audit hook = %q %q %q", gotAction, gotRes, gotDetail)
	}

	// The patched request is Denied, so it is never retried.
	cr.Status.Conditions = p.Status.Conditions
	if cr.needsIssuance() {
		t.Error("denied request must not need issuance")
	}
	ctrl.retryDue(context.Background())
	if n := atomic.LoadInt32(&hubCalls); n != 1 {
		t.Errorf("hub called %d times, want 1", n)
	}
}

func TestController_PendingApproval_NoRepost(t *testing.T) {
	var hubCalls int32
	hub := hubReturning(http.StatusAccepted, `{"status":"pending_approval","approval_id":"ap-9"}`, &hubCalls)
	defer hub.Close()
	k8s := newFakeK8s(t, "appr-cr")
	ctrl := NewController(NewK8sClient(k8s.srv.URL, "", nil), IssuerConfig{HubURL: hub.URL}, []string{"default"})
	cr := newPendingCR(t, "appr-cr")
	ctrl.process(context.Background(), &cr)

	p := <-k8s.patches
	c := condOf(p, "Ready")
	if c == nil || c.Status != "False" || c.Reason != "PendingApproval" || !strings.Contains(c.Message, "ap-9") {
		t.Fatalf("unexpected Ready condition: %+v", c)
	}
	cr.Status.Conditions = p.Status.Conditions
	if cr.needsIssuance() {
		t.Error("pending-approval request must not be re-POSTed")
	}
}

func TestController_HubUnreachable_BacksOff(t *testing.T) {
	var hubCalls int32
	hub := hubReturning(http.StatusServiceUnavailable, "down", &hubCalls)
	defer hub.Close()
	k8s := newFakeK8s(t, "retry-cr")

	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctrl := NewController(NewK8sClient(k8s.srv.URL, "", nil), IssuerConfig{HubURL: hub.URL}, []string{"default"})
	ctrl.now = func() time.Time { return clock }
	cr := newPendingCR(t, "retry-cr")

	ctrl.process(context.Background(), &cr)
	p := <-k8s.patches
	if c := condOf(p, "Ready"); c == nil || c.Status != "False" || c.Reason != "Pending" || !strings.Contains(c.Message, "hub unreachable") {
		t.Fatalf("unexpected Ready condition: %+v", c)
	}
	if n := atomic.LoadInt32(&hubCalls); n != 1 {
		t.Fatalf("calls = %d, want 1", n)
	}

	// Inside the 2 s window nothing happens.
	clock = clock.Add(time.Second)
	ctrl.process(context.Background(), &cr)
	if n := atomic.LoadInt32(&hubCalls); n != 1 {
		t.Fatalf("retried inside backoff: calls = %d", n)
	}

	// After 2 s the attempt runs and the next delay doubles to 4 s.
	clock = clock.Add(time.Second)
	ctrl.process(context.Background(), &cr)
	<-k8s.patches
	if n := atomic.LoadInt32(&hubCalls); n != 2 {
		t.Fatalf("calls = %d, want 2", n)
	}
	clock = clock.Add(3 * time.Second)
	ctrl.process(context.Background(), &cr)
	if n := atomic.LoadInt32(&hubCalls); n != 2 {
		t.Fatalf("retried before 4 s: calls = %d", n)
	}
	clock = clock.Add(time.Second)
	ctrl.process(context.Background(), &cr)
	<-k8s.patches
	if n := atomic.LoadInt32(&hubCalls); n != 3 {
		t.Fatalf("calls = %d, want 3", n)
	}
}

func TestBackoff_DelaysCapAndReset(t *testing.T) {
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i, w := range want {
		if got := delayFor(i + 1); got != w {
			t.Errorf("delayFor(%d) = %s, want %s", i+1, got, w)
		}
	}
	if got := delayFor(50); got != 5*time.Minute {
		t.Errorf("cap = %s", got)
	}
	b := newBackoff()
	now := time.Now()
	b.fail("a/b", "a", "b", now)
	if b.begin("a/b", "a", "b", now) {
		t.Error("begin must be refused during backoff")
	}
	if len(b.due(now.Add(3*time.Second))) != 1 {
		t.Error("expected entry due after backoff")
	}
	b.reset("a/b")
	if !b.begin("a/b", "a", "b", now) {
		t.Error("begin must succeed after reset")
	}
}

func TestController_UnreachableAlertAfter5(t *testing.T) {
	hubFail := hubReturning(http.StatusBadGateway, "bad gateway", nil)
	defer hubFail.Close()
	k8s := newFakeK8s(t, "alert-cr")

	var alerts []string
	old := certManagerAlertHook
	certManagerAlertHook = func(code, detail string) { alerts = append(alerts, code+"|"+detail) }
	defer func() { certManagerAlertHook = old }()

	ctrl := NewController(NewK8sClient(k8s.srv.URL, "", nil), IssuerConfig{HubURL: hubFail.URL}, []string{"default"})
	cr := newPendingCR(t, "alert-cr")
	for i := 1; i <= 7; i++ {
		_ = ctrl.reconcile(context.Background(), &cr)
		<-k8s.patches
		if i < 5 && len(alerts) != 0 {
			t.Fatalf("alert fired after %d failures", i)
		}
	}
	if len(alerts) != 1 || alerts[0] != "certmanager.issuer.unreachable|"+hubFail.URL {
		t.Fatalf("alerts = %v, want exactly one", alerts)
	}

	// A hub success resets the counter; 5 more failures alert again.
	ctrl.Issuer.HubURL = hubReturning(http.StatusUnprocessableEntity, `{"error":"x","message":"y"}`, nil).URL
	_ = ctrl.reconcile(context.Background(), &cr)
	<-k8s.patches
	ctrl.Issuer.HubURL = hubFail.URL
	for i := 0; i < 4; i++ {
		_ = ctrl.reconcile(context.Background(), &cr)
		<-k8s.patches
	}
	if len(alerts) != 1 {
		t.Fatalf("counter not reset by hub response: %v", alerts)
	}
	_ = ctrl.reconcile(context.Background(), &cr)
	<-k8s.patches
	if len(alerts) != 2 {
		t.Fatalf("expected second alert after reset: %v", alerts)
	}
}

func TestHubError_Classification(t *testing.T) {
	cases := []struct {
		status      int
		body        string
		unreachable bool
		pending     bool
		code        string
	}{
		{500, "boom", true, false, ""},
		{502, "", true, false, ""},
		{503, "", true, false, ""},
		{429, "slow down", true, false, ""},
		{401, "bad token", true, false, ""},
		{404, "nope", true, false, ""},
		{400, `{"error":"bad_request","message":"m"}`, false, false, "bad_request"},
		{403, `{"error":"forbidden","message":"m"}`, false, false, "forbidden"},
		{409, `{"error":"conflict","message":"m"}`, false, false, "conflict"},
		{422, `{"error":"policy_violation","message":"m"}`, false, false, "policy_violation"},
		{202, `{"status":"pending_approval","approval_id":"ap-1"}`, false, true, "pending_approval"},
	}
	for _, tc := range cases {
		_, _, err := parseHubResponse(tc.status, []byte(tc.body))
		var he *HubError
		if !errors.As(err, &he) {
			t.Fatalf("%d: want *HubError, got %v", tc.status, err)
		}
		if he.Unreachable != tc.unreachable || he.PendingApproval() != tc.pending || he.Code != tc.code {
			t.Errorf("%d: got %+v", tc.status, he)
		}
	}
	if _, _, err := parseHubResponse(201, []byte(`{"data":{"certificate_pem":"PEM"}}`)); err != nil {
		t.Errorf("201 should succeed: %v", err)
	}
	if pem, fp, err := parseHubResponse(200, []byte(`{"data":{"fingerprint_sha256":"ab12"}}`)); err != nil || pem != nil || fp != "ab12" {
		t.Errorf("fingerprint-only body: pem=%q fp=%q err=%v", pem, fp, err)
	}
	if _, _, err := parseHubResponse(201, []byte(`{"data":{}}`)); err == nil {
		t.Error("body with neither certificate_pem nor fingerprint must error")
	}
	if _, err := network(); err == nil {
		t.Error("network failure should be an error")
	}
}

// network simulates a connection failure to a closed server.
func network() ([]byte, error) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	_, err := issueCertificate(context.Background(), IssuerConfig{HubURL: url}, "csr")
	var he *HubError
	if errors.As(err, &he) && he.Unreachable {
		return nil, err
	}
	return nil, nil
}

// cert-manager stores PEM bytes in spec.request; the PEM must reach the hub
// unchanged (not wrapped a second time), and bare DER must still work.
func TestCSRToPEM(t *testing.T) {
	der := buildFakeCSRDER(t)
	wantPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	for name, raw := range map[string][]byte{"pem": []byte(wantPEM), "der": der} {
		got, err := csrToPEM(base64.StdEncoding.EncodeToString(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != wantPEM {
			t.Errorf("%s: got %q want %q", name, got, wantPEM)
		}
		blk, _ := pem.Decode([]byte(got))
		if blk == nil || blk.Type != "CERTIFICATE REQUEST" || !bytes.Equal(blk.Bytes, der) {
			t.Errorf("%s: PEM does not round-trip to the CSR DER", name)
		}
	}
	if _, err := csrToPEM("!!notbase64"); err == nil {
		t.Error("want error for invalid base64")
	}
}

// cert-manager's webhook rejects Denied on an approved request (found live:
// "both 'Denied' and 'Approved' conditions cannot coexist"), so the issuer
// must mark such a request Ready=False/Denied instead, and never retry it.
func TestController_DenialOnApprovedRequest_UsesReadyDenied(t *testing.T) {
	var hubCalls int32
	hub := hubReturning(http.StatusUnprocessableEntity, `{"error":"policy_violation","message":"name policy"}`, &hubCalls)
	defer hub.Close()
	k8s := newFakeK8s(t, "appr-cr")
	ctrl := NewController(NewK8sClient(k8s.srv.URL, "", nil), IssuerConfig{HubURL: hub.URL}, []string{"default"})
	cr := newPendingCR(t, "appr-cr")
	cr.Status.Conditions = []Condition{{Type: "Approved", Status: "True"}}
	ctrl.process(context.Background(), &cr)

	p := <-k8s.patches
	if condOf(p, "Denied") != nil {
		t.Fatalf("Denied must not be set on an approved request: %+v", p.Status.Conditions)
	}
	if r := condOf(p, "Ready"); r == nil || r.Status != "False" || r.Reason != "Denied" || !strings.Contains(r.Message, "policy_violation") {
		t.Fatalf("Ready condition = %+v", r)
	}
	if a := condOf(p, "Approved"); a == nil || a.Status != "True" {
		t.Errorf("Approved condition must be preserved: %+v", p.Status.Conditions)
	}
	cr.Status.Conditions = p.Status.Conditions
	if cr.needsIssuance() {
		t.Error("Ready=False/Denied request must not need issuance")
	}
}

// The real hub's POST /api/v1/certificates body is the inventory item (no
// certificate_pem; found live); the PEM comes from the download endpoint.
func TestIssueCertificate_DownloadsPEMFromFingerprint(t *testing.T) {
	certPEM := buildFakeCertPEM(t)
	var gotAuth, gotPath, gotQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"fingerprint_sha256":"ab12cd","common_name":"x"}}`))
	})
	mux.HandleFunc("GET /api/v1/certificates/{fp}/download", func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotQuery = r.Header.Get("Authorization"), r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(certPEM))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, err := issueCertificate(context.Background(), IssuerConfig{HubURL: srv.URL, APIToken: "tok"}, "csr")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != certPEM {
		t.Errorf("got %q", got)
	}
	if gotAuth != "Bearer tok" || gotPath != "/api/v1/certificates/ab12cd/download" || gotQuery != "format=pem&include_chain=true" {
		t.Errorf("download request: auth=%q path=%q query=%q", gotAuth, gotPath, gotQuery)
	}
}

func TestIssueCertificate_DownloadFailureIsRetriable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"fingerprint_sha256":"ab12cd"}}`))
	})
	mux.HandleFunc("GET /api/v1/certificates/{fp}/download", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	_, err := issueCertificate(context.Background(), IssuerConfig{HubURL: srv.URL}, "csr")
	var he *HubError
	if !errors.As(err, &he) || !he.Unreachable {
		t.Fatalf("want retriable HubError, got %v", err)
	}
}
