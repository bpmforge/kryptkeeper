// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certmanagerissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
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
