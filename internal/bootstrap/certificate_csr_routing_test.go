// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// relabel re-encodes the DER of a PEM CSR under the given label.
func relabelCSRPEM(t *testing.T, csrPEM, label string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("not PEM")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: block.Bytes}))
}

// tamperCSRPEM flips a byte inside the trailing signature of the CSR.
func tamperCSRPEM(t *testing.T, csrPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("not PEM")
	}
	der := append([]byte(nil), block.Bytes...)
	der[len(der)-1] ^= 0xFF
	return string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der}))
}

func TestIssueCertificate_MLDSACSRUnderStandardLabel(t *testing.T) {
	// ML-DSA leaf key from the keystore; the CA under test is ECDSA in one
	// case and ML-DSA in the other.
	t.Run("ECDSA CA", func(t *testing.T) {
		provider, engine := newTestCAProvider(t)
		keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-for-ca-provider!"))
		if err != nil {
			t.Fatal(err)
		}
		csr, _ := generateTestMLDSACSRPEM(t, keys, "std-label.example.com", "std-label.example.com")
		std := relabelCSRPEM(t, csr, "CERTIFICATE REQUEST")
		res, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
			CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls", CSRPEM: std, TeamID: "team-1",
		})
		if err != nil {
			t.Fatalf("issue from standard-label ML-DSA CSR: %v", err)
		}
		if res.CommonName != "std-label.example.com" {
			t.Errorf("CN = %q", res.CommonName)
		}
	})
	t.Run("ML-DSA CA", func(t *testing.T) {
		provider, engine, keys := newTestMLDSACAProvider(t)
		csr, _ := generateTestMLDSACSRPEM(t, keys, "std-label2.example.com", "std-label2.example.com")
		std := relabelCSRPEM(t, csr, "CERTIFICATE REQUEST")
		if _, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
			CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls", CSRPEM: std, TeamID: "team-1",
		}); err != nil {
			t.Fatalf("issue from standard-label ML-DSA CSR: %v", err)
		}
	})
	t.Run("real openssl CSR", func(t *testing.T) {
		raw, err := os.ReadFile("../ca/testdata/openssl_mldsa65_std_label.csr")
		if err != nil {
			t.Fatal(err)
		}
		provider, engine := newTestCAProvider(t)
		res, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
			CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls", CSRPEM: string(raw), TeamID: "team-1",
		})
		if err != nil {
			t.Fatalf("issue from openssl ML-DSA-65 CSR: %v", err)
		}
		if res.CommonName != "pq.example.test" {
			t.Errorf("CN = %q", res.CommonName)
		}
	})
}

func TestIssueCertificate_TamperedCSRsAreInvalidCSR(t *testing.T) {
	provider, engine, keys := newTestMLDSACAProvider(t)
	caID := getFirstCAID(t, engine)
	mldsa, _ := generateTestMLDSACSRPEM(t, keys, "bad.example.com", "bad.example.com")
	classical := generateTestCSRPEM(t, "bad-classical.example.com", "bad-classical.example.com")

	cases := map[string]string{
		"ml-dsa custom label":   tamperCSRPEM(t, mldsa),
		"ml-dsa standard label": tamperCSRPEM(t, relabelCSRPEM(t, mldsa, "CERTIFICATE REQUEST")),
		"classical":             tamperCSRPEM(t, classical),
	}
	for name, csrPEM := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
				CAID: caID, TemplateID: "tpl-tls", CSRPEM: csrPEM, TeamID: "team-1",
			})
			if !errors.Is(err, errCertificateInvalid) || !errors.Is(err, ca.ErrInvalidCSR) {
				t.Fatalf("err = %v, want errCertificateInvalid wrapping ca.ErrInvalidCSR", err)
			}
		})
	}
}

func TestRenewCertificate_MLDSACSRUnderStandardLabel(t *testing.T) {
	provider, engine, keys := newTestMLDSACAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csr, _ := generateTestMLDSACSRPEM(t, keys, "renew-std.example.com", "renew-std.example.com")
	original, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-tls", CSRPEM: csr, TeamID: "team-1"})
	if err != nil {
		t.Fatal(err)
	}

	renewCSR, _ := generateTestMLDSACSRPEM(t, keys, "renew-std2.example.com", "renew-std.example.com")
	std := relabelCSRPEM(t, renewCSR, "CERTIFICATE REQUEST")

	// Tampered first, so the predecessor stays unsuperseded for the success case.
	_, err = provider.RenewCertificate(ctx, original.FingerprintSHA256, CertificateRenewRequest{CSRPEM: tamperCSRPEM(t, std)})
	if !errors.Is(err, errCertificateInvalid) || !errors.Is(err, ca.ErrInvalidCSR) {
		t.Fatalf("tampered renew err = %v, want errCertificateInvalid wrapping ca.ErrInvalidCSR", err)
	}
	if _, err := provider.RenewCertificate(ctx, original.FingerprintSHA256, CertificateRenewRequest{CSRPEM: std}); err != nil {
		t.Fatalf("renew from standard-label ML-DSA CSR: %v", err)
	}
}

func TestIssueCertificate_ClassicalCSRStillWorks(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	if _, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls",
		CSRPEM: generateTestCSRPEM(t, "classical.example.com", "classical.example.com"), TeamID: "team-1",
	}); err != nil {
		t.Fatalf("classical issue: %v", err)
	}
}

// Handler status codes. Before the fix each of the 400/409 cases below was a
// 503 "certificate unavailable".
func TestCertificateHandlers_CSRAndCAStateStatusCodes(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	provider, engine, keys := newTestMLDSACAProvider(t)
	caID := getFirstCAID(t, engine)
	mux := http.NewServeMux()
	registerCertificateHandlers(mux, NewAuthenticatorFromEnv(), provider, stubAuditProviderForCertificate{}, nil)

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	issueBody := func(csrPEM string) string {
		b, _ := json.Marshal(map[string]string{"ca_id": caID, "template_id": "tpl-tls", "csr_pem": csrPEM, "team_id": "team-1"})
		return string(b)
	}
	message := func(rec *httptest.ResponseRecorder) string {
		var out struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Message
	}

	good, _ := generateTestMLDSACSRPEM(t, keys, "h.example.com", "h.example.com")
	std := relabelCSRPEM(t, good, "CERTIFICATE REQUEST")

	rec := post("/api/v1/certificates", issueBody(tamperCSRPEM(t, std)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(message(rec), "invalid CSR") {
		t.Fatalf("tampered ML-DSA issue: %d %s, want 400 invalid CSR", rec.Code, rec.Body.String())
	}

	rec = post("/api/v1/certificates", issueBody(std))
	if rec.Code != http.StatusCreated {
		t.Fatalf("standard-label ML-DSA issue: %d %s, want 201", rec.Code, rec.Body.String())
	}
	var issued struct {
		Data CertificateIssueResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}

	renewCSR, _ := generateTestMLDSACSRPEM(t, keys, "h2.example.com", "h.example.com")
	rec = post("/api/v1/certificates/"+issued.Data.FingerprintSHA256+"/renew",
		`{"csr_pem":`+jsonString(tamperCSRPEM(t, relabelCSRPEM(t, renewCSR, "CERTIFICATE REQUEST")))+`}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(message(rec), "invalid CSR") {
		t.Fatalf("tampered ML-DSA renew: %d %s, want 400 invalid CSR", rec.Code, rec.Body.String())
	}

	// A suspended CA cannot sign: a conflict, not an outage.
	if err := engine.UpdateCAStatus(caID, "suspended"); err != nil {
		t.Fatal(err)
	}
	rec = post("/api/v1/certificates", issueBody(std))
	if rec.Code != http.StatusConflict || !strings.Contains(message(rec), "not active") {
		t.Fatalf("suspended CA issue: %d %s, want 409 not active", rec.Code, rec.Body.String())
	}
	rec = post("/api/v1/certificates/"+issued.Data.FingerprintSHA256+"/renew",
		`{"csr_pem":`+jsonString(relabelCSRPEM(t, renewCSR, "CERTIFICATE REQUEST"))+`}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("suspended CA renew: %d %s, want 409", rec.Code, rec.Body.String())
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestWriteCSRorCAStateError_NoSigningKeyAndPassThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	if writeCSRorCAStateError(rec, errors.New("backend down")) {
		t.Fatal("unrelated error must not be mapped")
	}
	rec = httptest.NewRecorder()
	wrapped := fmt.Errorf("ca issuance failed: %w", ca.ErrCANoSigningKey)
	if !writeCSRorCAStateError(rec, wrapped) || rec.Code != http.StatusConflict {
		t.Fatalf("no-signing-key: code=%d, want 409", rec.Code)
	}
}
