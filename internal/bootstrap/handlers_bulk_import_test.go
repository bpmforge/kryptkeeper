// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W11-02 bulk import: 500 certs in one call through the production import
// path, dedupe by fingerprint, key material rejected whole, CSV ownership.

func newBulkImportTestMux(t *testing.T) (*http.ServeMux, CertificateProvider) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)

	mux := http.NewServeMux()
	RegisterBulkImportHandler(mux, auth, provider, stubAuditProvider{})
	return mux, provider
}

func postBulkImport(t *testing.T, mux *http.ServeMux, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/bulk-import", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// selfSignedDER mints one throwaway cert; the shared key keeps 500 certs fast.
func selfSignedDER(t *testing.T, key *ecdsa.PrivateKey, cn string, serial int64) []byte {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

func decodeBulkResult(t *testing.T, rec *httptest.ResponseRecorder) bulkImportResult {
	t.Helper()
	var resp struct {
		Data bulkImportResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return resp.Data
}

func TestBulkImport500PEMsThenDedupe(t *testing.T) {
	mux, provider := newBulkImportTestMux(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var bundle strings.Builder
	for i := 0; i < 500; i++ {
		der := selfSignedDER(t, key, fmt.Sprintf("bulk-%03d.example.com", i), int64(1000+i))
		bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	rec := postBulkImport(t, mux, map[string]string{"bundle": bundle.String(), "team_id": "team-bulk"})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	result := decodeBulkResult(t, rec)
	if result.Imported != 500 || result.SkippedDuplicates != 0 || len(result.Failed) != 0 {
		t.Fatalf("first import wrong: imported=%d skipped=%d failed=%d",
			result.Imported, result.SkippedDuplicates, len(result.Failed))
	}

	// Every row landed in inventory as imported/unmanaged (W11-01 estate).
	listed, err := provider.ListCertificates(context.Background(), CertificateListQuery{Origin: "imported", Limit: 100})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if listed.Total != 500 {
		t.Fatalf("expected 500 imported certs in inventory, got %d", listed.Total)
	}
	if listed.Items[0].ManagementState != "unmanaged" || listed.Items[0].RiskScore == 0 && listed.Items[0].Grade == "" {
		t.Fatalf("imported cert missing estate/risk fields: %+v", listed.Items[0])
	}

	// Re-importing the same bundle skips everything by fingerprint.
	rec2 := postBulkImport(t, mux, map[string]string{"bundle": bundle.String(), "team_id": "team-bulk"})
	result2 := decodeBulkResult(t, rec2)
	if result2.Imported != 0 || result2.SkippedDuplicates != 500 {
		t.Fatalf("dedupe wrong: imported=%d skipped=%d", result2.Imported, result2.SkippedDuplicates)
	}
}

func TestBulkImportRejectsPrivateKeyMaterialWhole(t *testing.T) {
	mux, provider := newBulkImportTestMux(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	der := selfSignedDER(t, key, "with-key.example.com", 7)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	rec := postBulkImport(t, mux, map[string]string{"bundle": bundle, "team_id": "team-bulk"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for key material, got %d: %s", rec.Code, rec.Body.String())
	}
	// NOTHING imported — the certificate before the key block must not land.
	listed, err := provider.ListCertificates(context.Background(), CertificateListQuery{Origin: "imported", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if listed.Total != 0 {
		t.Fatalf("a cert imported despite key material in the bundle: %d", listed.Total)
	}
}

func TestBulkImportCSVWithPerRowOwnership(t *testing.T) {
	mux, provider := newBulkImportTestMux(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	der1 := selfSignedDER(t, key, "csv-1.example.com", 21)
	der2 := selfSignedDER(t, key, "csv-2.example.com", 22)
	csvBody := "cert_b64,owner_email,owner_team\n" +
		base64.StdEncoding.EncodeToString(der1) + ",alice@example.com,platform\n" +
		base64.StdEncoding.EncodeToString(der2) + ",,\n"

	rec := postBulkImport(t, mux, map[string]string{
		"format": "csv", "bundle": csvBody, "team_id": "team-bulk",
		"owner_team": "fallback-team",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	result := decodeBulkResult(t, rec)
	if result.Imported != 2 {
		t.Fatalf("expected 2 imported, got %+v", result)
	}

	byCN := map[string]CertificateItem{}
	listed, _ := provider.ListCertificates(context.Background(), CertificateListQuery{Origin: "imported", Limit: 10})
	for _, item := range listed.Items {
		byCN[item.CommonName] = item
	}
	if byCN["csv-1.example.com"].OwnerEmail != "alice@example.com" || byCN["csv-1.example.com"].OwnerTeam != "platform" {
		t.Fatalf("per-row ownership not applied: %+v", byCN["csv-1.example.com"])
	}
	if byCN["csv-2.example.com"].OwnerTeam != "fallback-team" {
		t.Fatalf("body-level ownership fallback not applied: %+v", byCN["csv-2.example.com"])
	}
}

func TestBulkImportDERB64(t *testing.T) {
	mux, _ := newBulkImportTestMux(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundle := base64.StdEncoding.EncodeToString(selfSignedDER(t, key, "der-1.example.com", 31)) + "\n" +
		base64.StdEncoding.EncodeToString(selfSignedDER(t, key, "der-2.example.com", 32))

	rec := postBulkImport(t, mux, map[string]string{"format": "der_b64", "bundle": bundle, "team_id": "team-bulk"})
	result := decodeBulkResult(t, rec)
	if rec.Code != http.StatusOK || result.Imported != 2 {
		t.Fatalf("der_b64 import wrong: code=%d %+v", rec.Code, result)
	}
}

func TestBulkImportBadItemsDoNotSinkTheBatch(t *testing.T) {
	mux, _ := newBulkImportTestMux(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := selfSignedDER(t, key, "good.example.com", 41)
	// One valid cert + one garbage DER (valid base64, not a certificate).
	bundle := base64.StdEncoding.EncodeToString(good) + "\n" +
		base64.StdEncoding.EncodeToString([]byte("not a certificate at all"))

	rec := postBulkImport(t, mux, map[string]string{"format": "der_b64", "bundle": bundle, "team_id": "team-bulk"})
	result := decodeBulkResult(t, rec)
	if rec.Code != http.StatusOK || result.Imported != 1 || len(result.Failed) != 1 || result.Failed[0].Index != 1 {
		t.Fatalf("partial-batch handling wrong: code=%d %+v", rec.Code, result)
	}
}

func TestBulkImportEmptyAndOversizeRejected(t *testing.T) {
	mux, _ := newBulkImportTestMux(t)
	rec := postBulkImport(t, mux, map[string]string{"bundle": "no pem here"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty bundle, got %d", rec.Code)
	}
}
