// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
)

// W6-05: the CycloneDX 1.6 CBOM — certs, keys, algorithms, protocols,
// always current.

type cbomFakeCertProvider struct {
	CertificateProvider
	items []CertificateItem
}

func (f *cbomFakeCertProvider) ListCertificates(context.Context, CertificateListQuery) (CertificateListResult, error) {
	return CertificateListResult{Items: f.items, Total: len(f.items)}, nil
}

type cbomFakeDiscovery struct {
	DiscoveryProvider
	endpoints []DiscoveryEndpoint
}

func (f *cbomFakeDiscovery) ListEndpoints(context.Context, DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	return DiscoveryEndpointResult{Endpoints: f.endpoints, Total: len(f.endpoints)}, nil
}

func newCBOMFixture(t *testing.T) (*cbomFakeCertProvider, *keystore.SoftwareStore, *cbomFakeDiscovery) {
	t.Helper()
	certs := &cbomFakeCertProvider{items: []CertificateItem{{
		FingerprintSHA256:  "fp-1",
		CommonName:         "web.example.com",
		SubjectDN:          "CN=web.example.com",
		IssuerDN:           "CN=Example Root CA",
		ValidFrom:          "2026-01-01T00:00:00Z",
		ValidUntil:         "2027-01-01T00:00:00Z",
		PublicKeyAlgorithm: "ECDSA-P256",
		SignatureAlgorithm: "ML-DSA-65",
	}}}
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("cbom-export-test-passphrase-32b!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })
	if _, err := keys.GenerateKey("inventory-key", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	discovery := &cbomFakeDiscovery{endpoints: []DiscoveryEndpoint{
		{ID: "ep-1", Hostname: "lb.internal", Port: 443, Protocol: "tls"},
		{ID: "ep-2", Hostname: "bastion.internal", Port: 22, Protocol: "ssh"},
	}}
	return certs, keys, discovery
}

func TestCBOMExportsAllFourAssetTypes(t *testing.T) {
	certs, keys, discovery := newCBOMFixture(t)

	doc, err := BuildCBOM(context.Background(), certs, keys, discovery)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Fatalf("not a CycloneDX 1.6 BOM: %s %s", doc.BOMFormat, doc.SpecVersion)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(doc.SerialNumber) {
		t.Fatalf("serialNumber must be an RFC 4122 urn:uuid, got %q", doc.SerialNumber)
	}

	byType := map[string][]cbomComponent{}
	for _, comp := range doc.Components {
		if comp.Type != "cryptographic-asset" {
			t.Fatalf("every component must be a cryptographic-asset, got %q", comp.Type)
		}
		byType[comp.CryptoProperties.AssetType] = append(byType[comp.CryptoProperties.AssetType], comp)
	}
	for _, want := range []string{"certificate", "related-crypto-material", "algorithm", "protocol"} {
		if len(byType[want]) == 0 {
			t.Fatalf("missing asset type %q; have %v", want, len(doc.Components))
		}
	}

	// Certificate content.
	cert := byType["certificate"][0]
	cp := cert.CryptoProperties.CertificateProperties
	if cp == nil || cp.SubjectName != "CN=web.example.com" || cp.NotValidAfter != "2027-01-01T00:00:00Z" || cp.CertificateFormat != "X.509" {
		t.Fatalf("certificate properties wrong: %+v", cp)
	}
	// Key: metadata only, never material.
	key := byType["related-crypto-material"][0]
	if key.CryptoProperties.RelatedCryptoMaterial.Type != "private-key" {
		t.Fatalf("key material type wrong: %+v", key.CryptoProperties.RelatedCryptoMaterial)
	}
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("CBOM must never contain key material")
	}
	// ML-DSA algorithm carries its NIST quantum security level.
	foundMLDSA := false
	for _, alg := range byType["algorithm"] {
		if alg.Name == "ML-DSA-65" {
			foundMLDSA = true
			if alg.CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel != 3 {
				t.Fatalf("ML-DSA-65 must carry NIST level 3: %+v", alg.CryptoProperties.AlgorithmProperties)
			}
		}
	}
	if !foundMLDSA {
		t.Fatal("signature algorithm ML-DSA-65 missing from algorithm assets")
	}
	// Protocols: tls and ssh both mapped onto the schema enum.
	protoTypes := map[string]bool{}
	for _, p := range byType["protocol"] {
		protoTypes[p.CryptoProperties.ProtocolProperties.Type] = true
	}
	if !protoTypes["tls"] || !protoTypes["ssh"] {
		t.Fatalf("protocol enum mapping wrong: %v", protoTypes)
	}

	// The JSON round-trips.
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
}

func TestCBOMIsAlwaysCurrent(t *testing.T) {
	certs, keys, discovery := newCBOMFixture(t)
	first, err := BuildCBOM(context.Background(), certs, keys, discovery)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	certs.items = append(certs.items, CertificateItem{
		FingerprintSHA256: "fp-2", CommonName: "new.example.com",
	})
	second, err := BuildCBOM(context.Background(), certs, keys, discovery)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if len(second.Components) != len(first.Components)+1 {
		t.Fatalf("export must reflect live inventory: %d -> %d", len(first.Components), len(second.Components))
	}
	if second.SerialNumber == first.SerialNumber {
		t.Fatal("each export must carry a fresh serial number")
	}
}

func TestCBOMEndpointServesCycloneDX(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "cbom-token")
	auth := NewAuthenticatorFromEnv()
	certs, keys, discovery := newCBOMFixture(t)

	mux := http.NewServeMux()
	RegisterCBOMHandlers(mux, auth, certs, keys, discovery, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cbom", nil)
	req.Header.Set("Authorization", "Bearer cbom-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.cyclonedx+json" {
		t.Fatalf("wrong content type %q", ct)
	}
	var doc cbomDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" || len(doc.Components) == 0 {
		t.Fatalf("malformed served BOM: %+v", doc)
	}

	// Unauthenticated: refused.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/cbom", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}
}
