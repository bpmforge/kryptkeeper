// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

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

// Vendored schema: https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json
// (CycloneDX/specification, Apache-2.0; the file carries its own licence
// "$comment"). Kept byte-identical. Its two external $refs (spdx, jsf) are
// stubbed in the test: Kryptkeeper emits neither licences nor signatures.
//
//go:embed testdata/cyclonedx-1.6.schema.json
var cyclonedx16Schema []byte

func compileCycloneDX16(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("http://cyclonedx.org/schema/spdx.schema.json", map[string]any{"enum": []any{"Apache-2.0"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("http://cyclonedx.org/schema/jsf-0.82.schema.json", map[string]any{"definitions": map[string]any{"signature": map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(cyclonedx16Schema))
	if err != nil {
		t.Fatal(err)
	}
	const url = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func cbomGET(t *testing.T, certs CertificateProvider, keys keystore.Store, discovery DiscoveryProvider) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "cbom-token")
	mux := http.NewServeMux()
	RegisterCBOMHandlers(mux, NewAuthenticatorFromEnv(), certs, keys, discovery, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cbom", nil)
	req.Header.Set("Authorization", "Bearer cbom-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	return rec
}

func TestCBOMValidatesAgainstCycloneDX16(t *testing.T) {
	sch := compileCycloneDX16(t)
	certs, keys, discovery := newCBOMFixture(t)
	certs.items = append(certs.items, CertificateItem{FingerprintSHA256: "fp-bare"})
	rec := cbomGET(t, certs, keys, discovery)
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("CBOM is not valid CycloneDX 1.6: %v", err)
	}
}

func manyCerts(n int) []CertificateItem {
	items := make([]CertificateItem, n)
	for i := range items {
		items[i] = CertificateItem{
			FingerprintSHA256:  fmt.Sprintf("fp-%06d", i),
			CommonName:         fmt.Sprintf("host-%d.example.test", i),
			ValidFrom:          "2026-01-01T00:00:00Z",
			ValidUntil:         "2027-01-01T00:00:00Z",
			PublicKeyAlgorithm: []string{"RSA-2048", "ECDSA-P256", "ECDSA-P384"}[i%3],
			SignatureAlgorithm: []string{"SHA256-RSA", "ECDSA-P256", "ML-DSA-65"}[i%3],
			KeySizeBits:        2048,
			PQCReadiness:       "vulnerable",
		}
	}
	return items
}

func countByAssetType(doc cbomDocument) map[string]int {
	out := map[string]int{}
	for _, c := range doc.Components {
		out[c.CryptoProperties.AssetType]++
	}
	return out
}

func TestCBOMBomRefsUnique(t *testing.T) {
	certs := &cbomFakeCertProvider{items: manyCerts(1000)}
	certs.items = append(certs.items, certs.items[0]) // repeated fingerprint
	doc, err := BuildCBOM(context.Background(), certs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Components {
		if seen[c.BOMRef] {
			t.Fatalf("duplicate bom-ref %q", c.BOMRef)
		}
		seen[c.BOMRef] = true
	}
	if n := countByAssetType(doc)["certificate"]; n != 1000 {
		t.Fatalf("expected 1000 certificate components, got %d", n)
	}
}

func TestCBOMCountsReconcileWithInventory(t *testing.T) {
	_, keys, discovery := newCBOMFixture(t)
	for _, id := range []string{"k2", "k3"} {
		if _, err := keys.GenerateKey(id, keystore.ECDSAP256); err != nil {
			t.Fatal(err)
		}
	}
	discovery.endpoints = append(discovery.endpoints,
		DiscoveryEndpoint{ID: "ep-3", Hostname: "a.internal", Port: 443, Protocol: "tls"},
		DiscoveryEndpoint{ID: "ep-4", Hostname: "b.internal", Port: 443, Protocol: "tls"})
	certs := &cbomFakeCertProvider{items: manyCerts(1000)}

	doc, err := BuildCBOM(context.Background(), certs, keys, discovery)
	if err != nil {
		t.Fatal(err)
	}
	items, err := listAllCertificates(context.Background(), certs, CertificateListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	algs := map[string]bool{}
	for _, c := range items.Items {
		algs[c.SignatureAlgorithm] = true
		algs[c.PublicKeyAlgorithm] = true
	}
	metas, _ := keys.List()
	for _, m := range metas {
		algs[string(m.Algorithm)] = true
	}
	got := countByAssetType(doc)
	want := map[string]int{"certificate": len(items.Items), "related-crypto-material": 3, "protocol": 4, "algorithm": len(algs)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("component counts %v != inventory %v", got, want)
	}
	if got["certificate"] != 1000 {
		t.Fatalf("expected 1000 certs, got %d", got["certificate"])
	}
	total := 0
	for _, n := range want {
		total += n
	}
	if len(doc.Components) != total {
		t.Fatalf("total %d != sum %d", len(doc.Components), total)
	}
}

func TestCBOMCertificatesCarryAlgorithmAndPQCProperties(t *testing.T) {
	certs := &cbomFakeCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-q", CommonName: "q", SignatureAlgorithm: "ML-DSA-65", PublicKeyAlgorithm: "ML-DSA-65", KeySizeBits: 2592, PQCReadiness: "quantum_safe"},
		{FingerprintSHA256: "fp-empty"},
	}}
	doc, err := BuildCBOM(context.Background(), certs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"kryptkeeper:public-key-algorithm", "kryptkeeper:signature-algorithm", "kryptkeeper:key-size-bits", "kryptkeeper:pqc-readiness"}
	refs := map[string]bool{}
	for _, c := range doc.Components {
		refs[c.BOMRef] = true
	}
	for _, c := range doc.Components {
		if c.CryptoProperties.AssetType != "certificate" {
			if len(c.Properties) != 0 {
				t.Fatalf("non-certificate %s has properties", c.BOMRef)
			}
			continue
		}
		if len(c.Properties) != 4 {
			t.Fatalf("%s: expected 4 properties, got %v", c.BOMRef, c.Properties)
		}
		for i, p := range c.Properties {
			if p.Name != wantNames[i] || p.Value == "" {
				t.Fatalf("%s: bad property %d: %+v", c.BOMRef, i, p)
			}
		}
		if ref := c.CryptoProperties.CertificateProperties.SignatureAlgorithmRef; ref != "" && !refs[ref] {
			t.Fatalf("%s: signatureAlgorithmRef %q has no algorithm component", c.BOMRef, ref)
		}
		switch c.BOMRef {
		case "certificate:fp-q":
			if c.Properties[1].Value != "ML-DSA-65" || c.Properties[2].Value != "2592" || c.Properties[3].Value != "quantum_safe" {
				t.Fatalf("quantum-safe cert properties wrong: %+v", c.Properties)
			}
		case "certificate:fp-empty":
			if c.Properties[0].Value != "unknown" || c.Properties[1].Value != "unknown" || c.Properties[2].Value != "0" || c.Properties[3].Value != "unknown" {
				t.Fatalf("empty cert should read unknown: %+v", c.Properties)
			}
			if c.CryptoProperties.CertificateProperties.SignatureAlgorithmRef != "" {
				t.Fatal("no signatureAlgorithmRef expected for empty algorithm")
			}
		}
	}
}

func TestCBOMStreams10kCertsUnder30s(t *testing.T) {
	certs := &cbomFakeCertProvider{items: manyCerts(10000)}
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "cbom-token")
	mux := http.NewServeMux()
	RegisterCBOMHandlers(mux, NewAuthenticatorFromEnv(), certs, nil, nil, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cbom", nil)
	req.Header.Set("Authorization", "Bearer cbom-token")
	rec := httptest.NewRecorder()

	start := time.Now()
	mux.ServeHTTP(rec, req)
	elapsed := time.Since(start)
	t.Logf("10,000-cert CBOM export took %v (%d bytes)", elapsed, rec.Body.Len())
	if elapsed >= 30*time.Second {
		t.Fatalf("export took %v, want < 30s", elapsed)
	}
	if !rec.Flushed {
		t.Fatal("response was not flushed incrementally")
	}
	var doc cbomDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := countByAssetType(doc)["certificate"]; n != 10000 {
		t.Fatalf("expected 10000 certificate components, got %d", n)
	}
}

func TestWriteCBOMMatchesMarshal(t *testing.T) {
	certs, keys, discovery := newCBOMFixture(t)
	full, err := BuildCBOM(context.Background(), certs, keys, discovery)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := BuildCBOM(context.Background(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]cbomDocument{"fixture": full, "empty": empty} {
		var buf bytes.Buffer
		if err := writeCBOM(&buf, doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got, want any
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("%s: streamed output is not JSON: %v", name, err)
		}
		raw, _ := json.Marshal(doc)
		_ = json.Unmarshal(raw, &want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: streamed output differs from json.Marshal", name)
		}
	}
	if !strings.Contains(func() string { var b bytes.Buffer; _ = writeCBOM(&b, empty); return b.String() }(), `"components":[]`) {
		t.Fatal(`empty doc must serialize "components":[]`)
	}
}
