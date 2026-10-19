// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W31-02 (UC-M21, D-104/D-105): chain-label fixtures. Already covered
// elsewhere, deliberately not duplicated here:
//   - ML-DSA leaf under ECDSA root:        TestComputePQCReadiness_MLDSALeafClassicalCA
//   - ML-DSA leaf under ML-DSA root:       TestComputePQCReadiness_MLDSALeafMLDSACA
//   - classical root, ML-DSA int + leaf:   TestComputePQCReadiness_MultiTierChainClassicalRootDemotesLeaf

const pqcLabelDay = 24 * time.Hour

func newPQCLabelEngine(t *testing.T) (*ca.Engine, keystore.Store, CertificateProvider) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	return engine, keys, NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false)
}

func issuePQCLabelLeaf(t *testing.T, provider CertificateProvider, keys keystore.Store, caID, cn string) CertificateIssueResult {
	t.Helper()
	csrPEM, _ := generateTestMLDSACSRPEM(t, keys, cn)
	res, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: caID, TemplateID: "tpl-tls", CSRPEM: csrPEM, TeamID: "team-1",
	})
	if err != nil {
		t.Fatalf("issue ML-DSA leaf %s: %v", cn, err)
	}
	return res
}

func mustRootCA(t *testing.T, engine *ca.Engine, name string, algo keystore.Algorithm) *ca.CA {
	t.Helper()
	root, err := engine.CreateRootCA(name, pkix.Name{CommonName: name}, algo, 10*365*pqcLabelDay)
	if err != nil {
		t.Fatalf("create root %s (%s): %v", name, algo, err)
	}
	return root
}

func mustIntermediateCA(t *testing.T, engine *ca.Engine, name string, algo keystore.Algorithm, parentID string) *ca.CA {
	t.Helper()
	c, err := engine.CreateIntermediateCA(name, pkix.Name{CommonName: name}, algo, parentID, 5*365*pqcLabelDay)
	if err != nil {
		t.Fatalf("create intermediate %s (%s) under %s: %v", name, algo, parentID, err)
	}
	return c
}

func TestPQCLabel_MLDSALeafUnderRSARoot(t *testing.T) {
	engine, keys, provider := newPQCLabelEngine(t)
	root := mustRootCA(t, engine, "RSA Root", keystore.RSA2048)
	res := issuePQCLabelLeaf(t, provider, keys, root.ID, "rsa-root-leaf.example.com")
	if res.PQCReadiness != pqcReadinessLeafOnly {
		t.Fatalf("PQCReadiness = %q, want %q", res.PQCReadiness, pqcReadinessLeafOnly)
	}

	items := []CertificateItem{
		{FingerprintSHA256: "qs-1", PQCReadiness: "quantum_safe"},
		{FingerprintSHA256: "qs-2", PQCReadiness: "quantum_safe"},
		{FingerprintSHA256: res.FingerprintSHA256, PQCReadiness: res.PQCReadiness},
	}
	cd := computePQCCountdown(context.Background(), items, nil, nil, time.Now().UTC(), nil)
	if cd.QuantumSafe != 2 {
		t.Errorf("QuantumSafe = %d, want 2 (leaf-only must not raise it)", cd.QuantumSafe)
	}
	if cd.QuantumSafeLeafOnly != 1 {
		t.Errorf("QuantumSafeLeafOnly = %d, want 1", cd.QuantumSafeLeafOnly)
	}
	if cd.Status == "complete" {
		t.Errorf("countdown status = %q, must not be complete while a leaf-only cert exists", cd.Status)
	}
}

func TestPQCLabel_ThreeTierAllMLDSA(t *testing.T) {
	engine, keys, provider := newPQCLabelEngine(t)
	root := mustRootCA(t, engine, "MLDSA Root", keystore.MLDSA65)
	int1 := mustIntermediateCA(t, engine, "MLDSA Int 1", keystore.MLDSA65, root.ID)
	int2 := mustIntermediateCA(t, engine, "MLDSA Int 2", keystore.MLDSA65, int1.ID)
	res := issuePQCLabelLeaf(t, provider, keys, int2.ID, "three-tier.example.com")
	if res.PQCReadiness != "quantum_safe" {
		t.Errorf("PQCReadiness = %q, want quantum_safe (every hop is ML-DSA)", res.PQCReadiness)
	}
}

func TestPQCLabel_OneClassicalHopInMultiTier(t *testing.T) {
	engine, keys, provider := newPQCLabelEngine(t)
	root := mustRootCA(t, engine, "MLDSA Root", keystore.MLDSA65)
	classical := mustIntermediateCA(t, engine, "ECDSA Int", keystore.ECDSAP256, root.ID)
	int2 := mustIntermediateCA(t, engine, "MLDSA Int 2", keystore.MLDSA65, classical.ID)
	res := issuePQCLabelLeaf(t, provider, keys, int2.ID, "one-classical-hop.example.com")
	if res.PQCReadiness != pqcReadinessLeafOnly {
		t.Errorf("PQCReadiness = %q, want %q (a classical hop mid-chain)", res.PQCReadiness, pqcReadinessLeafOnly)
	}
}

func TestPQCLabel_UnknownHopYieldsWeakerLabel(t *testing.T) {
	engine, keys, _ := newPQCLabelEngine(t)
	root := mustRootCA(t, engine, "MLDSA Root", keystore.MLDSA65)
	if _, err := keys.GenerateKey("unknown-hop-key", keystore.MLDSA65); err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	issued, err := engine.IssueCertificate(root.ID, ca.IssuanceRequest{PQCCSR: mustPQCCSR(t, keys, "unknown-hop-key", "unknown-hop.example.com")})
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	cert := issued.Certificate
	if resolveChainClassical(engine, root.ID, cert) {
		t.Fatal("baseline: full ML-DSA chain must not resolve as classical")
	}

	if !resolveChainClassical(engine, "does-not-exist", cert) {
		t.Error("unknown caID must resolve to the weaker (classical) label")
	}
	if resolveChainClassical(engine, "", cert) {
		t.Error("empty caID keeps single-hop behaviour (ML-DSA leaf is not classical)")
	}
	// A chain with a deleted parent cannot be built: engine.DeleteCA refuses
	// CAs that still have children (ErrCAHasChildren), so the unknown-caID
	// fixture above is the unknown-hop case.
}

func fetchBody(t *testing.T, mux http.Handler, path, token string) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}

func TestPQCLabel_SnapshotAcrossSurfaces(t *testing.T) {
	items := []CertificateItem{
		{FingerprintSHA256: "fp-qs", CommonName: "qs.example.com", PQCReadiness: "quantum_safe"},
		{FingerprintSHA256: "fp-lo", CommonName: "lo.example.com", PQCReadiness: "quantum_safe_leaf_only"},
		{FingerprintSHA256: "fp-mr", CommonName: "mr.example.com", PQCReadiness: "migration_ready"},
	}
	certs := &reportCertProvider{items: items}
	auth := newReportsTestAuth(t)
	const token = "reports-test-token"

	mux := http.NewServeMux()
	registerReportsHandlers(mux, auth, certs, &reportCAProvider{}, stubTemplateProvider{}, nil, stubAuditProvider{})
	RegisterCBOMHandlers(mux, auth, certs, nil, nil, stubAuditProvider{})

	type counts struct {
		QuantumSafe         int `json:"quantum_safe"`
		QuantumSafeLeafOnly int `json:"quantum_safe_leaf_only"`
		MigrationReady      int `json:"migration_ready"`
	}
	decodeCounts := func(raw []byte, nested bool) counts {
		t.Helper()
		var c counts
		if nested {
			var env struct {
				Data struct {
					PQC counts `json:"pqc_readiness"`
				} `json:"data"`
			}
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatalf("decode posture: %v", err)
			}
			return env.Data.PQC
		}
		var env struct {
			Data counts `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode migration: %v", err)
		}
		c = env.Data
		return c
	}

	got := map[string]counts{}
	var bodies [][]byte
	// "report API" and "mcp" are the same GET paths: the MCP tools are raw
	// hub.get proxies (internal/mcpserver cannot be imported here).
	for _, surface := range []string{"report_api", "mcp"} {
		posture := fetchBody(t, mux, "/api/v1/reports/crypto-posture", token)
		migration := fetchBody(t, mux, "/api/v1/reports/pqc-migration", token)
		bodies = append(bodies, posture, migration)
		got[surface+":crypto-posture"] = decodeCounts(posture, true)
		got[surface+":pqc-migration"] = decodeCounts(migration, false)
	}

	cbomRaw := fetchBody(t, mux, "/api/v1/cbom", token)
	bodies = append(bodies, cbomRaw)
	var doc cbomDocument
	if err := json.Unmarshal(cbomRaw, &doc); err != nil {
		t.Fatalf("decode cbom: %v", err)
	}
	var cb counts
	for _, comp := range doc.Components {
		for _, p := range comp.Properties {
			if p.Name != "kryptkeeper:pqc-readiness" {
				continue
			}
			switch p.Value {
			case "quantum_safe":
				cb.QuantumSafe++
			case "quantum_safe_leaf_only":
				cb.QuantumSafeLeafOnly++
			case "migration_ready":
				cb.MigrationReady++
			}
		}
	}
	got["cbom"] = cb

	want := counts{QuantumSafe: 1, QuantumSafeLeafOnly: 1, MigrationReady: 1}
	golden := map[string]counts{
		"report_api:crypto-posture": want,
		"report_api:pqc-migration":  want,
		"mcp:crypto-posture":        want,
		"mcp:pqc-migration":         want,
		"cbom":                      want,
	}
	if !reflect.DeepEqual(got, golden) {
		t.Errorf("label counts differ across surfaces:\n got  %+v\n want %+v", got, golden)
	}
	for i, b := range bodies {
		if strings.Contains(string(b), `"quantum_safe":2`) {
			t.Errorf("body %d reports quantum_safe:2 although one of the two is leaf-only", i)
		}
	}
}
