// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func TestParseAlgorithmAcceptsMLDSASpellings(t *testing.T) {
	cases := map[string]keystore.Algorithm{
		"ML-DSA-44":  keystore.MLDSA44,
		"ML-DSA-65":  keystore.MLDSA65,
		"ml-dsa-65":  keystore.MLDSA65,
		"mldsa65":    keystore.MLDSA65,
		"MLDSA87":    keystore.MLDSA87,
		"ml_dsa_87":  keystore.MLDSA87,
		"ECDSA-P256": keystore.ECDSAP256,
		"rsa-4096":   keystore.RSA4096,
	}
	for in, want := range cases {
		got, err := parseAlgorithm(in)
		if err != nil || got != want {
			t.Errorf("parseAlgorithm(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestParseAlgorithmRejectionNamesSupportedSet(t *testing.T) {
	_, err := parseAlgorithm("ML-DSA-99")
	if err == nil || !strings.Contains(err.Error(), "ML-DSA-65") {
		t.Fatalf("want an error listing the supported algorithms, got %v", err)
	}
}

// ML-DSA CAs are supported by the engine on the software key backend; the API
// used to reject every spelling because parseAlgorithm lacked the cases.
func TestCreateCAMLDSARootAndIntermediate(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-ca-passphrase-32chars-min!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	provider := NewEngineCAProvider(ca.NewEngine(keys, ca.NewMemStore()))

	root, err := provider.CreateCA(context.Background(), CACreateRequest{
		Name: "pqc-root", Type: "root", Algorithm: "ML-DSA-65", SubjectCN: "PQC Root",
	})
	if err != nil {
		t.Fatalf("create ML-DSA-65 root: %v", err)
	}
	if root.ID == "" {
		t.Fatal("root has no id")
	}
	if _, err := provider.CreateCA(context.Background(), CACreateRequest{
		Name: "pqc-int", Type: "intermediate", Algorithm: "mldsa65", SubjectCN: "PQC Intermediate", ParentCAID: root.ID,
	}); err != nil {
		t.Fatalf("create ML-DSA-65 intermediate: %v", err)
	}
}

func newSoftwareEngine(t *testing.T) *ca.Engine {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-ca-passphrase-32chars-min!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	return ca.NewEngine(keys, ca.NewMemStore())
}

func TestParseAlgorithmAcceptsEd25519Spellings(t *testing.T) {
	for _, in := range []string{"Ed25519", "ed25519", "ED-25519"} {
		got, err := parseAlgorithm(in)
		if err != nil || got != keystore.Ed25519 {
			t.Errorf("parseAlgorithm(%q) = %q, %v; want Ed25519", in, got, err)
		}
	}
}

func TestParseAlgorithmRejectionNamesEverySupportedAlgorithm(t *testing.T) {
	_, err := parseAlgorithm("DSA")
	if err == nil || !errors.Is(err, errUnsupportedCAAlgorithm) {
		t.Fatalf("want errUnsupportedCAAlgorithm, got %v", err)
	}
	for _, a := range caSupportedAlgorithms {
		if !strings.Contains(err.Error(), a) {
			t.Errorf("error %q does not name %q", err, a)
		}
	}
}

func writePEM(t *testing.T, path string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// verifyHierarchy builds root -> intermediate -> ECDSA-P256 leaf for algo and
// checks the chain with x509.Verify and, when available, openssl verify.
func verifyHierarchy(t *testing.T, algo keystore.Algorithm) (*ca.CA, *ca.CA) {
	t.Helper()
	engine := newSoftwareEngine(t)
	root, err := engine.CreateRootCA("root", pkix.Name{CommonName: "Root"}, algo, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	inter, err := engine.CreateIntermediateCA("issuing", pkix.Name{CommonName: "Issuing"}, algo, root.ID, 2*365*24*time.Hour)
	if err != nil {
		t.Fatalf("intermediate: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.com"}, DNSNames: []string{"leaf.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := engine.IssueCertificate(inter.ID, ca.IssuanceRequest{CSR: csr, Validity: 24 * time.Hour, KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{"leaf.example.com"}})
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}

	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.Certificate)
	inters.AddCert(inter.Certificate)
	if _, err := leaf.Certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "leaf.example.com"}); err != nil {
		t.Fatalf("x509.Verify: %v", err)
	}

	if bin, lerr := exec.LookPath("openssl"); lerr == nil {
		dir := t.TempDir()
		writePEM(t, filepath.Join(dir, "root.pem"), root.Certificate.Raw)
		writePEM(t, filepath.Join(dir, "issuing.pem"), inter.Certificate.Raw)
		writePEM(t, filepath.Join(dir, "leaf.pem"), leaf.Certificate.Raw)
		out, verr := exec.Command(bin, "verify", "-CAfile", filepath.Join(dir, "root.pem"),
			"-untrusted", filepath.Join(dir, "issuing.pem"), filepath.Join(dir, "leaf.pem")).CombinedOutput()
		if verr != nil || !strings.Contains(string(out), "OK") {
			t.Fatalf("openssl verify: %v: %s", verr, out)
		}
	} else {
		t.Log("openssl not found; skipped openssl verify")
	}
	return root, inter
}

func TestCreateCAEd25519HierarchyVerifies(t *testing.T) {
	root, inter := verifyHierarchy(t, keystore.Ed25519)
	if root.Certificate.PublicKeyAlgorithm != x509.Ed25519 || inter.Certificate.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("CA keys are not Ed25519: %v / %v", root.Certificate.PublicKeyAlgorithm, inter.Certificate.PublicKeyAlgorithm)
	}
}

func TestCreateCAHandlerUnsupportedAlgorithmReturns400(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, NewEngineCAProvider(newSoftwareEngine(t)), NewTenantStoreFromEnv(), stubAuditProviderForCA{})

	for _, alg := range []string{"DSA", "nonsense"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cas", strings.NewReader(`{"type":"root","algorithm":"`+alg+`","subject_cn":"x"}`))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d body %s", alg, rec.Code, rec.Body)
		}
		var body struct {
			Message   string   `json:"message"`
			Supported []string `json:"supported_algorithms"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Supported) != len(caSupportedAlgorithms) {
			t.Errorf("%s: supported_algorithms = %v", alg, body.Supported)
		}
		for _, a := range caSupportedAlgorithms {
			if !strings.Contains(body.Message, a) {
				t.Errorf("%s: message %q does not name %q", alg, body.Message, a)
			}
		}
	}
}

func TestCreateCAEd25519RefusedOnPKCS11Label(t *testing.T) {
	for _, backend := range []string{"pkcs11", "cloudkms"} {
		engine := newSoftwareEngine(t)
		engine.SetKeyBackend(backend)
		_, err := engine.CreateRootCA("r", pkix.Name{CommonName: "R"}, keystore.Ed25519, time.Hour)
		if !errors.Is(err, ca.ErrAlgorithmUnsupportedByBackend) {
			t.Errorf("%s: want ErrAlgorithmUnsupportedByBackend, got %v", backend, err)
		}
	}
	engine := newSoftwareEngine(t)
	engine.SetKeyBackend("vault")
	if _, err := engine.CreateRootCA("r", pkix.Name{CommonName: "R"}, keystore.Ed25519, time.Hour); err != nil {
		t.Fatalf("vault label should pass: %v", err)
	}
}

func TestCreateCAEd25519ResponseCarriesWarning(t *testing.T) {
	provider := NewEngineCAProvider(newSoftwareEngine(t))
	ed, err := provider.CreateCA(context.Background(), CACreateRequest{Name: "ed", Type: "root", Algorithm: "Ed25519", SubjectCN: "Ed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ed.Warnings) != 1 || ed.Warnings[0] != ed25519ListWarning {
		t.Errorf("warnings = %v", ed.Warnings)
	}
	ec, err := provider.CreateCA(context.Background(), CACreateRequest{Name: "ec", Type: "root", Algorithm: "ECDSA-P256", SubjectCN: "Ec"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ec.Warnings) != 0 {
		t.Errorf("unexpected warnings on ECDSA CA: %v", ec.Warnings)
	}
}
