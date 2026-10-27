// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/crl"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/ocsp"
)

// lintCorpusEnv names the directory TestProfileLintCorpus writes to. Unset,
// the test still issues every profile into a temp dir (so the corpus cannot
// rot unnoticed) but nothing is kept; scripts/lint/profile-lint.sh sets it and
// runs pkilint and zlint over the result (gap T6).
const lintCorpusEnv = "KK_LINT_CORPUS_DIR"

type lintArtifact struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`    // cert | crl | ocsp
	Profile string `json:"profile"` // tls-server | tls-client | code-signing | smime | ca | ocsp-signing | timestamping | crl | ocsp
	PQC     bool   `json:"pqc,omitempty"`
	File    string `json:"file"` // PEM for cert/crl, DER for ocsp
}

type lintCorpus struct {
	t         *testing.T
	dir       string
	artifacts []lintArtifact
}

func (c *lintCorpus) add(name, kind, profile string, pqc bool, data []byte) {
	c.t.Helper()
	ext := ".pem"
	if kind == "ocsp" {
		ext = ".der"
	}
	file := name + ext
	if err := os.WriteFile(filepath.Join(c.dir, file), data, 0o600); err != nil {
		c.t.Fatal(err)
	}
	c.artifacts = append(c.artifacts, lintArtifact{Name: name, Kind: kind, Profile: profile, PQC: pqc, File: file})
}

// TestProfileLintCorpus issues one certificate per profile the hub can
// produce -- through the same provider -> template -> engine path the REST API
// uses -- plus CA certificates, CRLs and OCSP responses, and writes them where
// the external linters can read them.
func TestProfileLintCorpus(t *testing.T) {
	dir := os.Getenv(lintCorpusEnv)
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	c := &lintCorpus{t: t, dir: dir}
	ctx := context.Background()

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("lint-corpus-passphrase-32-bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	// What cmd/kryptkeeper/main.go installs when a revocation base URL is set.
	engine.SetRevocationPointers(func(caID string) ([]string, []string) {
		return []string{"http://pki.example.com/crl/" + caID + ".crl"}, []string{"http://pki.example.com/ocsp"}
	})

	const tenYears = 10 * 365 * 24 * time.Hour
	subj := func(cn string) pkix.Name {
		return pkix.Name{CommonName: cn, Organization: []string{"Kryptkeeper Lint Corpus"}, Country: []string{"US"}}
	}
	mustCA := func(got *ca.CA, err error) *ca.CA {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	rootEC := mustCA(engine.CreateRootCA("root-ecdsa", subj("Lint Root ECDSA P-384"), keystore.ECDSAP384, tenYears))
	rootRSA := mustCA(engine.CreateRootCA("root-rsa", subj("Lint Root RSA 4096"), keystore.RSA4096, tenYears))
	rootPQ := mustCA(engine.CreateRootCA("root-mldsa", subj("Lint Root ML-DSA-65"), keystore.MLDSA65, tenYears))
	interEC := mustCA(engine.CreateIntermediateCA("inter-ecdsa", subj("Lint Intermediate ECDSA P-256"), keystore.ECDSAP256, rootEC.ID, 5*365*24*time.Hour))
	interRSA := mustCA(engine.CreateIntermediateCA("inter-rsa", subj("Lint Intermediate RSA 3072"), keystore.RSA3072, rootRSA.ID, 5*365*24*time.Hour))
	interPQ := mustCA(engine.CreateIntermediateCA("inter-mldsa", subj("Lint Intermediate ML-DSA-65"), keystore.MLDSA65, rootPQ.ID, 5*365*24*time.Hour))
	type namedCA struct {
		name string
		ca   *ca.CA
		pqc  bool
	}
	for _, e := range []namedCA{
		{"root-ecdsa-p384", rootEC, false}, {"root-rsa-4096", rootRSA, false}, {"root-mldsa65", rootPQ, true},
		{"intermediate-ecdsa-p256", interEC, false}, {"intermediate-rsa-3072", interRSA, false}, {"intermediate-mldsa65", interPQ, true},
	} {
		c.add(e.name, "cert", "ca", e.pqc, e.ca.CertPEM)
	}

	templates := map[string]TemplateItem{}
	for id, eku := range map[string][]string{
		"tls-server":   {"serverAuth"},
		"tls-client":   {"clientAuth"},
		"tls-both":     {"serverAuth", "clientAuth"},
		"code-signing": {"codeSigning"},
		"smime":        {"emailProtection"},
		"ocsp-signing": {"ocspSigning"},
		"timestamping": {"timeStamping"},
	} {
		templates[id] = TemplateItem{ID: id, Active: true, ExtendedKeyUsage: eku, ValidityPeriod: "P90D"}
	}
	templates["tls-short-lived"] = TemplateItem{ID: "tls-short-lived", Active: true, ExtendedKeyUsage: []string{"serverAuth"}, ValidityPeriod: "P7D", ShortLived: true}
	provider := WithTemplateProvider(NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false),
		&fakeTemplateProvider{templates: templates}).(*caCertificateProvider)

	csr := func(key crypto.Signer, cn string, dns ...string) string {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}, key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	}
	issue := func(name, profile, caID, tpl, csrPEM string, pqc bool) *x509.Certificate {
		t.Helper()
		ictx := ctx
		if profile == "code-signing" {
			// Code signing is approval-gated; the approver's re-entry is what mints the cert.
			ictx = context.WithValue(ctx, approvalBypassKey{}, true)
		}
		res, err := provider.IssueCertificate(ictx, CertificateIssueRequest{CAID: caID, TemplateID: tpl, CSRPEM: csrPEM})
		if err != nil {
			t.Fatalf("issue %s: %v", name, err)
		}
		dl, err := provider.DownloadCertificate(ctx, res.FingerprintSHA256, "pem", false)
		if err != nil {
			t.Fatalf("download %s: %v", name, err)
		}
		c.add(name, "cert", profile, pqc, dl.Body)
		blk, _ := pem.Decode(dl.Body)
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return cert
	}

	ecKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	issue("tls-server-ecdsa", "tls-server", interEC.ID, "tls-server", csr(ecKey(), "www.example.com", "www.example.com", "example.com"), false)
	issue("tls-server-rsa", "tls-server", interRSA.ID, "tls-server", csr(rsaKey, "www.example.com", "www.example.com"), false)
	issue("tls-server-short-lived", "tls-server", interEC.ID, "tls-short-lived", csr(ecKey(), "short.example.com", "short.example.com"), false)
	issue("tls-client-ecdsa", "tls-client", interEC.ID, "tls-client", csr(ecKey(), "client-01"), false)
	issue("tls-server-client-ecdsa", "tls-server", interEC.ID, "tls-both", csr(ecKey(), "svc.example.com", "svc.example.com"), false)
	issue("code-signing-ecdsa", "code-signing", interEC.ID, "code-signing", csr(ecKey(), "Kryptkeeper Lint Signing"), false)
	issue("code-signing-rsa", "code-signing", interRSA.ID, "code-signing", csr(rsaKey, "Kryptkeeper Lint Signing"), false)
	issue("smime-ecdsa", "smime", interEC.ID, "smime", csr(ecKey(), "Alice Example"), false)
	issue("ocsp-signing-ecdsa", "ocsp-signing", interEC.ID, "ocsp-signing", csr(ecKey(), "Lint OCSP Responder"), false)
	issue("timestamping-ecdsa", "timestamping", interEC.ID, "timestamping", csr(ecKey(), "Lint TSA"), false)

	// ML-DSA leaves, under an ML-DSA CA and under a classical CA (mixed chain).
	pqKey := func(id string) crypto.Signer {
		if _, err := keys.GenerateKey(id, keystore.MLDSA65); err != nil {
			t.Fatal(err)
		}
		s, err := keys.Signer(id)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	pqCSR := func(signer crypto.Signer, cn string, dns ...string) string {
		der, err := ca.CreateCertificateRequestMLDSA(pkix.Name{CommonName: cn}, dns, nil, signer, keystore.MLDSA65)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	}
	issue("tls-server-mldsa65-under-mldsa", "tls-server", interPQ.ID, "tls-server", pqCSR(pqKey("lint-pq-1"), "pq.example.com", "pq.example.com"), true)
	issue("tls-server-mldsa65-under-ecdsa", "tls-server", interEC.ID, "tls-server", pqCSR(pqKey("lint-pq-2"), "pq2.example.com", "pq2.example.com"), true)

	// CRLs for the intermediates, each with a revoked entry.
	caLookup := func(id string) (*x509.Certificate, crypto.Signer, error) {
		got, err := engine.GetCA(id)
		if err != nil {
			return nil, nil, err
		}
		s, err := keys.Signer(got.KeyID)
		return got.Certificate, s, err
	}
	gen := crl.NewGenerator(func(string) ([]crl.RevokedCert, error) {
		return []crl.RevokedCert{{SerialNumber: big.NewInt(4242), RevokedAt: time.Now().Add(-time.Hour), ReasonCode: 1}}, nil
	}, caLookup, 24*time.Hour)
	for _, e := range []namedCA{{"crl-intermediate-ecdsa", interEC, false}, {"crl-intermediate-rsa", interRSA, false}, {"crl-intermediate-mldsa65", interPQ, true}} {
		g, err := gen.Generate(e.ca.ID)
		if err != nil {
			t.Fatalf("%s: %v", e.name, err)
		}
		c.add(e.name, "crl", "crl", e.pqc, g.PEM)
	}

	// OCSP responses are signed by the issuing CA itself; the hub issues no
	// delegated responder certificate.
	leaf := issue("ocsp-subject-ecdsa", "tls-server", interEC.ID, "tls-server", csr(ecKey(), "ocsp.example.com", "ocsp.example.com"), false)
	for _, revoked := range []bool{false, true} {
		resp := ocsp.NewResponder(func(*big.Int, *x509.Certificate) (bool, time.Time, int, error) {
			return revoked, time.Now().Add(-time.Hour), 1, nil
		}, func([]byte) (*x509.Certificate, crypto.Signer, error) { return caLookup(interEC.ID) }, time.Hour, 10)
		reqDER, err := goocsp.CreateRequest(leaf, interEC.Certificate, nil)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		hr := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqDER))
		hr.Header.Set("Content-Type", "application/ocsp-request")
		resp.Handler().ServeHTTP(rec, hr)
		body, _ := io.ReadAll(rec.Result().Body)
		if rec.Code != http.StatusOK {
			t.Fatalf("ocsp responder: %d %s", rec.Code, body)
		}
		name := "ocsp-good"
		if revoked {
			name = "ocsp-revoked"
		}
		c.add(name, "ocsp", "ocsp", false, body)
	}

	manifest, _ := json.MarshalIndent(c.artifacts, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if len(c.artifacts) < 20 {
		t.Fatalf("corpus has %d artifacts, expected at least 20", len(c.artifacts))
	}
}
