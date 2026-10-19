// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
)

// W23-04: offline-root flow. The hub generates the issuing CA key, hands back a
// CSR, parks the CA pending_certificate, and accepts the signed certificate
// only if it certifies THIS CA's key and chains to its claimed issuer.

type csrEnv struct {
	*importEnv
	rootID string
}

// newCSREnv imports the offline root (dual control off: the import flow has
// its own tests) and returns its CA id.
func newCSREnv(t *testing.T) *csrEnv {
	t.Helper()
	e := newImportEnv(t, "false")
	rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(e.rootPEM, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("import root: %d %s", rec.Code, rec.Body.String())
	}
	return &csrEnv{importEnv: e, rootID: e.caID(t, rec)}
}

type pendingCA struct {
	ID     string
	CSRPEM string
	Status string
}

func (e *csrEnv) requestCSR(t *testing.T, parentID, cn, algo string) (pendingCA, *httptest.ResponseRecorder) {
	t.Helper()
	rec := e.do(e.alice, http.MethodPost, "/api/v1/cas", map[string]any{
		"name": cn, "type": "intermediate", "algorithm": algo, "validity": "5y",
		"parent_ca_id": parentID, "subject_cn": cn,
	})
	var p struct {
		Data struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			CSRPEM string `json:"csr_pem"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return pendingCA{ID: p.Data.ID, CSRPEM: p.Data.CSRPEM, Status: p.Data.Status}, rec
}

func parseCSR(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("not a CSR PEM: %q", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR self-signature: %v", err)
	}
	return csr
}

type signOpts struct {
	isCA        bool
	pathLen     int
	pathLenZero bool
	notBefore   time.Time
	notAfter    time.Time
	issuer      *x509.Certificate
	issuerKey   crypto.Signer
	pub         crypto.PublicKey // overrides the CSR's key when set
}

// signAsOfflineRoot plays the offline root: signs the CSR's subject/key.
func (e *csrEnv) signAsOfflineRoot(t *testing.T, csr *x509.CertificateRequest, o signOpts) string {
	t.Helper()
	if o.issuer == nil {
		o.issuer, o.issuerKey = e.rootTemplate, e.rootKey
	}
	if o.pub == nil {
		o.pub = csr.PublicKey
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Minute)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(5 * 365 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()), Subject: csr.Subject,
		NotBefore: o.notBefore, NotAfter: o.notAfter,
		IsCA: o.isCA, BasicConstraintsValid: true, MaxPathLen: o.pathLen, MaxPathLenZero: o.pathLenZero,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.issuer, o.pub, o.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (e *csrEnv) complete(id, certPEM string) *httptest.ResponseRecorder {
	return e.do(e.alice, http.MethodPost, "/api/v1/cas/"+id+"/certificate", map[string]any{"certificate_pem": certPEM})
}

func (e *csrEnv) status(t *testing.T, id string) string {
	t.Helper()
	got, err := e.engine.GetCA(id)
	if err != nil {
		t.Fatal(err)
	}
	return got.Status
}

// pending requests a CSR and returns it with its parsed form.
func (e *csrEnv) pending(t *testing.T, cn string) (pendingCA, *x509.CertificateRequest) {
	t.Helper()
	p, rec := e.requestCSR(t, e.rootID, cn, "ECDSA-P256")
	if rec.Code != http.StatusCreated || p.Status != "pending_certificate" || p.CSRPEM == "" {
		t.Fatalf("request CSR: %d %s", rec.Code, rec.Body.String())
	}
	return p, parseCSR(t, p.CSRPEM)
}

func TestCSRFlowHappyPath(t *testing.T) {
	for _, algo := range []string{"ECDSA-P256", "Ed25519"} {
		t.Run(algo, func(t *testing.T) {
			e := newCSREnv(t)
			p, rec := e.requestCSR(t, e.rootID, "Issuing "+algo, algo)
			if rec.Code != http.StatusCreated || p.Status != "pending_certificate" {
				t.Fatalf("request CSR: %d %s", rec.Code, rec.Body.String())
			}
			csr := parseCSR(t, p.CSRPEM)
			if csr.Subject.CommonName != "Issuing "+algo {
				t.Fatalf("CSR CN = %q", csr.Subject.CommonName)
			}
			pendingCA, err := e.engine.GetCA(p.ID)
			if err != nil || pendingCA.KeyID == "" {
				t.Fatalf("pending CA = %+v err=%v", pendingCA, err)
			}
			if _, err := e.keys.Metadata(pendingCA.KeyID); err != nil {
				t.Fatalf("CA key must be in the keystore: %v", err)
			}
			if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
				t.Fatal("response must never carry key material")
			}
			if rec := e.do(e.alice, http.MethodGet, "/api/v1/cas/"+p.ID+"/csr", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE REQUEST") {
				t.Fatalf("GET csr: %d %s", rec.Code, rec.Body.String())
			}

			signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLenZero: true})
			if rec := e.complete(p.ID, signed); rec.Code != http.StatusOK {
				t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
			}
			if got := e.status(t, p.ID); got != "active" {
				t.Fatalf("status = %s, want active", got)
			}
			if rec := e.do(e.alice, http.MethodGet, "/api/v1/cas/"+p.ID+"/csr", nil); rec.Code != http.StatusConflict {
				t.Fatalf("GET csr after completion: want 409, got %d", rec.Code)
			}

			// First leaf issues from the completed CA and chains to the offline root.
			leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			leafCSRDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.com"}}, leafKey)
			leafCSR, _ := x509.ParseCertificateRequest(leafCSRDER)
			issued, err := e.engine.IssueCertificate(p.ID, ca.IssuanceRequest{
				CSR: leafCSR, Validity: 24 * time.Hour, KeyUsage: x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"leaf.example.com"},
			})
			if err != nil {
				t.Fatalf("issue first leaf: %v", err)
			}
			roots, inters := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(e.rootTemplate)
			ca2, _ := e.engine.GetCA(p.ID)
			inters.AddCert(ca2.Certificate)
			if _, err := issued.Certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "leaf.example.com"}); err != nil {
				t.Fatalf("leaf must chain to the offline root: %v", err)
			}
			for _, a := range []string{"ca.csr_generate", "ca.certificate_complete"} {
				if !e.audited(a, AuditOutcomeSuccess) {
					t.Errorf("%s not audited", a)
				}
			}
		})
	}
}

func TestCompleteRejectsMismatchedKey(t *testing.T) {
	e := newCSREnv(t)
	p, csr := e.pending(t, "Issuing")
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLenZero: true, pub: &otherKey.PublicKey})
	rec := e.complete(p.ID, signed)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "does not match the CA key") {
		t.Fatalf("want 400 key mismatch, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := e.status(t, p.ID); got != "pending_certificate" {
		t.Fatalf("a rejected certificate must leave the CA pending, status = %s", got)
	}
	if !e.audited("ca.certificate_complete", AuditOutcomeDenied) {
		t.Fatal("a rejected completion must be audited")
	}
}

func TestCompleteRejectsCertFromAnotherPendingCA(t *testing.T) {
	e := newCSREnv(t)
	a, _ := e.pending(t, "Issuing A")
	b, csrB := e.pending(t, "Issuing B")
	signedForB := e.signAsOfflineRoot(t, csrB, signOpts{isCA: true, pathLenZero: true})
	rec := e.complete(a.ID, signedForB)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("B's certificate posted to A: want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if e.status(t, a.ID) != "pending_certificate" || e.status(t, b.ID) != "pending_certificate" {
		t.Fatal("neither CA may change state")
	}
}

func TestCompleteRejectsExpiredCert(t *testing.T) {
	e := newCSREnv(t)
	p, csr := e.pending(t, "Issuing")
	signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLenZero: true,
		notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)})
	if rec := e.complete(p.ID, signed); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("want 400 expired, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCompleteRejectsWrongPathlen(t *testing.T) {
	t.Run("child exceeds parent limit", func(t *testing.T) {
		e := newCSREnv(t) // offline root allows pathlen 1: child may be at most 0
		p, csr := e.pending(t, "Issuing")
		signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLen: 1})
		if rec := e.complete(p.ID, signed); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "pathlen") {
			t.Fatalf("want 400 pathlen, got %d: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("child without pathlen under a limited parent", func(t *testing.T) {
		e := newCSREnv(t)
		p, csr := e.pending(t, "Issuing")
		signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLen: -1})
		if rec := e.complete(p.ID, signed); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "pathlen") {
			t.Fatalf("want 400 pathlen, got %d: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("parent pathlen zero permits no subordinate CA", func(t *testing.T) {
		e := newCSREnv(t)
		zeroTmpl, zeroKey, zeroPEM := testRoot(t, "Zero Root", 0, true)
		rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/import", e.importBody(zeroPEM, nil))
		if rec.Code != http.StatusCreated {
			t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
		}
		zeroID := e.caID(t, rec)
		p, crec := e.requestCSR(t, zeroID, "Issuing", "ECDSA-P256")
		if crec.Code != http.StatusCreated {
			t.Fatalf("request CSR: %d %s", crec.Code, crec.Body.String())
		}
		signed := e.signAsOfflineRoot(t, parseCSR(t, p.CSRPEM), signOpts{isCA: true, pathLenZero: true, issuer: zeroTmpl, issuerKey: zeroKey})
		if rec := e.complete(p.ID, signed); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "pathlen") {
			t.Fatalf("want 400 pathlen, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCompleteRejectsNotSignedByParent(t *testing.T) {
	e := newCSREnv(t)
	p, csr := e.pending(t, "Issuing")
	// An impostor with the parent's exact subject but a different key.
	impTmpl, impKey, _ := testRoot(t, "Offline Root", 1, false)
	signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLenZero: true, issuer: impTmpl, issuerKey: impKey})
	if rec := e.complete(p.ID, signed); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not signed by the parent CA") {
		t.Fatalf("want 400 not signed by parent, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCompleteRejectsNonCA(t *testing.T) {
	e := newCSREnv(t)
	p, csr := e.pending(t, "Issuing")
	signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: false})
	if rec := e.complete(p.ID, signed); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not a CA certificate") {
		t.Fatalf("want 400 not a CA, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCompleteRejectsOutlivingParent(t *testing.T) {
	e := newCSREnv(t)
	p, csr := e.pending(t, "Issuing")
	signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLenZero: true, notAfter: e.rootTemplate.NotAfter.Add(24 * time.Hour)})
	if rec := e.complete(p.ID, signed); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "outlives") {
		t.Fatalf("want 400 outlives parent, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCompleteRejectsGarbage(t *testing.T) {
	e := newCSREnv(t)
	p, _ := e.pending(t, "Issuing")
	if rec := e.complete(p.ID, "not a pem"); rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage: want 400, got %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/cas/"+p.ID+"/certificate", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty: want 400, got %d", rec.Code)
	}
}

func TestCompleteTwiceConflicts(t *testing.T) {
	e := newCSREnv(t)
	p, csr := e.pending(t, "Issuing")
	signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLenZero: true})
	if rec := e.complete(p.ID, signed); rec.Code != http.StatusOK {
		t.Fatalf("first completion: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.complete(p.ID, signed); rec.Code != http.StatusConflict {
		t.Fatalf("second completion: want 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := e.complete("nope", signed); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown CA: want 404, got %d", rec.Code)
	}
}

func TestPendingCAIssuanceRefused(t *testing.T) {
	e := newCSREnv(t)
	p, _ := e.pending(t, "Issuing")
	if _, err := e.engine.IssueCertificate(p.ID, ca.IssuanceRequest{}); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("issuing from a pending CA: err = %v, want ErrCANotActive", err)
	}
}

func TestCSRFlowRefusesPQCAndNonAdmin(t *testing.T) {
	e := newCSREnv(t)
	if _, rec := e.requestCSR(t, e.rootID, "PQC", "ML-DSA-65"); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "classical") {
		t.Fatalf("ML-DSA CSR: want 422 classical-only, got %d: %s", rec.Code, rec.Body.String())
	}
	p, csr := e.pending(t, "Issuing")
	_, viewer, err := e.auth.CreateAPIKeyAs("", "viewer-key", "viewer", "pki-viewer", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(viewer, http.MethodGet, "/api/v1/cas/"+p.ID+"/csr", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET csr: want 403, got %d", rec.Code)
	}
	signed := e.signAsOfflineRoot(t, csr, signOpts{isCA: true, pathLenZero: true})
	raw, _ := json.Marshal(map[string]any{"certificate_pem": signed})
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(viewer, http.MethodPost, "/api/v1/cas/"+p.ID+"/certificate", raw))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST certificate: want 403, got %d", rec.Code)
	}
	if e.status(t, p.ID) != "pending_certificate" {
		t.Fatal("a forbidden completion must not activate the CA")
	}
}

func TestDBStoreRoundTripsCSR(t *testing.T) {
	db := newBackendDB(t)
	store := ca.NewDBStore(db, false)
	c := &ca.CA{ID: "pend-1", Name: "n", Type: "intermediate", Status: ca.CAStatusPendingCertificate,
		KeyID: "key-pend-1", KeyStorageType: "software", CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n")}
	// An intermediate needs a parent row (FK + ca_issuing_has_parent).
	if err := store.Save(&ca.CA{ID: "root-1", Name: "root", Type: "root", Status: "active", KeyStorageType: "external"}); err != nil {
		t.Fatal(err)
	}
	c.ParentCAID = "root-1"
	if err := store.Save(c); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load("pend-1")
	if err != nil || string(got.CSRPEM) != string(c.CSRPEM) || got.Status != ca.CAStatusPendingCertificate {
		t.Fatalf("Load = %+v err=%v, want CSR round-trip", got, err)
	}
	list, err := store.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %d err=%v", len(list), err)
	}
	c.CSRPEM, c.Status = nil, "active"
	if err := store.Save(c); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Load("pend-1"); len(got.CSRPEM) != 0 || got.Status != "active" {
		t.Fatalf("completion must clear csr_pem, got %+v", got)
	}
}
