// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/smallstep/pkcs7"

	"kryptkeeper/internal/intune"
)

type fakeBackend struct {
	mu          sync.Mutex
	validateErr error
	successErr  error
	validated   []string // transaction ids
	successes   []*x509.Certificate
	failures    []string
	conns       []intune.Connection
}

func (b *fakeBackend) Validate(_ context.Context, c intune.Connection, tx string, _ []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.validated = append(b.validated, tx)
	b.conns = append(b.conns, c)
	return b.validateErr
}

func (b *fakeBackend) NotifySuccess(_ context.Context, _ intune.Connection, _ string, _ []byte, cert *x509.Certificate) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.successes = append(b.successes, cert)
	return b.successErr
}

func (b *fakeBackend) NotifyFailure(_ context.Context, _ intune.Connection, _ string, _ []byte, _ int32, d string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = append(b.failures, d)
	return nil
}

type labelRig struct {
	*scepFixture
	backend   *fakeBackend
	withdrawn []*x509.Certificate
	gateErr   error
}

func newLabelRig(t *testing.T) *labelRig {
	t.Helper()
	r := &labelRig{scepFixture: newSCEPFixture(t), backend: &fakeBackend{}}
	t.Cleanup(r.Close)
	store := NewMemLabelStore()
	if _, err := store.Create(context.Background(), Label{Label: "corp", Mode: ModeIntune, TemplateID: "tpl", IntuneTenantID: "t.example.com",
		IntuneClientID: "client-1", CredentialRef: "cred-1", IssuingAuthority: "Test CA"}); err != nil {
		t.Fatal(err)
	}
	r.srv.WithLabels(store, r.backend, func(string) EnrollmentGate {
		return func(context.Context, string) error { return r.gateErr }
	}).WithWithdrawer(func(_ context.Context, c *x509.Certificate) error {
		r.withdrawn = append(r.withdrawn, c)
		return nil
	})
	return r
}

func intuneCSR(t *testing.T, key *rsa.PrivateKey, tpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// post sends csrDER for label and returns the CertRep and, on success, the
// issued certificate.
func (r *labelRig) post(t *testing.T, label string, csrDER []byte) (certRepResult, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cc := selfSignedRSACert(t, key, "throwaway")
	// The CSR must be for the key that signs the envelope in a real client,
	// but the server never relates them; re-signing the CSR is not needed.
	msg, _, _ := buildPKIOperation(t, r.caObj.Certificate, key, cc, csrDER)
	resp, err := http.Post(r.ts.URL+"/scep/"+label+"?operation=PKIOperation", "application/x-pki-message", strings.NewReader(string(msg)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	rep := parseCertRep(t, body)
	if rep.pkiStatus != pkiStatusSuccess {
		return rep, nil
	}
	env, err := pkcs7.Parse(rep.p7.Content)
	if err != nil {
		t.Fatal(err)
	}
	deg, err := env.Decrypt(cc, key)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pkcs7.Parse(deg)
	if err != nil || len(certs.Certificates) != 1 {
		t.Fatalf("certs-only: %v", err)
	}
	return rep, certs.Certificates[0]
}

func (r *labelRig) lastDetail() string {
	if len(r.audited) == 0 {
		return ""
	}
	return r.audited[len(r.audited)-1].Detail
}

func csrFor(t *testing.T, cn string, dns ...string) []byte {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return intuneCSR(t, k, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns})
}

func TestIntuneLabelIssuesCSRNamesAfterValidation(t *testing.T) {
	r := newLabelRig(t)
	rep, cert := r.post(t, "corp", csrFor(t, "laptop-1", "laptop-1.corp.example"))
	if rep.pkiStatus != pkiStatusSuccess || cert == nil {
		t.Fatalf("status %q: %v", rep.pkiStatus, r.audited)
	}
	if cert.Subject.CommonName != "laptop-1" || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "laptop-1.corp.example" {
		t.Fatalf("names %q %v", cert.Subject.CommonName, cert.DNSNames)
	}
	if len(r.backend.validated) != 1 || rep.transactionID != r.backend.validated[0] {
		t.Fatalf("validated %v tx %q", r.backend.validated, rep.transactionID)
	}
	c := r.backend.conns[0]
	if c.TenantID != "t.example.com" || c.ClientID != "client-1" || c.CredentialRef != "cred-1" || c.IssuingAuthority != "Test CA" {
		t.Fatalf("connection %+v", c)
	}
	if len(r.backend.successes) != 1 || r.backend.successes[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("success notification must carry the issued certificate")
	}
	if len(r.backend.failures) != 0 {
		t.Fatal("no failure notification on success")
	}
	if got := r.audited[len(r.audited)-1]; got.Outcome != "success" || !strings.Contains(got.Detail, "label=corp") {
		t.Fatalf("audit %+v", got)
	}
}

func TestIntuneRefusalIssuesNothingAndDoesNotNotifyFailure(t *testing.T) {
	r := newLabelRig(t)
	r.backend.validateErr = &intune.ServiceError{Code: "SubjectNameMismatch", Description: "no"}
	rep, cert := r.post(t, "corp", csrFor(t, "evil", "evil.example"))
	if rep.pkiStatus != pkiStatusFailure || cert != nil {
		t.Fatalf("status %q", rep.pkiStatus)
	}
	if len(r.backend.successes)+len(r.backend.failures) != 0 {
		t.Fatal("a refusal sends no notification (ref-scep-api reserves failureNotification for post-validation errors)")
	}
	if d := r.lastDetail(); !strings.Contains(d, "SubjectNameMismatch") || r.audited[0].Outcome != "denied" {
		t.Fatalf("audit %v", r.audited)
	}
}

func TestIntuneOutageFailsClosed(t *testing.T) {
	r := newLabelRig(t)
	r.backend.validateErr = &intune.UnavailableError{Stage: "token", Detail: "down"}
	rep, cert := r.post(t, "corp", csrFor(t, "a", "a.example"))
	if rep.pkiStatus != pkiStatusFailure || cert != nil || !strings.Contains(r.lastDetail(), "unavailable") {
		t.Fatalf("status %q audit %v", rep.pkiStatus, r.audited)
	}
}

func TestIntuneWithholdsAndRevokesWhenSuccessNotificationFails(t *testing.T) {
	r := newLabelRig(t)
	r.backend.successErr = &intune.UnavailableError{Stage: "success_notification", Detail: "down"}
	rep, cert := r.post(t, "corp", csrFor(t, "a", "a.example"))
	if rep.pkiStatus != pkiStatusFailure || cert != nil {
		t.Fatalf("status %q: the certificate must not reach the device", rep.pkiStatus)
	}
	if len(r.withdrawn) != 1 || !strings.Contains(r.lastDetail(), "revoked") {
		t.Fatalf("withdrawn %d audit %v", len(r.withdrawn), r.lastDetail())
	}
}

func TestIntuneGateDenialNeverReachesIntune(t *testing.T) {
	r := newLabelRig(t)
	r.gateErr = errors.New("denied")
	rep, _ := r.post(t, "corp", csrFor(t, "a", "a.example"))
	if rep.pkiStatus != pkiStatusFailure || len(r.backend.validated) != 0 {
		t.Fatalf("status %q validated %v", rep.pkiStatus, r.backend.validated)
	}
}

func TestIntuneRefusesSANTypesTheEngineCannotCarry(t *testing.T) {
	r := newLabelRig(t)
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := intuneCSR(t, k, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "u"}, EmailAddresses: []string{"u@example.com"}})
	rep, _ := r.post(t, "corp", der)
	if rep.pkiStatus != pkiStatusFailure || len(r.backend.validated) != 0 || !strings.Contains(r.lastDetail(), "subjectAltName") {
		t.Fatalf("status %q audit %q", rep.pkiStatus, r.lastDetail())
	}
}

func TestIntuneHonoursRequestedEKUAndRefusesPowerfulOnes(t *testing.T) {
	r := newLabelRig(t)
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	eku := func(oids ...asn1.ObjectIdentifier) []pkix.Extension {
		v, _ := asn1.Marshal(oids)
		return []pkix.Extension{{Id: oidEKU, Value: v}}
	}
	ok := intuneCSR(t, k, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "s"}, DNSNames: []string{"s.example"},
		ExtraExtensions: eku(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})})
	rep, cert := r.post(t, "corp", ok)
	if rep.pkiStatus != pkiStatusSuccess || len(cert.ExtKeyUsage) != 2 {
		t.Fatalf("status %q eku %v", rep.pkiStatus, cert)
	}
	bad := intuneCSR(t, k, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "s"}, DNSNames: []string{"s.example"},
		ExtraExtensions: eku(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3})}) // codeSigning
	if rep, _ := r.post(t, "corp", bad); rep.pkiStatus != pkiStatusFailure {
		t.Fatal("codeSigning EKU must be refused")
	}
}

func TestIntuneLabelRoutingAndCaps(t *testing.T) {
	r := newLabelRig(t)
	for path, want := range map[string]int{
		"/scep/corp?operation=GetCACaps":        200,
		"/scep/nope?operation=GetCACaps":        404,
		"/scep/mscep_admin?operation=GetCACaps": 404,
		"/scep/Bad_Label?operation=GetCACert":   404,
		"/?operation=GetCACaps":                 200,
	} {
		resp, err := http.Get(r.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, resp.StatusCode, want)
		}
		if strings.HasPrefix(path, "/scep/corp") && strings.Contains(string(body), "Renewal") {
			t.Error("a label must not advertise hub-native Renewal")
		}
		if path == "/?operation=GetCACaps" && !strings.Contains(string(body), "Renewal") {
			t.Error("the bare route keeps Renewal")
		}
	}
}

func TestIntuneLabelWithoutBackendFailsClosed(t *testing.T) {
	r := newLabelRig(t)
	r.srv.intune = nil
	if rep, cert := r.post(t, "corp", csrFor(t, "a", "a.example")); rep.pkiStatus != pkiStatusFailure || cert != nil {
		t.Fatalf("status %q", rep.pkiStatus)
	}
}

func TestIntuneLabelAlwaysAsksIntune(t *testing.T) {
	// Every request on a label is validated by Intune; the hub-native
	// challenge and renewal paths do not apply.
	r := newLabelRig(t)
	r.backend.validateErr = &intune.ServiceError{Code: "ChallengeExpired"}
	rep, _ := r.post(t, "corp", csrFor(t, "a", "a.example"))
	if rep.pkiStatus != pkiStatusFailure || len(r.backend.validated) != 1 {
		t.Fatalf("status %q validated %d", rep.pkiStatus, len(r.backend.validated))
	}
}

func TestLabelStores(t *testing.T) {
	ctx := context.Background()
	m := NewMemLabelStore()
	l := Label{Label: "x", Mode: ModeIntune, TemplateID: "t", IntuneTenantID: "a", IntuneClientID: "b", CredentialRef: "c", CreatedBy: "u"}
	if _, err := m.Create(ctx, l); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(ctx, l); !errors.Is(err, ErrLabelExists) {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, "x"); !errors.Is(err, ErrLabelNotFound) {
		t.Fatal(err)
	}
	for _, s := range []string{"corp", "a", "a-b"} {
		if !ValidLabel(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", "A", "mscep_admin", "a/b", strings.Repeat("a", 33)} {
		if ValidLabel(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}
