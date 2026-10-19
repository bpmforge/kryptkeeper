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
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// buildTypedPKIOperation is buildPKIOperation with a caller-chosen messageType.
func buildTypedPKIOperation(t *testing.T, msgType string, caCert *x509.Certificate, key *rsa.PrivateKey, signer *x509.Certificate, csrDER []byte) []byte {
	t.Helper()
	envelopeDER, err := pkcs7.Encrypt(csrDER, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData(envelopeDER)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	extra := []pkcs7.Attribute{
		{Type: oidMessageType, Value: asn1.RawValue{Tag: 19, Bytes: []byte(msgType)}},
		{Type: oidTransactionID, Value: asn1.RawValue{Tag: 19, Bytes: []byte("renew-" + signer.SerialNumber.String())}},
		{Type: oidSenderNonce, Value: asn1.RawValue{Tag: 4, Bytes: nonce}},
	}
	if err := sd.AddSigner(signer, key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: extra}); err != nil {
		t.Fatal(err)
	}
	msg, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// holder is a client that owns a certificate and its key.
type holder struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// enrollHolder enrolls through the challenge path and keeps the key.
func (f *scepFixture) enrollHolder(t *testing.T, cn string, dns ...string) holder {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	boot := selfSignedRSACert(t, key, cn)
	msg, _, _ := buildPKIOperation(t, f.caObj.Certificate, key, boot, buildCSRWithChallenge(t, key, cn, f.mint(t, cn, dns...)))
	cert := f.postForCert(t, msg, key, boot)
	if cert == nil {
		t.Fatal("initial enrollment failed")
	}
	return holder{key: key, cert: cert}
}

// postForCert posts msg and returns the issued cert (decrypted with decKey /
// decCert), or nil on FAILURE. The CertRep of a refusal is also recorded in
// f.lastRep.
func (f *scepFixture) postForCert(t *testing.T, msg []byte, decKey *rsa.PrivateKey, decCert *x509.Certificate) *x509.Certificate {
	t.Helper()
	resp := postPKIOperation(t, f.ts, msg)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	rep := parseCertRep(t, body)
	f.lastRep = rep
	if rep.pkiStatus != pkiStatusSuccess {
		return nil
	}
	env, err := pkcs7.Parse(rep.p7.Content)
	if err != nil {
		t.Fatal(err)
	}
	der, err := env.Decrypt(decCert, decKey)
	if err != nil {
		t.Fatal(err)
	}
	co, err := pkcs7.Parse(der)
	if err != nil || len(co.Certificates) != 1 {
		t.Fatalf("certs-only: %v", err)
	}
	return co.Certificates[0]
}

// renewalFixture is a SCEP fixture with a working revocation store.
func newRenewalFixture(t *testing.T) (*scepFixture, *ca.MemRevocationStore) {
	t.Helper()
	f := newSCEPFixture(t)
	rs := ca.NewMemRevocationStore()
	f.srv.WithRevocationChecker(func(serial *big.Int) (bool, error) {
		revoked, _, _, err := rs.IsRevoked(serial, f.caObj.ID)
		return revoked, err
	})
	return f, rs
}

func (f *scepFixture) renewAs(t *testing.T, msgType string, signer holder, csrKey *rsa.PrivateKey, csrCN, challenge string) *x509.Certificate {
	t.Helper()
	var csr []byte
	if challenge != "" {
		csr = buildCSRWithChallenge(t, csrKey, csrCN, challenge)
	} else {
		var err error
		csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: csrCN}}, csrKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f.postForCert(t, buildTypedPKIOperation(t, msgType, f.caObj.Certificate, signer.key, signer.cert, csr), signer.key, signer.cert)
}

func (f *scepFixture) lastAudit(t *testing.T) AuditEvent {
	t.Helper()
	if len(f.audited) == 0 {
		t.Fatal("no audit event")
	}
	return f.audited[len(f.audited)-1]
}

func (f *scepFixture) wantRenewDenied(t *testing.T, reasonSubstr string) {
	t.Helper()
	if f.lastRep.pkiStatus != pkiStatusFailure || f.lastRep.failInfo != failInfoBadRequest {
		t.Errorf("rep = status %q failInfo %q, want FAILURE/badRequest", f.lastRep.pkiStatus, f.lastRep.failInfo)
	}
	ev := f.lastAudit(t)
	if ev.Action != "scep.renew" || ev.Outcome != "denied" || !strings.Contains(ev.Detail, reasonSubstr) {
		t.Errorf("audit %+v, want scep.renew denied containing %q", ev, reasonSubstr)
	}
}

func TestSCEPRenewalAccepted(t *testing.T) {
	for _, tc := range []struct {
		name, msgType string
		reKey         bool
	}{
		{"PKCSReq same key", msgTypePKCSReq, false},
		{"PKCSReq new key", msgTypePKCSReq, true},
		{"RenewalReq same key", msgTypeRenewalReq, false},
		{"RenewalReq new key", msgTypeRenewalReq, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newRenewalFixture(t)
			defer f.Close()
			old := f.enrollHolder(t, "device-1.example.com", "device-1.example.com", "device-1.lan")
			csrKey := old.key
			if tc.reKey {
				csrKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			}
			// The CSR names someone else and carries no challenge: neither matters.
			renewed := f.renewAs(t, tc.msgType, old, csrKey, "Administrator", "")
			if renewed == nil {
				t.Fatalf("renewal refused: %+v / %+v", f.lastRep, f.audited)
			}
			if renewed.SerialNumber.Cmp(old.cert.SerialNumber) == 0 {
				t.Error("renewal returned the old serial")
			}
			if renewed.Subject.String() != "CN=device-1.example.com" || strings.Join(renewed.DNSNames, ",") != "device-1.example.com,device-1.lan" {
				t.Errorf("names %q %v not copied from the signer", renewed.Subject, renewed.DNSNames)
			}
			pub := renewed.PublicKey.(*rsa.PublicKey)
			if pub.Equal(&csrKey.PublicKey) != true {
				t.Error("renewed certificate does not carry the CSR key")
			}
			roots := x509.NewCertPool()
			roots.AddCert(f.caObj.Certificate)
			if _, err := renewed.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Errorf("renewed cert does not chain to the CA: %v", err)
			}
			ev := f.lastAudit(t)
			if ev.Action != "scep.renew" || ev.Outcome != "success" || ev.Actor != "device-1.example.com" ||
				!strings.Contains(ev.Detail, "old_serial="+old.cert.SerialNumber.Text(16)) ||
				!strings.Contains(ev.Detail, "new_serial="+renewed.SerialNumber.Text(16)) {
				t.Errorf("audit %+v", ev)
			}
		})
	}
}

// A challengePassword on a renewal is ignored: it is not consumed.
func TestSCEPRenewalDoesNotBurnChallenge(t *testing.T) {
	f, _ := newRenewalFixture(t)
	defer f.Close()
	old := f.enrollHolder(t, "device-2.example.com")
	other := f.mint(t, "other.example.com")
	if f.renewAs(t, msgTypePKCSReq, old, old.key, "device-2.example.com", other) == nil {
		t.Fatalf("renewal refused: %+v", f.audited)
	}
	// The unspent challenge still enrolls a fresh device.
	_, issued := f.enrollWith(t, "other.example.com", other)
	if issued == nil || issued.Subject.CommonName != "other.example.com" {
		t.Fatal("the challenge carried on a renewal was burned")
	}
}

// Challenge replay rules are unchanged by renewal support.
func TestSCEPRenewalLeavesChallengeReplayRefused(t *testing.T) {
	f, _ := newRenewalFixture(t)
	defer f.Close()
	secret := f.mint(t, "replay.example.com")
	if _, issued := f.enrollWith(t, "replay.example.com", secret); issued == nil {
		t.Fatal("first enrollment failed")
	}
	if rep, issued := f.enrollWith(t, "replay.example.com", secret); issued != nil || rep.pkiStatus != pkiStatusFailure {
		t.Fatal("a replayed challenge enrolled")
	}
}

// otherIdentity makes a CA-signed (non-self-signed) cert for cn from a CA that
// is not the fixture's, so it looks like a renewal but is not ours.
func otherCAHolder(t *testing.T, cn string) holder {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("scep-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Other Root", pkix.Name{CommonName: "Other Root CA"}, keystore.RSA2048, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificateRequest(csr)
	issued, err := engine.IssueCertificate(root.ID, ca.IssuanceRequest{
		CSR: parsed, Subject: &pkix.Name{CommonName: cn}, DNSNames: []string{cn}, CallerNamesOnly: true,
		Validity: 24 * time.Hour, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	return holder{key: key, cert: issued.Certificate}
}

func TestSCEPRenewalRefusals(t *testing.T) {
	for _, msgType := range []string{msgTypePKCSReq, msgTypeRenewalReq} {
		t.Run("other CA/"+msgType, func(t *testing.T) {
			f, _ := newRenewalFixture(t)
			defer f.Close()
			stranger := otherCAHolder(t, "device-3.example.com")
			if f.renewAs(t, msgType, stranger, stranger.key, "device-3.example.com", "") != nil {
				t.Fatal("a certificate from another CA renewed")
			}
			f.wantRenewDenied(t, "not issued by this CA")
		})
		t.Run("self-made CA same CN/"+msgType, func(t *testing.T) {
			f, _ := newRenewalFixture(t)
			defer f.Close()
			f.enrollHolder(t, "device-4.example.com") // the real one exists
			fake := otherCAHolder(t, "device-4.example.com")
			if f.renewAs(t, msgType, fake, fake.key, "device-4.example.com", "") != nil {
				t.Fatal("an unrelated key with the same CN renewed")
			}
			f.wantRenewDenied(t, "not issued by this CA")
		})
		t.Run("expired/"+msgType, func(t *testing.T) {
			f, _ := newRenewalFixture(t)
			defer f.Close()
			old := f.enrollHolder(t, "device-5.example.com")
			f.srv.now = func() time.Time { return time.Now().Add(400 * 24 * time.Hour) }
			if f.renewAs(t, msgType, old, old.key, "device-5.example.com", "") != nil {
				t.Fatal("an expired certificate renewed")
			}
			f.wantRenewDenied(t, "validity")
		})
		t.Run("revoked/"+msgType, func(t *testing.T) {
			f, rs := newRenewalFixture(t)
			defer f.Close()
			old := f.enrollHolder(t, "device-6.example.com")
			if err := rs.Revoke(old.cert.SerialNumber, f.caObj.ID, 1, time.Now()); err != nil {
				t.Fatal(err)
			}
			if f.renewAs(t, msgType, old, old.key, "device-6.example.com", "") != nil {
				t.Fatal("a revoked certificate renewed")
			}
			f.wantRenewDenied(t, "revoked")
		})
		t.Run("revocation lookup errors/"+msgType, func(t *testing.T) {
			f, _ := newRenewalFixture(t)
			defer f.Close()
			old := f.enrollHolder(t, "device-7.example.com")
			f.srv.WithRevocationChecker(func(*big.Int) (bool, error) { return false, errors.New("db down") })
			if f.renewAs(t, msgType, old, old.key, "device-7.example.com", "") != nil {
				t.Fatal("renewed with unknown revocation status")
			}
			f.wantRenewDenied(t, "revocation status unavailable")
		})
		t.Run("nil revocation checker/"+msgType, func(t *testing.T) {
			f := newSCEPFixture(t) // no WithRevocationChecker
			defer f.Close()
			old := f.enrollHolder(t, "device-8.example.com")
			if f.renewAs(t, msgType, old, old.key, "device-8.example.com", "") != nil {
				t.Fatal("renewed without a revocation checker")
			}
			f.wantRenewDenied(t, "revocation status unavailable")
		})
	}
}

// A refused renewal that also carries a valid challenge must not fall through
// to the challenge path, and must not burn the challenge.
func TestSCEPRenewalRefusalNeverFallsToChallengePath(t *testing.T) {
	f, rs := newRenewalFixture(t)
	defer f.Close()
	old := f.enrollHolder(t, "device-9.example.com")
	if err := rs.Revoke(old.cert.SerialNumber, f.caObj.ID, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	secret := f.mint(t, "device-9.example.com")
	if f.renewAs(t, msgTypePKCSReq, old, old.key, "device-9.example.com", secret) != nil {
		t.Fatal("refused renewal fell through to the challenge path")
	}
	f.wantRenewDenied(t, "revoked")
	if _, issued := f.enrollWith(t, "device-9.example.com", secret); issued == nil {
		t.Fatal("the challenge was burned by a refused renewal")
	}
}

func TestSCEPRenewalReqFromSelfSignedSignerRefused(t *testing.T) {
	f, _ := newRenewalFixture(t)
	defer f.Close()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	boot := selfSignedRSACert(t, key, "device-10.example.com")
	h := holder{key: key, cert: boot}
	// Even with a valid challenge, RenewalReq is not an enrollment.
	if f.renewAs(t, msgTypeRenewalReq, h, key, "device-10.example.com", f.mint(t, "device-10.example.com")) != nil {
		t.Fatal("RenewalReq from a self-signed signer was served")
	}
	f.wantRenewDenied(t, "self-signed")
}

func TestSCEPRenewalEnrollmentGateStillRuns(t *testing.T) {
	f, _ := newRenewalFixture(t)
	defer f.Close()
	old := f.enrollHolder(t, "device-11.example.com")
	f.srv.WithEnrollmentGate(func(_ context.Context, _ string) error { return ca.ErrEnrollmentDenied })
	if f.renewAs(t, msgTypePKCSReq, old, old.key, "device-11.example.com", "") != nil {
		t.Fatal("renewal bypassed the enrollment gate")
	}
	f.wantRenewDenied(t, "enrollment_permissions")
}

// A tampered signature on a RenewalReq answers badMessageCheck and is audited.
func TestSCEPRenewalBadSignatureIsBadMessageCheck(t *testing.T) {
	f, _ := newRenewalFixture(t)
	defer f.Close()
	old := f.enrollHolder(t, "device-12.example.com")
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-12.example.com"}}, old.key)
	// Signed by a different key than the signer cert's: signature must not verify.
	wrong, _ := rsa.GenerateKey(rand.Reader, 2048)
	msg := buildTypedPKIOperation(t, msgTypeRenewalReq, f.caObj.Certificate, wrong, old.cert, csr)
	if f.postForCert(t, msg, old.key, old.cert) != nil {
		t.Fatal("a message not signed by the cert's key was served")
	}
	if f.lastRep.failInfo != failInfoBadMessageCheck {
		t.Errorf("failInfo %q, want badMessageCheck", f.lastRep.failInfo)
	}
	if ev := f.lastAudit(t); ev.Action != "scep.renew" || ev.Outcome != "denied" {
		t.Errorf("audit %+v", ev)
	}
}

func TestSCEPIsSelfSigned(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if !isSelfSigned(selfSignedRSACert(t, key, "x")) {
		t.Error("a real self-signed cert was not recognised")
	}
	f, _ := newRenewalFixture(t)
	defer f.Close()
	if isSelfSigned(f.enrollHolder(t, "y.example.com").cert) {
		t.Error("a CA-issued cert counted as self-signed")
	}
}
