// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package revsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6960 byKey ResponderID
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// mldsaRevocationFixture is an ML-DSA-65 root with one issued ECDSA leaf.
type mldsaRevocationFixture struct {
	root   *ca.CA
	signer crypto.Signer
	pub    *mldsa65.PublicKey
	leaf   *x509.Certificate
}

func newMLDSARevocationFixture(t *testing.T) *mldsaRevocationFixture {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("mldsa-test-passphrase-32chars!!!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("ML-DSA CRL Root", pkix.Name{CommonName: "ML-DSA CRL Root"}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	signer, err := keys.Signer(root.KeyID)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	pub, ok := signer.Public().(*mldsa65.PublicKey)
	if !ok {
		t.Fatalf("signer public key is %T, want *mldsa65.PublicKey", signer.Public())
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.com"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := engine.IssueCertificate(root.ID, ca.IssuanceRequest{
		CSR:      csr,
		Validity: 24 * time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	return &mldsaRevocationFixture{root: root, signer: signer, pub: pub, leaf: issued.Certificate}
}

// splitSignedDER unpacks a CertificateList / signed structure into its TBS
// bytes, signature algorithm OID and signature.
func splitSignedDER(t *testing.T, der []byte) (tbs []byte, oid asn1.ObjectIdentifier, sig []byte) {
	t.Helper()
	var outer struct {
		TBS asn1.RawValue
		Alg algID
		Sig asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 {
		t.Fatalf("outer parse: err=%v rest=%d", err, len(rest))
	}
	return outer.TBS.FullBytes, outer.Alg.Algorithm, outer.Sig.Bytes
}

func TestMLDSACRLListsRevokedLeaf(t *testing.T) {
	f := newMLDSARevocationFixture(t)
	if !IsMLDSAIssuer(f.root.Certificate) {
		t.Fatal("ML-DSA root not detected as ML-DSA issuer")
	}

	store := ca.NewMemRevocationStore()
	revokedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if err := store.Revoke(f.leaf.SerialNumber, f.root.ID, 1, revokedAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	entries, err := store.ListRevoked(f.root.ID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: time.Now().UTC().Truncate(time.Second),
		NextUpdate: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second),
	}
	for _, e := range entries {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber: e.Serial, RevocationTime: e.RevokedAt, ReasonCode: e.ReasonCode,
		})
	}
	freshest := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: []byte{0x30, 0x00}}
	tmpl.ExtraExtensions = []pkix.Extension{freshest}

	der, err := CreateRevocationList(rand.Reader, tmpl, f.root.Certificate, f.signer)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}

	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 1 || parsed.RevokedCertificateEntries[0].SerialNumber.Cmp(f.leaf.SerialNumber) != 0 {
		t.Fatalf("leaf %v not listed: %+v", f.leaf.SerialNumber, parsed.RevokedCertificateEntries)
	}
	if got := parsed.RevokedCertificateEntries[0].ReasonCode; got != 1 {
		t.Errorf("reason code = %d, want 1", got)
	}
	if !parsed.RevokedCertificateEntries[0].RevocationTime.Equal(revokedAt) {
		t.Errorf("revocation time = %v, want %v", parsed.RevokedCertificateEntries[0].RevocationTime, revokedAt)
	}
	if parsed.Number.Int64() != 7 {
		t.Errorf("CRL number = %v, want 7", parsed.Number)
	}
	if string(parsed.RawIssuer) != string(f.root.Certificate.RawSubject) {
		t.Error("CRL issuer is not the CA subject")
	}
	if string(parsed.AuthorityKeyId) != string(f.root.Certificate.SubjectKeyId) {
		t.Error("authority key id does not match issuer SKI")
	}
	var sawFreshest bool
	for _, e := range parsed.Extensions {
		if e.Id.Equal(freshest.Id) {
			sawFreshest = true
		}
	}
	if !sawFreshest {
		t.Error("ExtraExtensions (freshest CRL) not carried through")
	}

	tbs, oid, sig := splitSignedDER(t, der)
	if !oid.Equal(keystore.OIDMLDsa65) {
		t.Fatalf("signature algorithm %v, want ML-DSA-65", oid)
	}
	if !mldsa65.Verify(f.pub, tbs, nil, sig) {
		t.Fatal("ML-DSA signature over TBSCertList does not verify")
	}

	// Negative: flipping one TBS byte must fail verification.
	bad := append([]byte(nil), tbs...)
	bad[len(bad)/2] ^= 0x01
	if mldsa65.Verify(f.pub, bad, nil, sig) {
		t.Fatal("tampered TBSCertList verified")
	}
	// Negative: wrong key must fail.
	otherPub, _, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if mldsa65.Verify(otherPub, tbs, nil, sig) {
		t.Fatal("signature verified under an unrelated key")
	}
}

func TestMLDSACRLEmptyAndNumber(t *testing.T) {
	f := newMLDSARevocationFixture(t)
	n := new(big.Int).Lsh(big.NewInt(1), 100)
	der, err := CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     n,
		ThisUpdate: time.Now().UTC(),
		NextUpdate: time.Now().UTC().Add(time.Hour),
	}, f.root.Certificate, f.signer)
	if err != nil {
		t.Fatalf("empty CRL: %v", err)
	}
	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 0 {
		t.Errorf("expected no entries, got %d", len(parsed.RevokedCertificateEntries))
	}
	if parsed.Number.Cmp(n) != 0 {
		t.Errorf("CRL number %v != %v", parsed.Number, n)
	}
	tbs, _, sig := splitSignedDER(t, der)
	if !mldsa65.Verify(f.pub, tbs, nil, sig) {
		t.Fatal("signature does not verify")
	}

	// Template validation mirrors the stdlib.
	if _, err := CreateRevocationList(rand.Reader, &x509.RevocationList{ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, f.root.Certificate, f.signer); err == nil {
		t.Error("nil CRL number accepted")
	}
}

type ocspParts struct {
	Status asn1.Enumerated
	Bytes  struct {
		Type asn1.ObjectIdentifier
		Resp []byte
	} `asn1:"explicit,tag:0"`
}

func TestMLDSAOCSPGoodAndRevoked(t *testing.T) {
	f := newMLDSARevocationFixture(t)
	nameHash := sha256.Sum256(f.root.Certificate.RawSubject)
	var spki spkiInfo
	if _, err := asn1.Unmarshal(f.root.Certificate.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	keyHash256 := sha256.Sum256(spki.PublicKey.Bytes)
	keyHash1 := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // byKey

	now := time.Now().UTC().Truncate(time.Second)
	revokedAt := now.Add(-time.Hour)
	for _, revoked := range []bool{false, true} {
		in := OCSPResponseInput{
			SerialNumber: f.leaf.SerialNumber, HashAlgorithm: crypto.SHA256,
			IssuerNameHash: nameHash[:], IssuerKeyHash: keyHash256[:],
			Revoked: revoked, RevokedAt: revokedAt, Reason: 1,
			ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		}
		der, err := CreateOCSPResponseMLDSA(f.root.Certificate, f.signer, in)
		if err != nil {
			t.Fatalf("revoked=%v: %v", revoked, err)
		}

		var resp ocspParts
		if rest, err := asn1.Unmarshal(der, &resp); err != nil || len(rest) != 0 {
			t.Fatalf("OCSPResponse parse: %v", err)
		}
		if resp.Status != 0 || !resp.Bytes.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}) {
			t.Fatalf("status=%d type=%v", resp.Status, resp.Bytes.Type)
		}
		tbs, oid, sig := splitSignedDER(t, resp.Bytes.Resp)
		if !oid.Equal(keystore.OIDMLDsa65) {
			t.Fatalf("signature algorithm %v", oid)
		}
		if !mldsa65.Verify(f.pub, tbs, nil, sig) {
			t.Fatal("OCSP signature does not verify")
		}
		bad := append([]byte(nil), tbs...)
		bad[len(bad)-3] ^= 0x01
		if mldsa65.Verify(f.pub, bad, nil, sig) {
			t.Fatal("tampered ResponseData verified")
		}

		// Walk ResponseData by hand: responderID byKey, CertStatus tag.
		var rd struct {
			ResponderID asn1.RawValue
			ProducedAt  time.Time `asn1:"generalized"`
			Responses   []asn1.RawValue
		}
		if _, err := asn1.Unmarshal(tbs, &rd); err != nil {
			t.Fatalf("ResponseData: %v", err)
		}
		if rd.ResponderID.Class != asn1.ClassContextSpecific || rd.ResponderID.Tag != 2 {
			t.Fatalf("responderID is not byKey [2]: %+v", rd.ResponderID)
		}
		var kh []byte
		if _, err := asn1.Unmarshal(rd.ResponderID.Bytes, &kh); err != nil || string(kh) != string(keyHash1[:]) {
			t.Fatalf("responder key hash mismatch (err=%v)", err)
		}
		var single struct {
			CertID struct {
				Alg          algID
				NameHash     []byte
				KeyHash      []byte
				SerialNumber *big.Int
			}
			Status     asn1.RawValue
			ThisUpdate time.Time `asn1:"generalized"`
			NextUpdate time.Time `asn1:"generalized,explicit,tag:0"`
		}
		if _, err := asn1.Unmarshal(rd.Responses[0].FullBytes, &single); err != nil {
			t.Fatalf("SingleResponse: %v", err)
		}
		if single.CertID.SerialNumber.Cmp(f.leaf.SerialNumber) != 0 || string(single.CertID.NameHash) != string(nameHash[:]) {
			t.Error("CertID not echoed")
		}
		if !single.NextUpdate.Equal(in.NextUpdate) {
			t.Errorf("nextUpdate %v", single.NextUpdate)
		}
		if revoked {
			if single.Status.Tag != 1 || !single.Status.IsCompound {
				t.Fatalf("want revoked [1], got %+v", single.Status)
			}
			var info struct {
				Time   time.Time       `asn1:"generalized"`
				Reason asn1.Enumerated `asn1:"explicit,tag:0"`
			}
			// Re-wrap the IMPLICIT content as a SEQUENCE to decode it.
			seq, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: single.Status.Bytes})
			if _, err := asn1.Unmarshal(seq, &info); err != nil {
				t.Fatalf("RevokedInfo: %v", err)
			}
			if !info.Time.Equal(revokedAt) || info.Reason != 1 {
				t.Errorf("revoked info = %+v", info)
			}
		} else if single.Status.Tag != 0 || single.Status.IsCompound || len(single.Status.Bytes) != 0 {
			t.Fatalf("want good [0] NULL, got %+v", single.Status)
		}

		// Cross-check with the library parser (status and timing only; it cannot
		// verify an ML-DSA signature).
		parsed, err := goocsp.ParseResponse(der, nil)
		if err != nil {
			t.Fatalf("x/crypto ocsp.ParseResponse: %v", err)
		}
		wantStatus := goocsp.Good
		if revoked {
			wantStatus = goocsp.Revoked
		}
		if parsed.Status != wantStatus || parsed.SerialNumber.Cmp(f.leaf.SerialNumber) != 0 {
			t.Errorf("library parse: status=%d serial=%v", parsed.Status, parsed.SerialNumber)
		}
		if revoked && (parsed.RevocationReason != 1 || !parsed.RevokedAt.Equal(revokedAt)) {
			t.Errorf("library parse revoked info: %d %v", parsed.RevocationReason, parsed.RevokedAt)
		}
	}
}

func TestClassicalIssuerStillUsesStdlib(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Classical CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if IsMLDSAIssuer(caCert) {
		t.Fatal("ECDSA CA reported as ML-DSA")
	}
	crlDER, err := CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(99), RevocationTime: time.Now()}},
	}, caCert, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("stdlib CRL signature: %v", err)
	}
}
