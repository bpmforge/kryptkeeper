// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

// windowsShaped builds what CertEnroll sends to renew: SignedData over
// content with a version-1 SignerInfo by the old certificate (RSA, SHA-1,
// signed attributes) AND a version-3 SignerInfo identified by subject key
// identifier. The pkcs7 libraries report no signers for this shape.
func windowsShaped(t *testing.T, content []byte, old *x509.Certificate, oldKey *rsa.PrivateKey) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA1)
	if err := sd.AddSigner(old, oldKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var signed cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &signed); err != nil {
		t.Fatal(err)
	}
	v3, err := asn1.Marshal(cmsSignerInfo{
		Version:            3,
		SID:                asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: make([]byte, 20)},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}},
		Signature:          make([]byte, 256),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed.SignerInfos = asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: append(v3, signed.SignerInfos.Bytes...)}
	inner, err := asn1.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	// A RawValue with FullBytes is emitted verbatim, ignoring the field's
	// explicit [0] tag, so the wrapper is built by hand.
	wrapped, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{ci.ContentType, asn1.RawValue{FullBytes: wrapped}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rsaCert(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func TestOldKeySignerFindsWindowsRenewalSigner(t *testing.T) {
	old, key := rsaCert(t, "ws01.corp.example")
	content := []byte("cmc pkidata stand-in")
	der := windowsShaped(t, content, old, key)

	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Signers) != 0 {
		t.Fatalf("fixture no longer reproduces the library gap (%d signers)", len(p7.Signers))
	}
	if got := oldKeySigner(der, p7.Content, p7.Certificates); got == nil || !got.Equal(old) {
		t.Fatal("old-key signer not found in a Windows-shaped renewal")
	}

	// The signature must actually cover what was sent.
	if oldKeySigner(der, []byte("cmc pkidata stand-iN"), p7.Certificates) != nil {
		t.Fatal("altered content still verified")
	}
	// The signer must be identified by issuer and serial among the
	// embedded certificates: a look-alike with another key does not count.
	lookalike, _ := rsaCert(t, "ws01.corp.example")
	lookalike.RawIssuer, lookalike.SerialNumber = old.RawIssuer, old.SerialNumber
	if oldKeySigner(der, content, []*x509.Certificate{lookalike}) != nil {
		t.Fatal("a certificate with another key verified the signature")
	}
	if oldKeySigner([]byte("junk"), content, p7.Certificates) != nil {
		t.Fatal("junk parsed as a signed message")
	}
}
