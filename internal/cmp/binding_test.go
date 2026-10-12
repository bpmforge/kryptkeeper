// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"net/http/httptest"
	"testing"
	"time"
)

func bodyTag(t *testing.T, rr *httptest.ResponseRecorder) int {
	t.Helper()
	return decodeResponse(t, rr.Body.Bytes()).Body.Tag
}

// SUP-A04-2: the shared secret authenticates "a client", and the senderKID
// must name the configured reference, not any string.
func TestCMPHandlerIR_WrongSenderKID_Rejected(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	h := newServerForTest(engine, caID).Handler()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-wrong-kid")

	if got := bodyTag(t, postCMP(h, buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{kid: "someone-else"}))); got != PKIBodyError {
		t.Fatalf("wrong senderKID: body tag = %d, want PKIBodyError", got)
	}
	if got := bodyTag(t, postCMP(h, buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{}))); got != PKIBodyIP {
		t.Fatalf("matching senderKID: body tag = %d, want PKIBodyIP", got)
	}
}

// A captured, validly MAC'd request must not be replayable.
func TestCMPHandler_ReplayedTransactionAndNonce_Rejected(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	h := newServerForTest(engine, caID).Handler()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-replay")
	msg := buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{txnID: "txn-replay-1", nonce: "nonce-replay-0001"})

	if got := bodyTag(t, postCMP(h, msg)); got != PKIBodyIP {
		t.Fatalf("first submission: body tag = %d, want PKIBodyIP", got)
	}
	if got := bodyTag(t, postCMP(h, msg)); got != PKIBodyError {
		t.Fatalf("replay of the same message: body tag = %d, want PKIBodyError", got)
	}
	// The same transaction with a fresh nonce (its certConf) is not a replay.
	confBody, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true})
	if err != nil {
		t.Fatal(err)
	}
	conf := buildProtectedPKIMessage(t, PKIBodyCertConf, confBody, pbmOptions{txnID: "txn-replay-1"})
	if got := bodyTag(t, postCMP(h, conf)); got != PKIBodyPKIConf {
		t.Fatalf("certConf with a fresh nonce: body tag = %d, want PKIBodyPKIConf", got)
	}
}

func TestCMPReplayCache(t *testing.T) {
	c := newReplayCache(4, time.Hour)
	if !c.firstUse([]byte("t"), []byte("n")) {
		t.Fatal("first use refused")
	}
	if c.firstUse([]byte("t"), []byte("n")) {
		t.Fatal("reuse accepted")
	}
	if c.firstUse(nil, []byte("n")) || c.firstUse([]byte("t"), nil) {
		t.Fatal("empty transactionID or senderNonce must be refused")
	}
	// "ab"+"c" and "a"+"bc" are different keys.
	if !c.firstUse([]byte("ab"), []byte("c")) || !c.firstUse([]byte("a"), []byte("bc")) {
		t.Fatal("key concatenation is ambiguous")
	}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		c.firstUse([]byte("t2"), []byte(n))
	}
	if got := c.size(); got > 4 {
		t.Fatalf("cache grew past its bound: %d", got)
	}

	now := time.Now()
	c = newReplayCache(4, time.Minute)
	c.now = func() time.Time { return now }
	c.firstUse([]byte("t"), []byte("n"))
	c.now = func() time.Time { return now.Add(2 * time.Minute) }
	if !c.firstUse([]byte("t"), []byte("n")) {
		t.Fatal("an entry past its window must be forgotten (documented per-process window)")
	}
}

func TestCMPHandlerIR_AllowedDNSSuffixes(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	bound := newServerForTest(engine, caID).WithAllowedDNSSuffixes([]string{".corp.example"}).Handler()
	open := newServerForTest(engine, caID).Handler()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	build := func(cn string, dns ...string) []byte {
		body := buildCRMFBodySANs(t, &priv.PublicKey, oidECDSAWithSHA256,
			func(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, priv, d) }, cn, dns)
		return buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{})
	}
	for _, tc := range []struct {
		name string
		msg  []byte
		want int
	}{
		{"SAN in suffix", build("a.corp.example", "a.corp.example"), PKIBodyIP},
		{"SAN outside suffix", build("a.corp.example", "a.corp.example", "www.bank.example"), PKIBodyError},
		{"CN outside suffix", build("www.bank.example", "a.corp.example"), PKIBodyError},
		{"CN outside suffix, no SAN", build("www.bank.example"), PKIBodyError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bodyTag(t, postCMP(bound, tc.msg)); got != tc.want {
				t.Fatalf("body tag = %d, want %d", got, tc.want)
			}
		})
	}
	// Without the setting an out-of-zone name still issues (unchanged).
	if got := bodyTag(t, postCMP(open, build("www.bank.example", "www.bank.example"))); got != PKIBodyIP {
		t.Fatalf("unconfigured server refused: body tag %d", got)
	}
}
