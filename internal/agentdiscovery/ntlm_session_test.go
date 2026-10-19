// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Golden vectors produced by an INDEPENDENT implementation (jborean93's
// ntlm-auth 1.5, Python) driven with the same fixed inputs: user "User",
// password "Password", domain "Domain", workstation "WS", client challenge
// 0xaa*8, exported session key 0x55*16, and a hand-built type-2 challenge
// with a fixed timestamp. Matching it byte for byte covers NTOWFv2, the
// NTLMv2 response, MIC, key exchange, key derivation, RC4 sealing and the
// signature. Regenerate by re-running that library, not by editing hex.
const (
	vecNegotiate    = "4e544c4d535350000100000031b088e20600060028000000020002002e0000000601b11d0000000f446f6d61696e5753"
	vecChallenge    = "4e544c4d53535000020000000c000c0038000000358289e20123456789abcdef00000000000000007e007e00440000000601b11d0000000f44004f004d00410049004e0002000c0044004f004d00410049004e0001000c0053004500520056004500520004001c0064006f006d00610069006e002e006500780061006d0070006c00650003002a007300650072007600650072002e0064006f006d00610069006e002e006500780061006d0070006c0065000700080000005af64cf5d40100000000"
	vecAuthenticate = "4e544c4d53535000030000001800180070000000b600b600880000000c000c00580000000800080064000000040004006c000000100010003e010000358289e20601b11d0000000f140aef3b55a71cd62d777024fb9556d944006f006d00610069006e00550073006500720057005300000000000000000000000000000000000000000000000000936d828894911a765fb38900eaad16ba010100000000000000005af64cf5d401aaaaaaaaaaaaaaaa0000000002000c0044004f004d00410049004e0001000c0053004500520056004500520004001c0064006f006d00610069006e002e006500780061006d0070006c00650003002a007300650072007600650072002e0064006f006d00610069006e002e006500780061006d0070006c0065000700080000005af64cf5d401060004000200000000000000000000000a3e0ebc1a21aac53e7de0d53a4b86a1"
	vecPlain1       = "506c61696e74657874"
	vecWrapped1     = "0100000071259958fa902db20000000054890c0cb06d3aa483"
	vecPlain2       = "50006c00610069006e007400650078007400320050006c00610069006e007400650078007400320050006c00610069006e0074006500780074003200"
	vecWrapped2     = "0100000060cb198142317f65010000000f0feaa6f537620a1134b76485ffda5f939a115103ac2679867493375658b987759c6a42d864270600a3b8b823ffa1f0e5205971d5b6827f3f5589dd"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixedNTLMRand() *bytes.Reader {
	return bytes.NewReader(append(bytes.Repeat([]byte{0xaa}, 8), bytes.Repeat([]byte{0x55}, 16)...))
}

func TestNTLMMatchesIndependentImplementation(t *testing.T) {
	c := newNTLMClient("Domain", "User", "Password", "WS", fixedNTLMRand())
	if got := c.negotiateMessage(); !bytes.Equal(got, mustHex(t, vecNegotiate)) {
		t.Fatalf("negotiate differs:\n got %x\nwant %s", got, vecNegotiate)
	}
	auth, err := c.authenticateMessage(mustHex(t, vecChallenge))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(auth, mustHex(t, vecAuthenticate)) {
		t.Fatalf("authenticate differs:\n got %x\nwant %s", auth, vecAuthenticate)
	}
	for i, v := range [][2]string{{vecPlain1, vecWrapped1}, {vecPlain2, vecWrapped2}} {
		sig, sealed := c.seal(mustHex(t, v[0]))
		if got := append(sig, sealed...); !bytes.Equal(got, mustHex(t, v[1])) {
			t.Fatalf("message %d sealed differently:\n got %x\nwant %s", i, got, v[1])
		}
	}
}

func TestNTLMRefusesWeakOrMalformedChallenges(t *testing.T) {
	good := mustHex(t, vecChallenge)
	mutate := func(f func(b []byte)) []byte { b := append([]byte(nil), good...); f(b); return b }
	cases := map[string][]byte{
		"no 128-bit":        mutate(func(b []byte) { b[23] &^= 0x20 }),
		"no key exchange":   mutate(func(b []byte) { b[23] &^= 0x40 }),
		"no sealing":        mutate(func(b []byte) { b[20] &^= 0x20 }),
		"no extended sess.": mutate(func(b []byte) { b[22] &^= 0x08 }),
		"truncated":         good[:30],
		"wrong type":        mutate(func(b []byte) { b[8] = 3 }),
		"bad target info":   mutate(func(b []byte) { b[40], b[41] = 0xff, 0x7f }),
	}
	for name, ch := range cases {
		if _, err := newNTLMClient("Domain", "User", "Password", "WS", fixedNTLMRand()).authenticateMessage(ch); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Server-direction messages sealed per MS-NLMP and independently
// verified by ntlm-auth's unwrap (which checks signature and sequence).
const (
	vecServer1 = "01000000a244354485684d6700000000356d6fc134c83d9a49bd54f74b32"
	vecServer2 = "0100000062214058eca9ae0a01000000586b2f9703cea7740646d0c1eb"
)

func authedTestClient(t *testing.T) *ntlmClient {
	t.Helper()
	c := newNTLMClient("Domain", "User", "Password", "WS", fixedNTLMRand())
	c.negotiateMessage()
	if _, err := c.authenticateMessage(mustHex(t, vecChallenge)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNTLMUnsealAcceptsIndependentlyVerifiedServerMessages(t *testing.T) {
	c := authedTestClient(t)
	for i, want := range []string{"server says hi", "<s:Envelope/>"} {
		m := mustHex(t, []string{vecServer1, vecServer2}[i])
		got, err := c.unseal(m[:16], m[16:])
		if err != nil || string(got) != want {
			t.Fatalf("message %d: %q, %v", i, got, err)
		}
	}
}

func TestNTLMUnsealRejectsTamperingReplayAndReorder(t *testing.T) {
	m1, m2 := mustHex(t, vecServer1), mustHex(t, vecServer2)
	flip := func(b []byte, i int) []byte { b = append([]byte(nil), b...); b[i] ^= 1; return b }
	c := authedTestClient(t)
	if _, err := c.unseal(m1[:16], flip(m1[16:], 0)); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	c = authedTestClient(t)
	if _, err := c.unseal(flip(m1[:16], 6), m1[16:]); err == nil {
		t.Fatal("tampered checksum accepted")
	}
	c = authedTestClient(t)
	if _, err := c.unseal(m2[:16], m2[16:]); err == nil {
		t.Fatal("out-of-order message (seq 1 first) accepted")
	}
	c = authedTestClient(t)
	if _, err := c.unseal(m1[:16], m1[16:]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.unseal(m1[:16], m1[16:]); err == nil {
		t.Fatal("replayed message accepted")
	}
	if _, err := c.unseal([]byte{1}, nil); err == nil {
		t.Fatal("short signature accepted")
	}
}
