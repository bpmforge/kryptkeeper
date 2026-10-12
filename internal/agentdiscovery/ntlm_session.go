// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // NTLMv2 (MS-NLMP) mandates HMAC-MD5/MD5; not used for any Kryptkeeper-originated integrity decision.
	"crypto/rc4" //nolint:gosec // MS-NLMP sealing is RC4; the ONLY reason this exists is to talk to a Windows WinRM listener that offers nothing else over http.
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // NTOWFv1 is MD4 by definition (MS-NLMP 3.3.1).
)

// W18-09: NTLMv2 authentication with message sealing (MS-NLMP), the layer
// WinRM needs over plain HTTP. go-ntlmssp only authenticates ("no key
// exchange or encryption"), so this is ours. It is deliberately a CLIENT-only,
// NTLMv2-only, 128-bit-key-exchange-only implementation: a challenge that does
// not offer all of that is refused rather than negotiated down, because the
// downgrade path is exactly an unsealed or weakly-sealed session.

const (
	ntlmUnicode          = 0x00000001
	ntlmSign             = 0x00000010
	ntlmSeal             = 0x00000020
	ntlmOEMDomain        = 0x00001000
	ntlmOEMWorkstation   = 0x00002000
	ntlmAlwaysSign       = 0x00008000
	ntlmExtendedSession  = 0x00080000
	ntlmTargetInfo       = 0x00800000
	ntlmVersion          = 0x02000000
	ntlm128              = 0x20000000
	ntlmKeyExch          = 0x40000000
	ntlm56               = 0x80000000
	ntlmNegotiateOffered = ntlmUnicode | ntlmSign | ntlmSeal | ntlmOEMDomain |
		ntlmOEMWorkstation | ntlmAlwaysSign | ntlmExtendedSession | ntlmTargetInfo | ntlmVersion | ntlm128 | ntlmKeyExch | ntlm56
	// What the server's challenge must grant for us to continue.
	ntlmRequired = ntlmUnicode | ntlmSign | ntlmSeal | ntlmExtendedSession | ntlmTargetInfo | ntlm128 | ntlmKeyExch

	avEOL       = 0
	avFlags     = 6
	avTimestamp = 7
	avFlagsMIC  = 0x2
)

// ntlmVersionBytes is informational (MS-NLMP 2.2.2.10); it only has to be 8 bytes.
var ntlmVersionBytes = []byte{0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f}

// ntlmClient is one authenticated, sealed NTLM session. Not safe for
// concurrent use: sealing is a stateful stream cipher, so callers serialise.
type ntlmClient struct {
	user, domain, workstation, password string
	rand                                io.Reader

	negotiate []byte

	signC, signS []byte
	sealC, sealS *rc4.Cipher
	seqC, seqS   uint32
}

func newNTLMClient(domain, user, password, workstation string, rnd io.Reader) *ntlmClient {
	return &ntlmClient{user: user, domain: domain, workstation: workstation, password: password, rand: rnd}
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[2*i:], r)
	}
	return b
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key) //nolint:gosec // see import note
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// secField appends a (len, maxlen, offset) security-buffer descriptor.
func secField(dst []byte, n, off int) []byte {
	dst = binary.LittleEndian.AppendUint16(dst, uint16(n))
	dst = binary.LittleEndian.AppendUint16(dst, uint16(n))
	return binary.LittleEndian.AppendUint32(dst, uint32(off))
}

// negotiateMessage is the type-1 message. The domain and workstation ride as
// OEM (ASCII) strings, as Windows clients send them.
func (c *ntlmClient) negotiateMessage() []byte {
	dom, ws := []byte(c.domain), []byte(c.workstation)
	const hdr = 40
	b := append([]byte("NTLMSSP\x00"), 1, 0, 0, 0)
	b = binary.LittleEndian.AppendUint32(b, ntlmNegotiateOffered)
	b = secField(b, len(dom), hdr)
	b = secField(b, len(ws), hdr+len(dom))
	b = append(b, ntlmVersionBytes...)
	b = append(b, dom...)
	b = append(b, ws...)
	c.negotiate = b
	return b
}

type avPair struct {
	id  uint16
	val []byte
}

func parseAVPairs(b []byte) ([]avPair, error) {
	var out []avPair
	for {
		if len(b) < 4 {
			return nil, errors.New("ntlm: truncated target info")
		}
		id, n := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
		if len(b) < 4+n {
			return nil, errors.New("ntlm: target info pair overruns the buffer")
		}
		if id == avEOL {
			return out, nil
		}
		out = append(out, avPair{id, b[4 : 4+n]})
		b = b[4+n:]
	}
}

func encodeAVPairs(ps []avPair) []byte {
	var b []byte
	for _, p := range ps {
		b = binary.LittleEndian.AppendUint16(b, p.id)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(p.val)))
		b = append(b, p.val...)
	}
	return append(b, 0, 0, 0, 0)
}

// field reads a security buffer descriptor at off and bounds-checks its payload.
func field(msg []byte, off int) ([]byte, error) {
	if len(msg) < off+8 {
		return nil, errors.New("ntlm: message too short")
	}
	n := int(binary.LittleEndian.Uint16(msg[off:]))
	p := int(binary.LittleEndian.Uint32(msg[off+4:]))
	if p < 0 || p+n > len(msg) || p+n < p {
		return nil, errors.New("ntlm: security buffer outside the message")
	}
	return msg[p : p+n], nil
}

func ntowfV2(password, user, domain string) []byte {
	h := md4.New() //nolint:gosec,staticcheck // see import note
	h.Write(utf16le(password))
	return hmacMD5(h.Sum(nil), utf16le(strings.ToUpper(user)+domain))
}

// authenticateMessage consumes the server's type-2 challenge, derives the
// session keys, and returns the type-3 message (with MIC).
func (c *ntlmClient) authenticateMessage(challenge []byte) ([]byte, error) {
	if len(challenge) < 48 || !bytes.Equal(challenge[:8], []byte("NTLMSSP\x00")) || binary.LittleEndian.Uint32(challenge[8:]) != 2 {
		return nil, errors.New("ntlm: not a type-2 challenge message")
	}
	flags := binary.LittleEndian.Uint32(challenge[20:])
	if flags&ntlmRequired != ntlmRequired {
		return nil, fmt.Errorf("ntlm: server does not grant 128-bit sealing with key exchange (flags %#x); refusing a weaker session", flags)
	}
	serverChallenge := challenge[24:32]
	tiRaw, err := field(challenge, 40)
	if err != nil {
		return nil, err
	}
	pairs, err := parseAVPairs(tiRaw)
	if err != nil {
		return nil, err
	}
	var ts []byte
	patched := false
	for i := range pairs {
		switch pairs[i].id {
		case avTimestamp:
			ts = pairs[i].val
		case avFlags:
			if len(pairs[i].val) == 4 {
				v := append([]byte(nil), pairs[i].val...)
				binary.LittleEndian.PutUint32(v, binary.LittleEndian.Uint32(v)|avFlagsMIC)
				pairs[i].val, patched = v, true
			}
		}
	}
	if len(ts) != 8 {
		return nil, errors.New("ntlm: challenge carries no timestamp; refusing (MIC could not be bound)")
	}
	if !patched {
		pairs = append(pairs, avPair{avFlags, []byte{avFlagsMIC, 0, 0, 0}})
	}

	clientChallenge := make([]byte, 8)
	exported := make([]byte, 16)
	if _, err := io.ReadFull(c.rand, clientChallenge); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c.rand, exported); err != nil {
		return nil, err
	}

	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, ts...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, encodeAVPairs(pairs)...)
	temp = append(temp, 0, 0, 0, 0)

	respKey := ntowfV2(c.password, c.user, c.domain)
	proof := hmacMD5(respKey, serverChallenge, temp)
	ntResp := append(append([]byte(nil), proof...), temp...)
	lmResp := make([]byte, 24) // all-zero when the server sent a timestamp (MS-NLMP 3.1.5.1.2)
	sessionBase := hmacMD5(respKey, proof)

	rc, err := rc4.NewCipher(sessionBase) //nolint:gosec // KEY_EXCH wraps the exported key with RC4 by definition.
	if err != nil {
		return nil, err
	}
	encKey := make([]byte, 16)
	rc.XORKeyStream(encKey, exported)

	dom, user, ws := utf16le(c.domain), utf16le(c.user), utf16le(c.workstation)
	const hdr = 88
	off := hdr
	b := append([]byte("NTLMSSP\x00"), 3, 0, 0, 0)
	b = secField(b, len(lmResp), off+len(dom)+len(user)+len(ws))
	b = secField(b, len(ntResp), off+len(dom)+len(user)+len(ws)+len(lmResp))
	b = secField(b, len(dom), off)
	b = secField(b, len(user), off+len(dom))
	b = secField(b, len(ws), off+len(dom)+len(user))
	b = secField(b, len(encKey), off+len(dom)+len(user)+len(ws)+len(lmResp)+len(ntResp))
	b = binary.LittleEndian.AppendUint32(b, flags)
	b = append(b, ntlmVersionBytes...)
	micAt := len(b)
	b = append(b, make([]byte, 16)...)
	b = append(b, dom...)
	b = append(b, user...)
	b = append(b, ws...)
	b = append(b, lmResp...)
	b = append(b, ntResp...)
	b = append(b, encKey...)
	copy(b[micAt:], hmacMD5(exported, c.negotiate, challenge, b))

	c.deriveKeys(exported)
	return b, nil
}

func (c *ntlmClient) deriveKeys(exported []byte) {
	k := func(magic string) []byte {
		sum := md5.Sum(append(append([]byte(nil), exported...), magic+"\x00"...)) //nolint:gosec // MS-NLMP 3.4.5.2/3.4.5.3
		return sum[:]
	}
	c.signC = k("session key to client-to-server signing key magic constant")
	c.signS = k("session key to server-to-client signing key magic constant")
	c.sealC, _ = rc4.NewCipher(k("session key to client-to-server sealing key magic constant")) //nolint:gosec // 16-byte key: cannot fail
	c.sealS, _ = rc4.NewCipher(k("session key to server-to-client sealing key magic constant")) //nolint:gosec // 16-byte key: cannot fail
}

func ntlmChecksum(signKey []byte, seq uint32, msg []byte) []byte {
	var s [4]byte
	binary.LittleEndian.PutUint32(s[:], seq)
	return hmacMD5(signKey, s[:], msg)[:8]
}

// seal encrypts msg and returns (16-byte signature, ciphertext).
func (c *ntlmClient) seal(msg []byte) (sig, sealed []byte) {
	sealed = make([]byte, len(msg))
	c.sealC.XORKeyStream(sealed, msg)
	sum := ntlmChecksum(c.signC, c.seqC, msg)
	c.sealC.XORKeyStream(sum, sum)
	sig = binary.LittleEndian.AppendUint32(nil, 1)
	sig = append(sig, sum...)
	sig = binary.LittleEndian.AppendUint32(sig, c.seqC)
	c.seqC++
	return sig, sealed
}

// unseal decrypts a server message and verifies its signature and sequence
// number. A bad signature is an error, never a best-effort plaintext.
func (c *ntlmClient) unseal(sig, sealed []byte) ([]byte, error) {
	if len(sig) != 16 || binary.LittleEndian.Uint32(sig) != 1 {
		return nil, errors.New("ntlm: malformed message signature")
	}
	plain := make([]byte, len(sealed))
	c.sealS.XORKeyStream(plain, sealed)
	want := ntlmChecksum(c.signS, c.seqS, plain)
	c.sealS.XORKeyStream(want, want)
	if subtle.ConstantTimeCompare(want, sig[4:12]) != 1 || binary.LittleEndian.Uint32(sig[12:]) != c.seqS {
		return nil, errors.New("ntlm: server message failed signature or sequence verification")
	}
	c.seqS++
	return plain, nil
}
