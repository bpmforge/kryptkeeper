// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pkcs12"
	sslmatepkcs12 "software.sslmate.com/src/go-pkcs12"

	"kryptkeeper/internal/agentclient"
)

// W14-05: JKS, PKCS#12, and kubeconfig discovery — the formats where
// enterprise certificates hide, which the plain PEM walk misses.
// CERTIFICATES ONLY are extracted; private key material is never read
// (JKS) or discarded immediately (P12).

// KeystoreScanResult is one directory/host's keystore discovery.
type KeystoreScanResult struct {
	Certs            []agentclient.DiscoveredCert `json:"certs"`
	UnreadableStores []string                     `json:"unreadable_stores"` // "path: reason"
}

// defaultP12Passwords are tried before any configured ones.
var defaultP12Passwords = []string{"changeit", ""}

// jksMagic identifies a Java keystore.
const jksMagic = 0xFEEDFEED

const (
	// jceksMagic identifies a JCEKS keystore (JKS layout, different magic).
	jceksMagic uint32 = 0xCECECECE

	// reasonPasswordUnknown is the reason recorded for a password-protected
	// store we could not open with any default or configured password.
	reasonPasswordUnknown = "keystore, password unknown"

	// jceksChainSearchWindow bounds the forward search past a serialized key.
	jceksChainSearchWindow = 64 * 1024
)

// sniffKeystore classifies a Java-family keystore by CONTENT, not extension
// (users routinely name JCEKS files .jks). It returns "jks", "jceks", "bcfks"
// or "" when the bytes match none of them.
func sniffKeystore(content []byte) string {
	if len(content) >= 4 {
		switch binary.BigEndian.Uint32(content) {
		case jksMagic:
			return "jks"
		case jceksMagic:
			return "jceks"
		}
	}
	if looksLikeBCFKS(content) {
		return "bcfks"
	}
	return ""
}

// looksLikeBCFKS reports whether content is a DER SEQUENCE whose leading
// elements nest SEQUENCEs down to an OBJECT IDENTIFIER, which is the shape of
// a BCFKS ObjectStore (encrypted store data led by an AlgorithmIdentifier).
// An X.509 certificate, PKCS#12 PFX or arbitrary text does not match: their
// leading nested element is a tag or INTEGER, not an OID.
func looksLikeBCFKS(content []byte) bool {
	cur := content
	for depth := 0; depth < 4; depth++ {
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(cur, &seq); err != nil ||
			seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
			return false
		}
		var first asn1.RawValue
		if _, err := asn1.Unmarshal(seq.Bytes, &first); err != nil || first.Class != asn1.ClassUniversal {
			return false
		}
		if first.Tag == asn1.TagOID {
			return depth > 0
		}
		if first.Tag != asn1.TagSequence {
			return false
		}
		cur = seq.Bytes
	}
	return false
}

// ParseJKSCerts extracts the CLEAR-text certificates from a JKS blob:
// trusted-cert entries and the cert chains of key entries. The
// encrypted private-key blob of a key entry is length-skipped and
// never read — JKS cert discovery cannot touch key material.
func ParseJKSCerts(data []byte) ([]*x509.Certificate, error) {
	p := &jksReader{b: data}
	if p.u32() != jksMagic {
		return nil, fmt.Errorf("not a JKS keystore (bad magic)")
	}
	_ = p.u32() // version
	count := p.u32()
	if p.err != nil {
		return nil, p.err
	}
	var certs []*x509.Certificate
	for i := uint32(0); i < count && p.err == nil; i++ {
		tag := p.u32()
		_ = p.utf() // alias
		_ = p.i64() // creation timestamp
		switch tag {
		case 1: // private key entry: [encrypted key][cert chain]
			p.skip(int(p.u32())) // encrypted key blob — NEVER read
			chainLen := p.u32()
			for j := uint32(0); j < chainLen && p.err == nil; j++ {
				_ = p.utf() // cert type ("X.509")
				if c := p.certBytes(); c != nil {
					if cert, err := x509.ParseCertificate(c); err == nil {
						certs = append(certs, cert)
					}
				}
			}
		case 2: // trusted cert entry
			_ = p.utf() // cert type
			if c := p.certBytes(); c != nil {
				if cert, err := x509.ParseCertificate(c); err == nil {
					certs = append(certs, cert)
				}
			}
		default:
			return certs, fmt.Errorf("unknown JKS entry tag %d", tag)
		}
	}
	if p.err != nil {
		return certs, p.err
	}
	return certs, nil
}

// ParseJCEKSCerts extracts the CLEAR-text certificates from a JCEKS blob. The
// layout matches JKS except that a key entry carries a Java-serialized
// SealedObject (not a length-prefixed blob) before its chain. Serialization
// cannot be length-skipped, so the chain is located by searching forward for
// a chain count followed by an "X.509" cert that parses; the sealed bytes are
// never interpreted. A partial result accompanies any error.
func ParseJCEKSCerts(data []byte) ([]*x509.Certificate, error) {
	p := &jksReader{b: data}
	if p.u32() != jceksMagic {
		return nil, fmt.Errorf("not a JCEKS keystore (bad magic)")
	}
	_ = p.u32() // version
	count := p.u32()
	if p.err != nil {
		return nil, p.err
	}
	var certs []*x509.Certificate
	readCert := func() {
		_ = p.utf() // cert type ("X.509")
		if c := p.certBytes(); c != nil {
			if cert, err := x509.ParseCertificate(c); err == nil {
				certs = append(certs, cert)
			}
		}
	}
	for i := uint32(0); i < count && p.err == nil; i++ {
		tag := p.u32()
		_ = p.utf() // alias
		_ = p.i64() // creation timestamp
		if p.err != nil {
			break
		}
		switch tag {
		case 1: // key entry: [serialized SealedObject][chain]
			at := locateJCEKSChain(p.b, p.off)
			if at < 0 {
				return certs, fmt.Errorf("jceks: key entry chain not located")
			}
			p.off = at
			chainLen := p.u32()
			for j := uint32(0); j < chainLen && p.err == nil; j++ {
				readCert()
			}
		case 2: // trusted cert entry
			readCert()
		case 3: // secret-key entry: serialized object only, no chain
			return certs, fmt.Errorf("jceks: secret-key entry, remaining entries not scanned")
		default:
			return certs, fmt.Errorf("unknown JCEKS entry tag %d", tag)
		}
	}
	return certs, p.err
}

// jceksChainMarker is the UTF "X.509" cert-type string that opens each chain
// element (u16 length 5 + bytes).
var jceksChainMarker = []byte{0x00, 0x05, 'X', '.', '5', '0', '9'}

// locateJCEKSChain returns the offset of the chain-count word of a key entry,
// searching at most jceksChainSearchWindow bytes from start, or -1. A hit needs
// a count in 1..16, the marker, and a length-prefixed DER that x509 accepts;
// the bare byte pattern alone is never trusted.
func locateJCEKSChain(b []byte, start int) int {
	end := min(len(b), start+jceksChainSearchWindow)
	for i := start; i+4+len(jceksChainMarker)+4 <= end; i++ {
		if n := binary.BigEndian.Uint32(b[i:]); n < 1 || n > 16 {
			continue
		}
		m := i + 4
		if !bytes.Equal(b[m:m+len(jceksChainMarker)], jceksChainMarker) {
			continue
		}
		l := m + len(jceksChainMarker)
		derLen := int(binary.BigEndian.Uint32(b[l:]))
		if derLen <= 0 || l+4+derLen > len(b) {
			continue
		}
		if _, err := x509.ParseCertificate(b[l+4 : l+4+derLen]); err == nil {
			return i
		}
	}
	return -1
}

// jksReader is a bounds-checked big-endian reader over the JKS blob.
type jksReader struct {
	b   []byte
	off int
	err error
}

func (r *jksReader) need(n int) bool {
	if r.err != nil || r.off+n > len(r.b) {
		if r.err == nil {
			r.err = fmt.Errorf("truncated JKS at offset %d", r.off)
		}
		return false
	}
	return true
}
func (r *jksReader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}
func (r *jksReader) i64() int64 {
	if !r.need(8) {
		return 0
	}
	v := int64(binary.BigEndian.Uint64(r.b[r.off:]))
	r.off += 8
	return v
}
func (r *jksReader) utf() string {
	if !r.need(2) {
		return ""
	}
	n := int(binary.BigEndian.Uint16(r.b[r.off:]))
	r.off += 2
	if !r.need(n) {
		return ""
	}
	s := string(r.b[r.off : r.off+n])
	r.off += n
	return s
}
func (r *jksReader) certBytes() []byte {
	n := int(r.u32())
	if !r.need(n) {
		return nil
	}
	c := r.b[r.off : r.off+n]
	r.off += n
	return c
}
func (r *jksReader) skip(n int) {
	if r.need(n) {
		r.off += n
	}
}

// ParsePKCS12Certs extracts CERTIFICATE blocks from a P12, discarding
// any private key. x/crypto/pkcs12 supports the legacy SHA-1-MAC
// profile only; modern SHA-256-MAC files return an error here and are
// recorded as unreadable, not silently dropped.
func ParsePKCS12Certs(data []byte, passwords []string) ([]*x509.Certificate, error) {
	var lastErr error
	for _, pw := range passwords {
		blocks, err := pkcs12.ToPEM(data, pw)
		if err != nil {
			// golang.org/x/crypto/pkcs12 predates SHA-256 MACs and PBES2, which
			// is what keytool on JDK 11+ writes; "unknown digest algorithm
			// 2.16.840.1.101.3.4.2.1" was every modern Java keystore (W34-20).
			// The maintained library reads those.
			var modernErr error
			blocks, modernErr = sslmatepkcs12.ToPEM(data, pw)
			if modernErr != nil {
				lastErr = err
				continue
			}
		}
		var certs []*x509.Certificate
		for _, blk := range blocks {
			if blk.Type != "CERTIFICATE" {
				continue // PRIVATE KEY blocks are discarded, never retained
			}
			if cert, err := x509.ParseCertificate(blk.Bytes); err == nil {
				certs = append(certs, cert)
			}
		}
		return certs, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no password matched")
	}
	return nil, lastErr
}

// ParseKubeconfigCerts scans a kubeconfig for embedded certificate
// data (client-certificate-data, certificate-authority-data) without a
// YAML dependency — the fields are flat base64.
func ParseKubeconfigCerts(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		for _, key := range []string{"client-certificate-data:", "certificate-authority-data:"} {
			if !strings.HasPrefix(line, key) {
				continue
			}
			b64 := strings.TrimSpace(strings.TrimPrefix(line, key))
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				continue
			}
			// Value is usually PEM; fall back to raw DER.
			certs = append(certs, certsFromDERorPEM(raw)...)
		}
	}
	return certs
}

func certsFromDERorPEM(raw []byte) []*x509.Certificate {
	var out []*x509.Certificate
	if c, err := x509.ParseCertificate(raw); err == nil {
		return []*x509.Certificate{c}
	}
	rest := raw
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// ScanKeystoreFile classifies a file by content (Java stores) or extension
// and extracts its certs. isKeystore is false for files this scanner does not
// handle.
func ScanKeystoreFile(path string, content []byte, configPasswords []string, res *KeystoreScanResult) (isKeystore bool) {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	add := func(certs []*x509.Certificate, format string) {
		for _, c := range certs {
			res.Certs = append(res.Certs, certToDiscovered(c, format+":"+path))
		}
	}
	unreadable := func(reason string) {
		res.UnreadableStores = append(res.UnreadableStores, path+": "+reason)
	}
	switch {
	case ext == ".jks" || ext == ".keystore" || ext == ".jceks" || ext == ".bcfks":
		format := sniffKeystore(content)
		if format == "" {
			// Unrecognised bytes keep the extension's historical parser, so a
			// corrupt .jks still surfaces its own error text.
			if ext == ".jceks" {
				format = "jceks"
			} else if ext == ".bcfks" {
				format = "bcfks"
			} else {
				format = "jks"
			}
		}
		switch format {
		case "jceks":
			certs, err := ParseJCEKSCerts(content)
			if err != nil {
				unreadable(err.Error())
			}
			add(certs, "jceks")
		case "bcfks":
			// BCFKS encrypts the whole store, certificates included, so cert
			// extraction needs a decryptor we do not ship. Inventory it as
			// unreadable rather than drop it.
			unreadable(reasonPasswordUnknown)
		default:
			certs, err := ParseJKSCerts(content)
			if err != nil {
				unreadable(err.Error())
			}
			add(certs, "jks")
		}
		return true
	case ext == ".p12" || ext == ".pfx":
		pws := append(append([]string{}, defaultP12Passwords...), configPasswords...)
		certs, err := ParsePKCS12Certs(content, pws)
		if err != nil {
			if errors.Is(err, pkcs12.ErrIncorrectPassword) {
				unreadable(reasonPasswordUnknown)
			} else {
				unreadable(err.Error())
			}
		}
		add(certs, "pkcs12")
		return true
	case base == "config" || base == "kubeconfig" || strings.HasSuffix(base, ".kubeconfig"):
		add(ParseKubeconfigCerts(content), "kubeconfig")
		return true
	}
	return false
}
