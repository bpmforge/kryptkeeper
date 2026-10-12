// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pkcs12"

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
			lastErr = err
			continue
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
			for _, c := range certsFromDERorPEM(raw) {
				certs = append(certs, c)
			}
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

// ScanKeystoreFile classifies a file by extension and extracts its
// certs. isKeystore is false for files this scanner does not handle.
func ScanKeystoreFile(path string, content []byte, configPasswords []string, res *KeystoreScanResult) (isKeystore bool) {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	add := func(certs []*x509.Certificate, format string) {
		for _, c := range certs {
			res.Certs = append(res.Certs, certToDiscovered(c, format+":"+path))
		}
	}
	switch {
	case ext == ".jks" || ext == ".keystore":
		certs, err := ParseJKSCerts(content)
		if err != nil {
			res.UnreadableStores = append(res.UnreadableStores, path+": "+err.Error())
		}
		add(certs, "jks")
		return true
	case ext == ".p12" || ext == ".pfx":
		pws := append(append([]string{}, defaultP12Passwords...), configPasswords...)
		certs, err := ParsePKCS12Certs(content, pws)
		if err != nil {
			res.UnreadableStores = append(res.UnreadableStores, path+": "+err.Error())
		}
		add(certs, "pkcs12")
		return true
	case base == "config" || base == "kubeconfig" || strings.HasSuffix(base, ".kubeconfig"):
		add(ParseKubeconfigCerts(content), "kubeconfig")
		return true
	}
	return false
}
