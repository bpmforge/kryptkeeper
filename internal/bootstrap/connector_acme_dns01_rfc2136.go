// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W27-22: RFC 2136 dynamic-update dns-01 adapter with TSIG (RFC 8945)
// request signing. Messages are packed with golang.org/x/net/dns/dnsmessage;
// the TSIG record is built by hand because dnsmessage has no TSIG type.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"kryptkeeper/internal/egress"
)

const (
	dnsOpUpdate     dnsmessage.OpCode = 5
	dnsClassNONE    dnsmessage.Class  = 254
	dnsTypeTSIG     dnsmessage.Type   = 250
	tsigFudgeSecs                     = 300
	rfc2136TXTTTL                     = 60
	rfc2136IOWindow                   = 10 * time.Second
)

func init() { registerDNSProvider("rfc2136", newRFC2136DNSFromConfig) }

type rfc2136DNS struct {
	nameserver string // host:port
	zone       string // no trailing dot
	keyName    string // lowercase, trailing dot
	algorithm  string // hmac-sha256|hmac-sha384|hmac-sha512
	secret     []byte
	secretB64  string // kept only to redact it

	now  func() time.Time
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newRFC2136DNSFromConfig(_ acmeConnectorConfig, p acmeCredentialPayload) (dnsProvider, error) {
	const need = `acme connector dns_provider rfc2136 needs a "dns" object in its credential (nameserver, zone, tsig_key_name, tsig_secret)`
	var d struct {
		Nameserver   string `json:"nameserver"`
		Zone         string `json:"zone"`
		TSIGKeyName  string `json:"tsig_key_name"`
		TSIGSecret   string `json:"tsig_secret"`
		TSIGAlgoritm string `json:"tsig_algorithm"`
	}
	if len(p.DNS) == 0 || json.Unmarshal(p.DNS, &d) != nil ||
		d.Nameserver == "" || d.Zone == "" || d.TSIGKeyName == "" || d.TSIGSecret == "" {
		return nil, errors.New(need)
	}
	alg := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.TSIGAlgoritm)), ".")
	if alg == "" {
		alg = "hmac-sha256"
	}
	if _, ok := tsigHash(alg); !ok {
		return nil, fmt.Errorf("acme connector dns_provider rfc2136: tsig_algorithm %q is not supported (hmac-sha256, hmac-sha384, hmac-sha512)", d.TSIGAlgoritm)
	}
	secret, err := base64.StdEncoding.DecodeString(d.TSIGSecret)
	if err != nil || len(secret) == 0 {
		return nil, errors.New("acme connector dns_provider rfc2136: tsig_secret must be base64")
	}
	ns := d.Nameserver
	if _, _, err := net.SplitHostPort(ns); err != nil {
		ns = net.JoinHostPort(strings.Trim(ns, "[]"), "53")
	}
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: egress.PolicyFromEnv(egress.Policy{AllowPrivate: true, AllowLoopback: egressAllowLoopback}).DialControl(),
	}
	return &rfc2136DNS{
		nameserver: ns,
		zone:       strings.TrimSuffix(strings.ToLower(d.Zone), "."),
		keyName:    strings.ToLower(strings.TrimSuffix(d.TSIGKeyName, ".")) + ".",
		algorithm:  alg, secret: secret, secretB64: d.TSIGSecret,
		now: time.Now, dial: dialer.DialContext,
	}, nil
}

func tsigHash(alg string) (func() hash.Hash, bool) {
	switch alg {
	case "hmac-sha256":
		return sha256.New, true
	case "hmac-sha384":
		return sha512.New384, true
	case "hmac-sha512":
		return sha512.New, true
	}
	return nil, false
}

// dnsWireName is the uncompressed lowercase wire form of a name.
func dnsWireName(name string) []byte {
	var out []byte
	for _, l := range strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".") {
		if l == "" {
			continue
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0)
}

func tsigTime48(t time.Time) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(t.Unix()))
	return b[2:]
}

// signTSIG returns the TSIG RDATA for a request message that does not yet
// carry its TSIG record (RFC 8945 section 4.3.3 request MAC).
func signTSIG(msgWithoutTSIG []byte, keyName, alg string, secret []byte, now time.Time) []byte {
	newHash, ok := tsigHash(alg)
	if !ok || len(msgWithoutTSIG) < 2 {
		return nil
	}
	algWire := dnsWireName(alg + ".")
	t48 := tsigTime48(now)
	fudge := []byte{byte(tsigFudgeSecs >> 8), byte(tsigFudgeSecs & 0xff)}

	mac := hmac.New(newHash, secret)
	mac.Write(msgWithoutTSIG)
	mac.Write(dnsWireName(keyName))
	mac.Write([]byte{0x00, 0xff}) // class ANY
	mac.Write([]byte{0, 0, 0, 0}) // TTL 0
	mac.Write(algWire)
	mac.Write(t48)
	mac.Write(fudge)
	mac.Write([]byte{0, 0}) // error
	mac.Write([]byte{0, 0}) // other len
	sum := mac.Sum(nil)

	rd := append([]byte(nil), algWire...)
	rd = append(rd, t48...)
	rd = append(rd, fudge...)
	rd = append(rd, byte(len(sum)>>8), byte(len(sum)))
	rd = append(rd, sum...)
	rd = append(rd, msgWithoutTSIG[0], msgWithoutTSIG[1]) // original ID
	return append(rd, 0, 0, 0, 0)                         // error, other len
}

// buildUpdate packs an UPDATE for one TXT RR (add, or exact-RR delete) and,
// when tsigRData is set, the TSIG record in the additional section. The
// returned bytes carry the 2-byte TCP length prefix.
func buildUpdate(id uint16, zone, fqdn, value string, add bool, keyName string, tsigRData []byte) ([]byte, error) {
	zn, err := dnsmessage.NewName(zone + ".")
	if err != nil {
		return nil, err
	}
	rn, err := dnsmessage.NewName(fqdn + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, OpCode: dnsOpUpdate})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: zn, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAuthorities(); err != nil {
		return nil, err
	}
	hdr := dnsmessage.ResourceHeader{Name: rn, Class: dnsmessage.ClassINET, TTL: rfc2136TXTTTL}
	if !add {
		hdr.Class, hdr.TTL = dnsClassNONE, 0
	}
	if err := b.TXTResource(hdr, dnsmessage.TXTResource{TXT: []string{value}}); err != nil {
		return nil, err
	}
	if tsigRData != nil {
		kn, err := dnsmessage.NewName(keyName)
		if err != nil {
			return nil, err
		}
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		if err := b.UnknownResource(dnsmessage.ResourceHeader{Name: kn, Class: dnsmessage.ClassANY},
			dnsmessage.UnknownResource{Type: dnsTypeTSIG, Data: tsigRData}); err != nil {
			return nil, err
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(out[:2], uint16(len(out)-2))
	return out, nil
}

func (r *rfc2136DNS) update(ctx context.Context, fqdn, value string, add bool) error {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return err
	}
	id := binary.BigEndian.Uint16(idb[:])
	// Build once without TSIG to sign, then again with it; same ID, so the
	// signed bytes are exactly what the server reconstructs.
	plain, err := buildUpdate(id, r.zone, fqdn, value, add, r.keyName, nil)
	if err != nil {
		return err
	}
	msg, err := buildUpdate(id, r.zone, fqdn, value, add, r.keyName, signTSIG(plain[2:], r.keyName, r.algorithm, r.secret, r.now()))
	if err != nil {
		return err
	}

	conn, err := r.dial(ctx, "tcp", r.nameserver)
	if err != nil {
		return r.wrap(fmt.Errorf("dns update to %s: %w", r.nameserver, err))
	}
	defer conn.Close()
	deadline := time.Now().Add(rfc2136IOWindow)
	if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(deadline) {
		deadline = ctxDL
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return r.wrap(fmt.Errorf("dns update to %s: %w", r.nameserver, err))
	}
	if _, err := conn.Write(msg); err != nil {
		return r.wrap(fmt.Errorf("dns update to %s: %w", r.nameserver, err))
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return r.wrap(fmt.Errorf("dns update to %s: no response: %w", r.nameserver, err))
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return r.wrap(fmt.Errorf("dns update to %s: short response: %w", r.nameserver, err))
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return r.wrap(fmt.Errorf("dns update to %s: unreadable response: %w", r.nameserver, err))
	}
	// The response MAC is deliberately NOT verified: the CA's own validation
	// stays the authority on whether the record is served, and a spoofed
	// NOERROR cannot make a missing record validate.
	if !h.Response || h.ID != id {
		return fmt.Errorf("dns update to %s: response does not match the request", r.nameserver)
	}
	return r.rcodeError(h.RCode)
}

func (r *rfc2136DNS) rcodeError(rc dnsmessage.RCode) error {
	switch rc {
	case dnsmessage.RCodeSuccess:
		return nil
	case dnsmessage.RCodeRefused:
		return fmt.Errorf("update refused by %s (check allow-update / update-policy and the TSIG key)", r.nameserver)
	case dnsmessage.RCode(9): // NOTAUTH
		return fmt.Errorf("%s is not authoritative for %s or rejected the TSIG signature", r.nameserver, r.zone)
	case dnsmessage.RCodeNotImplemented:
		return fmt.Errorf("%s does not implement dynamic update", r.nameserver)
	case dnsmessage.RCode(8): // NOTZONE
		return fmt.Errorf("%s is not a zone on %s", r.zone, r.nameserver)
	default:
		return fmt.Errorf("dns update rcode %d", rc)
	}
}

func (r *rfc2136DNS) wrap(err error) error {
	return errors.New(redact(err.Error(), string(r.secret), r.secretB64))
}

func (r *rfc2136DNS) Present(ctx context.Context, fqdn, value string) (string, func(context.Context) error, error) {
	if fqdn != r.zone && !strings.HasSuffix(fqdn, "."+r.zone) {
		return "", nil, fmt.Errorf("%s is not inside the configured rfc2136 zone %s", fqdn, r.zone)
	}
	if err := r.update(ctx, fqdn, value, true); err != nil {
		return "", nil, err
	}
	cleanup := func(ctx context.Context) error {
		// Deleting an exact RR leaves other values at the name alone, and
		// deleting an absent one is NOERROR, so no read is needed.
		return r.update(ctx, fqdn, value, false)
	}
	return r.zone, cleanup, nil
}
