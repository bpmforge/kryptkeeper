// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/url"
)

// PermanentIdentifier is the RFC 4043 otherName that names a device by its
// manufacturer-assigned identity (serial number). W40-02 puts it in the SAN of
// a certificate issued after device attestation, because crypto/x509 has no
// field for otherName and the identifier must appear in the certificate
// exactly as it was proven (draft-ietf-acme-device-attest-10 section 3.2).
type PermanentIdentifier struct {
	Value    string
	Assigner asn1.ObjectIdentifier // nil when the order carried no assigner
}

var (
	// id-on-permanentIdentifier, RFC 4043 section 4.1.
	oidPermanentIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
)

// permanentIdentifierASN1 is RFC 4043's PermanentIdentifier. Both members are
// OPTIONAL in the RFC; the draft requires identifierValue.
type permanentIdentifierASN1 struct {
	IdentifierValue string                `asn1:"utf8,optional"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

// marshalSANExtension builds the whole SAN extension. crypto/x509 only writes
// the SAN itself from DNSNames/IPAddresses/URIs; an extension passed in
// ExtraExtensions replaces that one ("Values override any extensions that
// would otherwise be produced"), so the names are re-encoded here beside the
// otherNames rather than dropped.
func marshalSANExtension(dns []string, ips []net.IP, uris []*url.URL, ids []PermanentIdentifier) (pkix.Extension, error) {
	var names []asn1.RawValue
	ctx := func(tag int, compound bool, b []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: compound, Bytes: b}
	}
	for _, n := range dns {
		names = append(names, ctx(2, false, []byte(n)))
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		names = append(names, ctx(7, false, ip))
	}
	for _, u := range uris {
		names = append(names, ctx(6, false, []byte(u.String())))
	}
	for _, id := range ids {
		if id.Value == "" {
			return pkix.Extension{}, errors.New("permanent identifier value is empty")
		}
		inner := permanentIdentifierASN1{IdentifierValue: id.Value}
		if len(id.Assigner) > 0 {
			inner.Assigner = id.Assigner
		}
		innerDER, err := asn1.Marshal(inner)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("marshal permanent identifier: %w", err)
		}
		oidDER, err := asn1.Marshal(oidPermanentIdentifier)
		if err != nil {
			return pkix.Extension{}, err
		}
		explicit, err := asn1.Marshal(ctx(0, true, innerDER)) // [0] EXPLICIT value
		if err != nil {
			return pkix.Extension{}, err
		}
		names = append(names, ctx(0, true, append(oidDER, explicit...)))
	}
	der, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal subject alternative name: %w", err)
	}
	return pkix.Extension{Id: oidSubjectAltName, Value: der}, nil
}

// SANPermanentIdentifiers returns the RFC 4043 PermanentIdentifier otherNames
// in the SAN extension among exts (a certificate's or a CSR's), and how many
// other general names ride beside them, so a caller can insist on exactly the
// identifier it expects and nothing else.
func SANPermanentIdentifiers(exts []pkix.Extension) (ids []PermanentIdentifier, foreign int, err error) {
	for _, ext := range exts {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var seq asn1.RawValue
		if rest, perr := asn1.Unmarshal(ext.Value, &seq); perr != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence || !seq.IsCompound {
			return nil, 0, errors.New("malformed subject alternative name extension")
		}
		rest := seq.Bytes
		for len(rest) > 0 {
			var gn asn1.RawValue
			if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
				return nil, 0, errors.New("malformed general name")
			}
			id, ok := parsePermanentIdentifierName(gn)
			if !ok {
				foreign++
				continue
			}
			ids = append(ids, id)
		}
	}
	return ids, foreign, nil
}

func parsePermanentIdentifierName(gn asn1.RawValue) (PermanentIdentifier, bool) {
	if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 || !gn.IsCompound {
		return PermanentIdentifier{}, false
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(gn.Bytes, &oid)
	if err != nil || !oid.Equal(oidPermanentIdentifier) {
		return PermanentIdentifier{}, false
	}
	var explicit asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &explicit); err != nil || len(rest) != 0 || explicit.Tag != 0 {
		return PermanentIdentifier{}, false
	}
	var pi permanentIdentifierASN1
	if rest, err = asn1.Unmarshal(explicit.Bytes, &pi); err != nil || len(rest) != 0 {
		return PermanentIdentifier{}, false
	}
	return PermanentIdentifier{Value: pi.IdentifierValue, Assigner: pi.Assigner}, true
}
