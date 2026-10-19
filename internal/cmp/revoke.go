// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"kryptkeeper/internal/logging"
)

// Revoker revokes a certificate by serial on behalf of an authenticated CMP
// client. It is the seam to the hub's revocation path (CRL + OCSP). The
// returned scope is the hub's revocation_scope ("ca" or "inventory_only"); rp
// has no field for it, so it is recorded in the audit detail.
type Revoker interface {
	Revoke(ctx context.Context, serial *big.Int, reason int, actor string) (scope string, err error)
}

var (
	// ErrUnknownSerial: no certificate with that serial.
	ErrUnknownSerial = errors.New("cmp: unknown certificate serial")
	// ErrNotRevocable: the certificate exists but this client may not (or
	// cannot) revoke it, e.g. not CMP-issued or already revoked. Callers must
	// answer exactly as for ErrUnknownSerial.
	ErrNotRevocable = errors.New("cmp: certificate not revocable")
)

// revDetail is one RevDetails reduced to what revocation needs.
type revDetail struct {
	Serial *big.Int
	Issuer []byte // raw issuer Name from the CertTemplate, if present
	Reason int
}

// validRevReasons are the CRLReason codes RFC 5280 §5.3.1 allows in a CRL
// entry (7 is unused).
var validRevReasons = map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 8: true, 9: true, 10: true}

// oidCRLReason is 2.5.29.21 (id-ce-cRLReasons).
var oidCRLReason = asn1.ObjectIdentifier{2, 5, 29, 21}

// parseRevReqContent decodes RevReqContent ::= SEQUENCE OF RevDetails,
// RevDetails ::= SEQUENCE { certDetails CertTemplate, crlEntryDetails
// Extensions OPTIONAL }. From the CertTemplate it takes [1] serialNumber and
// [3] issuer; the reason is the CRLReason extension (default unspecified).
func parseRevReqContent(body []byte) ([]revDetail, error) {
	var raw []struct {
		CertDetails     asn1.RawValue
		CrlEntryDetails []pkix.Extension `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse RevReqContent: %w", err)
	}
	out := make([]revDetail, 0, len(raw))
	for _, rd := range raw {
		var fields []asn1.RawValue
		if _, err := asn1.Unmarshal(rd.CertDetails.FullBytes, &fields); err != nil {
			return nil, fmt.Errorf("parse CertTemplate: %w", err)
		}
		var d revDetail
		for _, f := range fields {
			if f.Class != asn1.ClassContextSpecific {
				continue
			}
			switch f.Tag {
			case 1: // serialNumber [1] IMPLICIT INTEGER
				der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: f.Bytes})
				if err != nil {
					return nil, fmt.Errorf("re-tag serialNumber: %w", err)
				}
				serial := new(big.Int)
				if _, err := asn1.Unmarshal(der, &serial); err != nil {
					return nil, fmt.Errorf("parse serialNumber: %w", err)
				}
				d.Serial = serial
			case 3: // issuer [3] Name (CHOICE, so EXPLICIT); kept raw
				d.Issuer = f.Bytes
			}
		}
		if d.Serial == nil || d.Serial.Sign() <= 0 {
			return nil, errors.New("certDetails carries no positive serialNumber")
		}
		for _, ext := range rd.CrlEntryDetails {
			if !ext.Id.Equal(oidCRLReason) {
				continue
			}
			var reason asn1.Enumerated
			if _, err := asn1.Unmarshal(ext.Value, &reason); err != nil {
				return nil, fmt.Errorf("parse CRLReason: %w", err)
			}
			d.Reason = int(reason)
		}
		if !validRevReasons[d.Reason] {
			return nil, fmt.Errorf("unsupported revocation reason %d", d.Reason)
		}
		out = append(out, d)
	}
	return out, nil
}

// handleRevoke answers an rr (body type 11) with a protected rp (12). The
// message already passed the shared PBM protection gate; protection by the
// revoked certificate's own key is not supported (see W26-09).
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, msg *parsedMessage) {
	fail := func(outcome, detail, clientText string) {
		s.emit(r.Context(), r, msg, "cmp.rr", outcome, detail)
		s.writeErrorFail(w, msg.cred, msg.Header, "badRequest: "+clientText, failBadRequest)
	}

	if s.revoker == nil {
		fail("denied", "revocation is not enabled", "revocation is not enabled")
		return
	}
	details, err := parseRevReqContent(msg.BodyBytes)
	if err != nil {
		fail("denied", "malformed rr: "+err.Error(), "malformed revocation request")
		return
	}
	if len(details) != 1 {
		fail("denied", fmt.Sprintf("rr carries %d RevDetails, want 1", len(details)), "exactly one certificate per revocation request")
		return
	}
	d := details[0]
	serialHex := d.Serial.Text(16)

	// One answer for unknown and not-revocable, so a CMP secret holder learns
	// nothing about certificates it did not issue.
	scope, err := s.revoker.Revoke(r.Context(), d.Serial, d.Reason, string(msg.Header.SenderKID))
	if err != nil {
		if errors.Is(err, ErrUnknownSerial) || errors.Is(err, ErrNotRevocable) {
			fail("denied", "serial="+serialHex+" unknown or not revocable", "unknown or not revocable certificate")
			return
		}
		logging.Warnf("cmp: revocation of %s failed: %v", serialHex, err)
		fail("failure", "serial="+serialHex+" revocation failed", "revocation failed")
		return
	}

	pkiMsg, err := buildRevResponse(msg.Header, msg.cred.secret, msg.cred.reference)
	if err != nil {
		logging.Warnf("cmp: build rp failed: %v", err)
		s.writeErrorFail(w, msg.cred, msg.Header, "revocation response encoding failed", failSystemFailure)
		return
	}
	s.emit(r.Context(), r, msg, "cmp.rr", "success", fmt.Sprintf("serial=%s reason=%d revocation_scope=%s", serialHex, d.Reason, scope))
	s.write(w, pkiMsg)
}
