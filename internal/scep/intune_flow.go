// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

// Enrollment through a label in intune mode (W20-23, D-327).
//
// Order, and why:
//  1. template gate (a denial burns nothing);
//  2. Intune validateRequest: the only permission to issue. Any error, an
//     Intune refusal or an outage alike, ends in a FAILURE CertRep. No
//     failureNotification is sent for it: ref-scep-api reserves that call for
//     errors after validation, and the library does not call it for its own.
//  3. issue. Names come from the CSR, not from a minted challenge: Intune
//     returns only success or a code, and its validation is exactly the proof
//     that the CSR's subject, SANs, key usage and key length match what the
//     tenant's SCEP profile expects (SubjectNameMismatch, SubjectAltName
//     Mismatch, KeyUsageMismatch, ...). The CSR is therefore the approved
//     request. This is deliberately the reverse of the bare /scep route.
//     A failure here sends failureNotification.
//  4. record to inventory, then successNotification. The docs say a failed
//     notification means do not issue; the certificate is already signed, so
//     it is withheld from the device, revoked, and a FAILURE CertRep goes out.

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/intune"
	"kryptkeeper/internal/logging"
)

// IntuneBackend is the Intune contract; *intune.Manager implements it.
type IntuneBackend interface {
	Validate(ctx context.Context, c intune.Connection, transactionID string, csrDER []byte) error
	NotifySuccess(ctx context.Context, c intune.Connection, transactionID string, csrDER []byte, cert *x509.Certificate) error
	NotifyFailure(ctx context.Context, c intune.Connection, transactionID string, csrDER []byte, hresult int32, description string) error
}

// WithdrawFunc revokes a certificate that was signed but never handed to a
// device because Intune could not be told about it.
type WithdrawFunc func(ctx context.Context, cert *x509.Certificate) error

type ctxLabelKey struct{}

func labelFrom(ctx context.Context) *Label {
	l, _ := ctx.Value(ctxLabelKey{}).(*Label)
	return l
}

// WithLabels enables /scep/<label> routes. gateFor builds the enrollment gate
// for a label's template; without a backend every label enrollment fails
// closed.
func (s *Server) WithLabels(store LabelStore, backend IntuneBackend, gateFor func(templateID string) EnrollmentGate) *Server {
	s.labels, s.intune, s.labelGate = store, backend, gateFor
	return s
}

// WithWithdrawer wires the revocation of certificates withheld after a failed
// success notification.
func (s *Server) WithWithdrawer(fn WithdrawFunc) *Server {
	s.withdraw = fn
	return s
}

func (s *Server) denyIntune(w http.ResponseWriter, r *http.Request, caObj *ca.CA, txID string, nonce []byte, actor, reason string) {
	s.emit(r, AuditEvent{Action: "scep.enroll", Actor: actor, Outcome: "denied", Detail: reason})
	s.writeCertRep(w, caObj, txID, nonce, pkiStatusFailure, failInfoBadRequest, nil, nil)
}

func (s *Server) enrollIntune(w http.ResponseWriter, r *http.Request, caObj *ca.CA, txID string, nonce []byte, csr *x509.CertificateRequest, clientCert *x509.Certificate, l *Label) {
	actor := csr.Subject.CommonName
	prefix := "label=" + l.Label + " "
	if s.intune == nil {
		s.denyIntune(w, r, caObj, txID, nonce, actor, prefix+"Intune validation is not configured")
		return
	}
	if s.labelGate != nil {
		if gerr := s.labelGate(l.TemplateID)(r.Context(), actor); gerr != nil {
			s.denyIntune(w, r, caObj, txID, nonce, actor, prefix+"template enrollment_permissions: "+gerr.Error())
			return
		}
	}
	// Inputs the engine can carry are checked before Intune is asked, so a
	// request the hub would refuse never reaches a success notification.
	spec, err := intuneSpec(csr)
	if err != nil {
		s.denyIntune(w, r, caObj, txID, nonce, actor, prefix+err.Error())
		return
	}

	conn := intune.Connection{TenantID: l.IntuneTenantID, ClientID: l.IntuneClientID, CredentialRef: l.CredentialRef, IssuingAuthority: l.IssuingAuthority}
	if err := s.intune.Validate(r.Context(), conn, txID, csr.Raw); err != nil {
		var refused *intune.ServiceError
		reason := "intune validation unavailable: " + err.Error()
		if errors.As(err, &refused) {
			reason = "intune refused: " + refused.Code + " " + refused.Description
		}
		logging.Infof("scep intune label %s: %v", l.Label, err)
		s.denyIntune(w, r, caObj, txID, nonce, actor, prefix+reason)
		return
	}

	issued, err := s.caEngine.IssueCertificate(s.caID, ca.IssuanceRequest{
		CSR:             csr,
		Subject:         &spec.subject,
		DNSNames:        spec.dns,
		IPAddresses:     spec.ips,
		URIs:            spec.uris,
		CallerNamesOnly: true,
		Validity:        365 * 24 * time.Hour,
		KeyUsage:        spec.keyUsage,
		ExtKeyUsage:     spec.extKeyUsage,
	})
	if err != nil {
		logging.Warnf("scep intune label %s: issuance failed: %v", l.Label, err)
		detail := prefix + fmt.Sprintf("intune validated, issuance failed: %v", err)
		if nerr := s.intune.NotifyFailure(r.Context(), conn, txID, csr.Raw, intune.HResultFail, "certificate issuance failed"); nerr != nil {
			detail += "; failure notification not delivered: " + nerr.Error()
		}
		s.denyIntune(w, r, caObj, txID, nonce, actor, detail)
		return
	}

	if s.issuedRecorder != nil {
		if rerr := s.issuedRecorder.RecordIssuedCertificate(r.Context(), s.caID, issued.Certificate, issued.CertPEM, "scep"); rerr != nil {
			logging.Infof("scep: issued certificate %s not recorded: %v", issued.Fingerprint, rerr)
		}
	}
	if nerr := s.intune.NotifySuccess(r.Context(), conn, txID, csr.Raw, issued.Certificate); nerr != nil {
		detail := prefix + fmt.Sprintf("certificate %s withheld: success notification failed: %v", issued.Certificate.SerialNumber.Text(16), nerr)
		if s.withdraw == nil {
			detail += "; no revoker configured, the unreleased certificate stays valid"
		} else if werr := s.withdraw(r.Context(), issued.Certificate); werr != nil {
			detail += "; revocation failed: " + werr.Error()
		} else {
			detail += "; revoked"
		}
		s.denyIntune(w, r, caObj, txID, nonce, actor, detail)
		return
	}
	s.emit(r, AuditEvent{Action: "scep.enroll", Actor: actor, Outcome: "success",
		Detail: fmt.Sprintf("%sserial=%s subject=%q dns=%s", prefix, issued.Certificate.SerialNumber.Text(16),
			issued.Certificate.Subject.String(), strings.Join(issued.Certificate.DNSNames, ","))})
	s.writeCertRep(w, caObj, txID, nonce, pkiStatusSuccess, "", issued.Certificate, clientCert)
}

type issueSpec struct {
	subject     pkix.Name
	dns         []string
	ips         []net.IP
	uris        []*url.URL
	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
}

var (
	oidSAN      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidKU       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidEKU      = asn1.ObjectIdentifier{2, 5, 29, 37}
	ekuByOID    = map[string]x509.ExtKeyUsage{"1.3.6.1.5.5.7.3.1": x509.ExtKeyUsageServerAuth, "1.3.6.1.5.5.7.3.2": x509.ExtKeyUsageClientAuth, "1.3.6.1.5.5.7.3.4": x509.ExtKeyUsageEmailProtection}
	defaultKU   = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	forbiddenKU = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
)

// intuneSpec reads what the CSR asks for, which Intune has just proven equals
// what the tenant's profile asks for. It refuses what the engine cannot carry
// faithfully (SAN types other than DNS, IP and URI, such as UPN or email;
// unknown or powerful EKUs; CA key usages) instead of dropping it silently.
func intuneSpec(csr *x509.CertificateRequest) (issueSpec, error) {
	spec := issueSpec{subject: csr.Subject, dns: csr.DNSNames, ips: csr.IPAddresses, uris: csr.URIs,
		keyUsage: defaultKU, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	spec.subject.Names, spec.subject.ExtraNames = nil, nil
	if csr.Subject.CommonName == "" && len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.URIs) == 0 {
		return spec, errors.New("CSR carries no subject common name and no supported SAN")
	}
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(oidSAN):
			var names []asn1.RawValue
			if _, err := asn1.Unmarshal(ext.Value, &names); err != nil {
				return spec, errors.New("CSR subjectAltName does not parse")
			}
			for _, n := range names {
				if n.Class != asn1.ClassContextSpecific || (n.Tag != 2 && n.Tag != 6 && n.Tag != 7) {
					return spec, errors.New("CSR subjectAltName has a type the hub cannot issue (only DNS, IP and URI; not UPN or email)")
				}
			}
		case ext.Id.Equal(oidKU):
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &bs); err != nil {
				return spec, errors.New("CSR keyUsage does not parse")
			}
			var ku x509.KeyUsage
			for i := 0; i < 9; i++ {
				if bs.At(i) != 0 {
					ku |= 1 << uint(i)
				}
			}
			if ku == 0 || ku&forbiddenKU != 0 {
				return spec, errors.New("CSR keyUsage is empty or asks for CA usages")
			}
			spec.keyUsage = ku
		case ext.Id.Equal(oidEKU):
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil || len(oids) == 0 {
				return spec, errors.New("CSR extendedKeyUsage does not parse")
			}
			spec.extKeyUsage = nil
			for _, o := range oids {
				eku, ok := ekuByOID[o.String()]
				if !ok {
					return spec, errors.New("CSR extendedKeyUsage " + o.String() + " is not one the hub issues (serverAuth, clientAuth, emailProtection)")
				}
				spec.extKeyUsage = append(spec.extKeyUsage, eku)
			}
		}
	}
	return spec, nil
}
