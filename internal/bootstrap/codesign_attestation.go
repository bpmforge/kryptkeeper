// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"strings"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/attestation"
	"kryptkeeper/internal/ca"
)

const (
	auditCodesignAttestVerify = "codesign.attestation.verify"
	codesignAttestActorID     = "codesign-attestation"
	codesignAttestTimeout     = 5 * time.Second
)

// CodesignAttestation is the verified attestation stored for a CSR.
type CodesignAttestation struct {
	CSRSHA256        string   `json:"csr_sha256"`
	TemplateID       string   `json:"template_id"`
	Format           string   `json:"format"`
	Serial           string   `json:"serial,omitempty"`
	Firmware         string   `json:"firmware,omitempty"`
	KeySPKISHA256    string   `json:"key_spki_sha256"`
	AttestationPEM   string   `json:"attestation_pem"`
	IntermediatesPEM []string `json:"intermediates_pem,omitempty"`
	VendorRootSHA256 string   `json:"vendor_root_sha256"`
	VerifiedAt       string   `json:"verified_at"`
}

type codesignAttestationStore struct {
	db *sql.DB
	ph func(int) string
}

func codesignAttestationStoreForApprovals(s ApprovalStore) *codesignAttestationStore {
	switch v := s.(type) {
	case *sqliteApprovalStore:
		if v != nil {
			return &codesignAttestationStore{db: v.db, ph: sqlitePlaceholder}
		}
	case *postgresApprovalStore:
		if v != nil {
			return &codesignAttestationStore{db: v.db, ph: postgresPlaceholder}
		}
	}
	return nil
}

func (s *codesignAttestationStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, codesignAttestationSchema)
	return err
}

func (s *codesignAttestationStore) Upsert(ctx context.Context, a CodesignAttestation) error {
	inter, err := json.Marshal(a.IntermediatesPEM)
	if err != nil {
		return err
	}
	q := fmt.Sprintf(`INSERT INTO codesign_attestations
		(csr_sha256, template_id, format, serial, firmware, key_spki_sha256, attestation_pem, intermediates_pem, vendor_root_sha256, verified_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
		ON CONFLICT (csr_sha256) DO UPDATE SET template_id = excluded.template_id, format = excluded.format,
		serial = excluded.serial, firmware = excluded.firmware, key_spki_sha256 = excluded.key_spki_sha256,
		attestation_pem = excluded.attestation_pem, intermediates_pem = excluded.intermediates_pem,
		vendor_root_sha256 = excluded.vendor_root_sha256, verified_at = excluded.verified_at`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10))
	_, err = s.db.ExecContext(ctx, q, a.CSRSHA256, a.TemplateID, a.Format, a.Serial, a.Firmware,
		a.KeySPKISHA256, a.AttestationPEM, string(inter), a.VendorRootSHA256, a.VerifiedAt)
	return err
}

func (s *codesignAttestationStore) Get(ctx context.Context, csrSHA string) (CodesignAttestation, bool, error) {
	var a CodesignAttestation
	var serial, fw, inter sql.NullString
	err := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT csr_sha256, template_id, format, serial, firmware,
		key_spki_sha256, attestation_pem, intermediates_pem, vendor_root_sha256, verified_at
		FROM codesign_attestations WHERE csr_sha256 = %s`, s.ph(1)), csrSHA).
		Scan(&a.CSRSHA256, &a.TemplateID, &a.Format, &serial, &fw, &a.KeySPKISHA256, &a.AttestationPEM, &inter, &a.VendorRootSHA256, &a.VerifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CodesignAttestation{}, false, nil
	}
	if err != nil {
		return CodesignAttestation{}, false, err
	}
	a.Serial, a.Firmware = serial.String, fw.String
	if inter.Valid && inter.String != "" {
		if err := json.Unmarshal([]byte(inter.String), &a.IntermediatesPEM); err != nil {
			return CodesignAttestation{}, false, err
		}
	}
	return a, true, nil
}

// Process-wide singleton, like activeBreakGlassPtr: IssueCertificate has no
// handle on the approval store, and the check must run inside it.
var (
	codesignAttestStorePtr atomic.Pointer[codesignAttestationStore]
	codesignAuditPtr       atomic.Pointer[AuditProvider]
	// codesignVerifier is set at init and replaced by tests.
	codesignVerifier *attestation.Verifier
)

// codesignHubKeyKey marks an issuance whose key was generated and is held by
// the hub itself (the W26-22 flow); there is no requester key to attest.
type codesignHubKeyKey struct{}

// initCodesignAttestation wires the store and verifier. A failure leaves the
// store nil, which fails closed in protected mode.
func initCodesignAttestation(approvals ApprovalStore, audit AuditProvider) {
	codesignAuditPtr.Store(&audit)
	v, err := attestation.NewVerifier()
	if err != nil {
		logging.Infof("codesign attestation: loading vendor roots: %v", err)
		v = &attestation.Verifier{}
	}
	codesignVerifier = v
	st := codesignAttestationStoreForApprovals(approvals)
	if st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), codesignAttestTimeout)
	defer cancel()
	if err := st.EnsureSchema(ctx); err != nil {
		logging.Infof("codesign attestation: schema: %v", err)
		return
	}
	codesignAttestStorePtr.Store(st)
}

func csrDigest(csrPEM string) string {
	h := sha256.Sum256([]byte(csrPEM))
	return hex.EncodeToString(h[:])
}

// LookupCodesignAttestation returns the stored attestation for a CSR PEM.
func LookupCodesignAttestation(ctx context.Context, csrPEM string) (CodesignAttestation, bool, error) {
	st := codesignAttestStorePtr.Load()
	if st == nil {
		return CodesignAttestation{}, false, errors.New("codesign attestation store unavailable")
	}
	return st.Get(ctx, csrDigest(csrPEM))
}

func codesignAttestAudit(ctx context.Context, action string, outcome AuditOutcome, templateID, summary string) {
	p := codesignAuditPtr.Load()
	if p == nil || *p == nil {
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditAppendTimeout)
	defer cancel()
	err := (*p).AppendEntry(actx, AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action,
		ActorType: "system", ActorID: codesignAttestActorID,
		ResourceType: codesignResourceType, ResourceID: templateID,
		Outcome: outcome, ChangeSummary: summary,
	})
	if err != nil {
		logging.Errorf("audit append failed action=%s resource_id=%s: %v", action, templateID, err)
	}
}

func codesignAttestRefuse(ctx context.Context, tplID, reason string) error {
	summary, _ := json.Marshal(map[string]string{"reason": reason})
	codesignAttestAudit(ctx, auditCodesignDeny, AuditOutcomeDenied, tplID, string(summary))
	return fmt.Errorf("%w: attestation: %s", ca.ErrPolicyViolation, reason)
}

// codesignPreIssueCheck refuses, in protected mode, a code-signing CSR that
// lacks a valid hardware attestation of its own public key (FR-P92). It runs
// before the approval gate so a refused request is never queued.
func codesignPreIssueCheck(ctx context.Context, tpl TemplateItem, req CertificateIssueRequest) error {
	if !codesignProtectedMode() || !templateHasCodeSigningEKU(tpl) || ctx.Value(codesignHubKeyKey{}) != nil {
		return nil
	}
	blk, _ := pem.Decode([]byte(req.CSRPEM))
	if blk == nil {
		return codesignAttestRefuse(ctx, tpl.ID, "attestation_invalid")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return codesignAttestRefuse(ctx, tpl.ID, "attestation_invalid")
	}
	raw, present := req.Metadata["attestation"]
	if !present || raw == nil {
		return codesignAttestRefuse(ctx, tpl.ID, "attestation_missing")
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return codesignAttestRefuse(ctx, tpl.ID, "attestation_invalid")
	}
	if format, _ := m["format"].(string); format != attestation.FormatYubiKeyPIV {
		return codesignAttestRefuse(ctx, tpl.ID, "unsupported_format")
	}
	certPEM, ok := m["certificate_pem"].(string)
	if !ok {
		return codesignAttestRefuse(ctx, tpl.ID, "attestation_invalid")
	}
	var inter []string
	if rawInter, present := m["intermediates_pem"]; present && rawInter != nil {
		list, ok := rawInter.([]interface{})
		if !ok {
			return codesignAttestRefuse(ctx, tpl.ID, "attestation_invalid")
		}
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return codesignAttestRefuse(ctx, tpl.ID, "attestation_invalid")
			}
			inter = append(inter, s)
		}
	}
	st := codesignAttestStorePtr.Load()
	v := codesignVerifier
	if st == nil || v == nil {
		return codesignAttestRefuse(ctx, tpl.ID, "attestation_store_unavailable")
	}
	res, err := v.VerifyYubiKeyPIV(certPEM, inter, csr.PublicKey)
	switch {
	case errors.Is(err, attestation.ErrKeyMismatch):
		return codesignAttestRefuse(ctx, tpl.ID, "key_mismatch")
	case err != nil:
		return codesignAttestRefuse(ctx, tpl.ID, "attestation_invalid")
	}
	rec := CodesignAttestation{
		CSRSHA256: csrDigest(req.CSRPEM), TemplateID: tpl.ID, Format: res.Format, Serial: res.Serial,
		Firmware: res.Firmware, KeySPKISHA256: res.KeySPKISHA256, AttestationPEM: strings.TrimSpace(certPEM),
		IntermediatesPEM: inter, VendorRootSHA256: res.VendorRootSHA256, VerifiedAt: res.VerifiedAt.Format(time.RFC3339),
	}
	if err := st.Upsert(ctx, rec); err != nil {
		logging.Infof("codesign attestation: store: %v", err)
		return codesignAttestRefuse(ctx, tpl.ID, "attestation_store_unavailable")
	}
	summary, _ := json.Marshal(map[string]string{"serial": res.Serial, "key_spki_sha256": res.KeySPKISHA256, "vendor_root_sha256": res.VendorRootSHA256})
	codesignAttestAudit(ctx, auditCodesignAttestVerify, AuditOutcomeSuccess, tpl.ID, string(summary))
	return nil
}
