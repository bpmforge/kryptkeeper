// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// maxBulkRevoke caps a single bulk-revoke action (matches the bulk-op API caps).
const maxBulkRevoke = 500

// revokeParams is the payload for a "revoke" pending action.
type revokeParams struct {
	Fingerprint string `json:"fingerprint"`
	ReasonCode  int    `json:"reason_code"`
	ReasonText  string `json:"reason_text"`
}

// bulkRevokeParams is the payload for a "bulk_revoke" pending action (e.g. revoke
// everything a compromised CA signed).
type bulkRevokeParams struct {
	CAID       string `json:"ca_id"`
	ReasonCode int    `json:"reason_code"`
	ReasonText string `json:"reason_text"`
}

// executePendingAction performs an approved action via the certificate provider
// and returns a JSON result. Unknown or malformed actions return an error so the
// action is recorded as failed, never silently dropped.
func executePendingAction(ctx context.Context, certProvider CertificateProvider, action PendingAction) (json.RawMessage, error) {
	switch action.ActionType {
	case "revoke":
		var p revokeParams
		if err := json.Unmarshal(action.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid revoke params: %w", err)
		}
		if p.Fingerprint == "" {
			return nil, fmt.Errorf("revoke: fingerprint required")
		}
		res, err := certProvider.RevokeCertificate(ctx, p.Fingerprint, CertificateRevokeRequest{
			ReasonCode: p.ReasonCode, ReasonText: p.ReasonText,
		})
		if err != nil {
			return nil, fmt.Errorf("revoke %s: %w", p.Fingerprint, err)
		}
		return json.Marshal(map[string]any{"revoked": 1, "fingerprint": res.FingerprintSHA256})

	case "bulk_revoke":
		var p bulkRevokeParams
		if err := json.Unmarshal(action.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid bulk_revoke params: %w", err)
		}
		if p.CAID == "" {
			return nil, fmt.Errorf("bulk_revoke: ca_id required")
		}
		list, err := listAllCertificates(ctx, certProvider, CertificateListQuery{CAID: p.CAID})
		if err != nil {
			return nil, fmt.Errorf("bulk_revoke: list certs: %w", err)
		}
		revoked, failed, active := 0, 0, 0
		var firstErr string
		for _, c := range list.Items {
			if c.RevokedAt != nil {
				continue
			}
			// The ceiling bounds one approved action's blast radius; the rest
			// is reported below (truncated_at/total_matched) so the approver
			// sees a partial revoke rather than assuming a complete one.
			active++
			if active > maxBulkRevoke {
				continue
			}
			if _, err := certProvider.RevokeCertificate(ctx, c.FingerprintSHA256, CertificateRevokeRequest{
				ReasonCode: p.ReasonCode, ReasonText: p.ReasonText,
			}); err != nil {
				failed++
				if firstErr == "" {
					firstErr = err.Error()
				}
				continue
			}
			revoked++
		}
		result := map[string]any{"revoked": revoked, "failed": failed, "ca_id": p.CAID}
		if active > maxBulkRevoke {
			result["truncated_at"] = maxBulkRevoke
			result["total_matched"] = active
		}
		if firstErr != "" {
			result["first_error"] = firstErr
		}
		return json.Marshal(result)

	case "issue":
		var p issueParams
		if err := json.Unmarshal(action.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid issue params: %w", err)
		}
		if p.CAID == "" || p.CSRPEM == "" {
			return nil, fmt.Errorf("issue: ca_id and csr_pem required")
		}
		res, err := certProvider.IssueCertificate(ctx, CertificateIssueRequest{
			CAID: p.CAID, TemplateID: p.TemplateID, CSRPEM: p.CSRPEM, TeamID: p.TeamID,
		})
		if err != nil {
			return nil, fmt.Errorf("issue: %w", err)
		}
		return json.Marshal(map[string]any{"issued": res.FingerprintSHA256})

	case "renew":
		var p renewParams
		if err := json.Unmarshal(action.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid renew params: %w", err)
		}
		if p.Fingerprint == "" || p.CSRPEM == "" {
			return nil, fmt.Errorf("renew: fingerprint and csr_pem required")
		}
		res, err := certProvider.RenewCertificate(ctx, p.Fingerprint, CertificateRenewRequest{CSRPEM: p.CSRPEM})
		if err != nil {
			return nil, fmt.Errorf("renew %s: %w", p.Fingerprint, err)
		}
		return json.Marshal(map[string]any{"renewed": p.Fingerprint, "successor": res.FingerprintSHA256})

	case "rotate":
		var p renewParams
		if err := json.Unmarshal(action.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid rotate params: %w", err)
		}
		if p.Fingerprint == "" || p.CSRPEM == "" {
			return nil, fmt.Errorf("rotate: fingerprint and csr_pem required")
		}
		// W5-06: rotation's guarantee is a NEW key. A CSR reusing the
		// predecessor's key is a renewal wearing a costume — refuse it
		// rather than record a rotation that rotated nothing.
		if err := refuseSameKeyRotation(ctx, certProvider, p.Fingerprint, p.CSRPEM); err != nil {
			return nil, err
		}
		res, err := certProvider.RenewCertificate(ctx, p.Fingerprint, CertificateRenewRequest{CSRPEM: p.CSRPEM})
		if err != nil {
			return nil, fmt.Errorf("rotate %s: %w", p.Fingerprint, err)
		}
		return json.Marshal(map[string]any{"rotated": p.Fingerprint, "successor": res.FingerprintSHA256})

	default:
		return nil, fmt.Errorf("unknown action type %q", action.ActionType)
	}
}

// issueParams is the payload for an "issue" pending action.
type issueParams struct {
	CAID       string `json:"ca_id"`
	TemplateID string `json:"template_id"`
	CSRPEM     string `json:"csr_pem"`
	TeamID     string `json:"team_id"`
}

// renewParams serves both "renew" and "rotate".
type renewParams struct {
	Fingerprint string `json:"fingerprint"`
	CSRPEM      string `json:"csr_pem"`
}

// refuseSameKeyRotation compares the CSR's public key against the
// predecessor certificate's (SPKI bytes) and refuses a match.
func refuseSameKeyRotation(ctx context.Context, certProvider CertificateProvider, fingerprint, csrPEM string) error {
	dl, err := certProvider.DownloadCertificate(ctx, fingerprint, "pem", false)
	if err != nil {
		return fmt.Errorf("rotate %s: load predecessor: %w", fingerprint, err)
	}
	certBlock, _ := pem.Decode(dl.Body)
	if certBlock == nil {
		return fmt.Errorf("rotate %s: predecessor is not PEM", fingerprint)
	}
	oldCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("rotate %s: parse predecessor: %w", fingerprint, err)
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		return fmt.Errorf("rotate %s: csr is not PEM", fingerprint)
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("rotate %s: parse csr: %w", fingerprint, err)
	}
	if bytes.Equal(oldCert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("rotate %s: the CSR reuses the predecessor's public key — rotation requires a NEW key (use renew to keep it)", fingerprint)
	}
	return nil
}

// validActionType reports whether t is an executable action type.
func validActionType(t string) bool {
	switch t {
	case "revoke", "bulk_revoke", "issue", "renew", "rotate":
		return true
	}
	return false
}
