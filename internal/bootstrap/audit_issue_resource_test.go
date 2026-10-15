// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

type issueStubProvider struct {
	CertificateProvider
	result CertificateIssueResult
	err    error
}

func (p issueStubProvider) IssueCertificate(context.Context, CertificateIssueRequest) (CertificateIssueResult, error) {
	return p.result, p.err
}

type createApprovalStore struct {
	ApprovalStore
	created []ApprovalRequest
}

func (s *createApprovalStore) Create(_ context.Context, a ApprovalRequest) error {
	s.created = append(s.created, a)
	return nil
}

func issueAndCollect(t *testing.T, p issueStubProvider, store ApprovalStore) (int, []AuditEntry) {
	t.Helper()
	mux := http.NewServeMux()
	h := newWriteGateHarness(t, mux)
	registerCertificateHandlers(mux, h.auth, p, h.audit, store)
	body := `{"ca_id":"ca-1","template_id":"tpl-1","csr_pem":"x","team_id":"t"}`
	rec := h.do(h.key(t, "pki-admin"), http.MethodPost, "/api/v1/certificates", []byte(body))
	return rec.Code, h.audit.entries
}

// A successful issue names the issued certificate by fingerprint, never the
// collection.
func TestIssueAuditReferencesIssuedFingerprint(t *testing.T) {
	code, rows := issueAndCollect(t, issueStubProvider{result: CertificateIssueResult{CertificateItem{FingerprintSHA256: "fp-new", CommonName: "n.example.com"}}}, nil)
	if code != http.StatusCreated {
		t.Fatalf("status %d", code)
	}
	var found bool
	for _, e := range rows {
		if e.Action == "certificate.issue" && e.Outcome == AuditOutcomeSuccess {
			found = true
			if e.ResourceID != "fp-new" {
				t.Errorf("resource_id = %q, want the issued fingerprint", e.ResourceID)
			}
		}
	}
	if !found {
		t.Fatalf("no success row: %+v", rows)
	}
}

// Before a certificate exists the row keeps the collection name; a pending
// approval additionally records the approval ID so the row is traceable.
func TestIssueAuditPendingApprovalCarriesApprovalID(t *testing.T) {
	store := &createApprovalStore{}
	code, rows := issueAndCollect(t, issueStubProvider{err: errApprovalRequired}, store)
	if code != http.StatusAccepted || len(store.created) != 1 {
		t.Fatalf("status %d, approvals %d", code, len(store.created))
	}
	for _, e := range rows {
		if e.Action == "certificate.issue" && e.Outcome == AuditOutcomePendingApproval {
			if e.ResourceID != "certificates" {
				t.Errorf("resource_id = %q", e.ResourceID)
			}
			if !strings.Contains(e.ChangeSummary, store.created[0].ID) {
				t.Errorf("summary %q lacks approval id %q", e.ChangeSummary, store.created[0].ID)
			}
			return
		}
	}
	t.Fatalf("no pending_approval row: %+v", rows)
}
