// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
)

// itsmChannelName is the delivery channel the ITSM service registers
// (itsm.Channel.Name); this package cannot import the itsm package's channel
// without widening its dependencies, and the name is a stable wire value.
const itsmChannelName = "itsm"

// approvalPendingStore announces each newly created approval request to the
// ITSM connections routed through notification rules (W32-26). The announcement
// is "approval_pending" with the approval id, which itsm.Channel turns into a
// ticket plus an approval link (W32-12) so approving the ticket approves the
// request. It wraps the store instead of editing the three creation sites
// (certificate, SSH certificate, code signing), so every approval is covered.
type approvalPendingStore struct {
	ApprovalStore
	notifs NotificationProvider
}

// withApprovalPendingNotifier returns store unchanged when it or notifs is nil.
func withApprovalPendingNotifier(store ApprovalStore, notifs NotificationProvider) ApprovalStore {
	if store == nil || notifs == nil {
		return store
	}
	return &approvalPendingStore{ApprovalStore: store, notifs: notifs}
}

// Unwrap returns the underlying store (delegationStoreForApprovals type-switches on it).
func (s *approvalPendingStore) Unwrap() ApprovalStore { return s.ApprovalStore }

// Create stores the request, then announces it. The announcement is best
// effort: a notification failure never fails or undoes the request.
func (s *approvalPendingStore) Create(ctx context.Context, req ApprovalRequest) error {
	if err := s.ApprovalStore.Create(ctx, req); err != nil {
		return err
	}
	announceApprovalPending(ctx, s.notifs, req)
	return nil
}

// announceApprovalPending sends one itsm message per enabled itsm rule whose
// tenant may see the request (a connection never receives another tenant's approvals).
func announceApprovalPending(ctx context.Context, notifs NotificationProvider, req ApprovalRequest) {
	announceITSM(ctx, notifs, "approval "+req.ID,
		func(ruleTenant string) bool {
			return approvalVisibleToTenant(ctx, activeTenantStore, AuthPrincipal{Tenant: chatopsTenant(ruleTenant)}, req)
		},
		func() string { return approvalPendingMessage(req) })
}

// approvalPendingMessage is the JSON itsm.Channel.Send reads. The fingerprint
// is per approval, so a later resolve-by-fingerprint cannot close it by accident.
func approvalPendingMessage(req ApprovalRequest) string {
	link := "/approvals"
	if base := strings.TrimRight(strings.TrimSpace(os.Getenv("KRYPTKEEPER_BASE_URL")), "/"); base != "" {
		link = base + "/approvals"
	}
	b, _ := json.Marshal(map[string]string{
		"class":       "approval_pending",
		"cn":          approvalSubject(req),
		"deep_link":   link,
		"fingerprint": "approval:" + req.ID,
		"approval_id": req.ID,
	})
	return string(b)
}

func approvalSubject(req ApprovalRequest) string {
	if blk, _ := pem.Decode([]byte(req.CSRPEM)); blk != nil {
		if csr, err := x509.ParseCertificateRequest(blk.Bytes); err == nil && csr.Subject.CommonName != "" {
			return csr.Subject.CommonName
		}
	}
	if req.SSHRequest != nil && req.SSHRequest.KeyID != "" {
		return req.SSHRequest.KeyID
	}
	return "approval request " + req.ID
}
