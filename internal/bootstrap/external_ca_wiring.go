// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/logging"
)

// wireExternalCA connects the three pieces an external CA needs at runtime
// (W36): the issuer bridge the engine signs through, the audit record for a
// refused upstream response, and the upstream revoker the certificate store
// calls. Each hook is an optional capability, so a provider that cannot hold
// external CAs is skipped, as before.
func wireExternalCA(caProvider CAProvider, certificateProvider CertificateProvider, store ConnectorStore, creds OutboundCredentialStore, tenants TenantStore, audit AuditProvider) {
	if store == nil {
		return
	}
	if s, ok := caProvider.(interface{ SetExternalIssuer(ca.ExternalIssuer) }); ok {
		s.SetExternalIssuer(NewExternalCAIssuer(store, certificateProvider, creds, tenants))
	}
	if s, ok := caProvider.(interface {
		SetExternalRejectionObserver(ca.ExternalRejectionObserver)
	}); ok {
		s.SetExternalRejectionObserver(newExternalRejectionAuditor(audit))
	}
	if s, ok := certificateProvider.(interface{ SetUpstreamRevoker(UpstreamRevoker) }); ok {
		s.SetUpstreamRevoker(NewConnectorRevoker(store, certificateProvider, creds))
	}
}

// newExternalRejectionAuditor writes certificate.issue.upstream_rejected when
// an upstream CA returns a certificate that does not match the request. The
// engine calls it with no HTTP request in hand, so the row is a system entry;
// the failed issue itself is audited by the handler under the caller's name.
func newExternalRejectionAuditor(audit AuditProvider) ca.ExternalRejectionObserver {
	return func(caID, connectorID string, rej *ca.ExternalRejection) {
		if audit == nil || rej == nil {
			return
		}
		detail, _ := json.Marshal(map[string]string{
			"ca_id":        caID,
			"connector_id": connectorID,
			"reason":       rej.Reason,
			"fingerprint":  rej.Fingerprint,
		})
		ctx, cancel := context.WithTimeout(context.Background(), auditAppendTimeout)
		defer cancel()
		if err := audit.AppendEntry(ctx, AuditEntry{
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			Action:        "certificate.issue.upstream_rejected",
			ActorType:     "system",
			ActorID:       "external-ca:" + caID,
			ResourceType:  "certificate",
			ResourceID:    rej.Fingerprint,
			Outcome:       AuditOutcomeFailure,
			ChangeSummary: string(detail),
			Tenant:        DefaultTenant,
		}); err != nil {
			logging.Errorf("audit append failed action=certificate.issue.upstream_rejected ca_id=%s: %v", caID, err)
		}
	}
}
