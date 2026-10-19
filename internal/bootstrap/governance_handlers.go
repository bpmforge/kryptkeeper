// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "net/http"

// registerGovernanceHandlers is the single mount point for the access
// governance surface (access review, recertification, break-glass). New
// governance routes append here so server.go keeps one call site per entry
// point.
func registerGovernanceHandlers(mux *http.ServeMux, auth *Authenticator, auditProvider AuditProvider) {
	registerAccessReviewReportHandler(mux, auth, accessReviewUsers(auth), accessReviewRoles(auth), auditProvider,
		newOutboundCredentialStoreFromEnv(), NewManagedTargetStoreFromEnv())
	registerAccessReviewCampaignHandlers(mux, auth, accessReviewUsers(auth), accessReviewRoles(auth), newAccessReviewStoreFromEnv(), auditProvider)
	registerBreakGlassHandlers(mux, auth, accessReviewUsers(auth), auditProvider)
}
