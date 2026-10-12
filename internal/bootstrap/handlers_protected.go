// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "net/http"

func registerProtectedHandlers(mux *http.ServeMux, auth *Authenticator, certSummaryProvider CertSummaryProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/protected/ping", registerProtectedPingHandler(auth, auditProvider))
	mux.HandleFunc("/api/v1/protected/whoami", registerProtectedWhoamiHandler(auth, auditProvider))
	mux.HandleFunc("/api/v1/protected/config", registerProtectedConfigHandler(auth, auditProvider))
	mux.HandleFunc("/api/v1/protected/certs/summary", registerProtectedCertsSummaryHandler(auth, certSummaryProvider, auditProvider))
}
