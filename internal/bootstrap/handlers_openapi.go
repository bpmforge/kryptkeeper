// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"

	"kryptkeeper/docs"
)

// registerOpenAPIHandlers serves the embedded docs/openapi.yaml. The route is
// unauthenticated, read-only and not audited (UC-K01): the spec is already a
// public contract and carries no secrets.
func registerOpenAPIHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/openapi.yaml", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(docs.OpenAPI)
	}))
}
