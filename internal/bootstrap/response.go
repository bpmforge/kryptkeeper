// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// getOnly rejects a non-GET method before next runs at all, including before
// any auth check next performs -- fine for a route with no identity to check
// (handlers_meta.go's /, /healthz, /readyz, /api/v1/meta), but wrapping an
// AUTHENTICATED route in getOnly would answer 405+Allow to an unauthenticated
// caller and disclose which methods the route supports before it has proven
// who it is (S-31/S-32). Authenticated routes must check auth first and only
// then reject the method inline, matching handlers_cas.go's shape.
func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		next(w, r)
	}
}

func writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func writeUnauthorized(w http.ResponseWriter) {
	writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "invalid or missing bearer token")
}

func writeInvalidLoginCredentials(w http.ResponseWriter) {
	writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "invalid credentials")
}

func writeInvalidRefreshToken(w http.ResponseWriter) {
	writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "invalid refresh token")
}

func writeServiceUnavailable(w http.ResponseWriter, message string) {
	writeErrorEnvelope(w, http.StatusServiceUnavailable, "service_unavailable", message)
}

func writeNotFound(w http.ResponseWriter, message string) {
	writeErrorEnvelope(w, http.StatusNotFound, "not_found", message)
}

func writeForbidden(w http.ResponseWriter, message string) {
	writeErrorEnvelope(w, http.StatusForbidden, "forbidden", message)
}

func writeConflict(w http.ResponseWriter, message string) {
	writeErrorEnvelope(w, http.StatusConflict, "conflict", message)
}

func writeTooManyRequests(w http.ResponseWriter, message string) {
	writeErrorEnvelope(w, http.StatusTooManyRequests, "too_many_requests", message)
}

func writeBadRequest(w http.ResponseWriter, message string) {
	writeErrorEnvelope(w, http.StatusBadRequest, "bad_request", message)
}

func writeErrorEnvelope(w http.ResponseWriter, status int, code string, message string) {
	if shouldUseProblemJSON() {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		payload, _ := json.Marshal(map[string]any{
			"type":   "about:blank",
			"title":  titleForStatus(status),
			"status": status,
			"detail": message,
		})
		_, _ = w.Write(payload)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	payload, _ := json.Marshal(map[string]string{
		"error":   code,
		"message": message,
	})
	_, _ = w.Write(payload)
}

func shouldUseProblemJSON() bool {
	format := strings.TrimSpace(os.Getenv("APP_ERROR_FORMAT"))
	return strings.EqualFold(format, "problem") || strings.EqualFold(format, "rfc7807")
}

func titleForStatus(status int) string {
	if text := strings.TrimSpace(http.StatusText(status)); text != "" {
		return text
	}
	return "Error"
}
