// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"strings"

	"kryptkeeper/internal/clientip"
)

// requestIsSecure reports whether the browser-facing connection is TLS: the
// hub's own listener (r.TLS) or a trusted proxy (APP_TRUSTED_PROXY_CIDRS)
// that terminated TLS and said so. X-Forwarded-Proto from any other peer is
// client-controlled and ignored, and a TLS listener is always secure whatever
// a proxy header claims (OWASP-004 / A02-1).
func requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !clientip.FromEnv().PeerTrusted(r.RemoteAddr) {
		return false
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// setNoStore marks a response that carries a credential, token or key
// material as uncacheable by browsers and intermediaries (A02-6).
func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// withSecurityHeaders applies the baseline response headers to every hub
// response and no-store to the whole /api/ surface: login, refresh, api-key
// create, key export/escrow/backup, SPIFFE and agent enrolment all return
// secrets, and no API response is meant to be cached. A handler that needs a
// different Cache-Control (SSE) sets it after this runs, so its value wins.
// CRL and OCSP live outside /api/ and keep their own max-age.
//
// The hub serves no HTML, so frame-ancestors 'none' is the whole CSP; the
// dashboard's own headers live in nginx.conf.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		if requestIsSecure(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			setNoStore(w)
		}
		next.ServeHTTP(w, r)
	})
}
