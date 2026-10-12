// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// revocationHTTPHandler serves only the CRL and OCSP endpoints. CRLs and OCSP
// responses are signed by the CA, so they need no transport security, and
// RFC 5280 relying parties fetch CDP/AIA over plain HTTP. Over HTTPS the
// main listener's client-certificate request (W20-08) makes Windows' WinHTTP
// revocation fetch fail with ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED (W20-10).
// Nothing else is reachable here: no API, UI or enrollment over plaintext.
func revocationHTTPHandler(crl, ocsp http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/crl/", crl)
	mux.Handle("/ocsp", ocsp)
	mux.Handle("/ocsp/", ocsp)
	return mux
}

// startRevocationHTTP serves revocationHTTPHandler on
// KRYPTKEEPER_REVOCATION_HTTP_ADDR when it is set. It is opt-in: a hub
// without it keeps a single TLS listener.
func startRevocationHTTP(crl, ocsp http.Handler) {
	addr := strings.TrimSpace(os.Getenv("KRYPTKEEPER_REVOCATION_HTTP_ADDR"))
	if addr == "" {
		return
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           revocationHTTPHandler(crl, ocsp),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		log.Printf("revocation endpoints (CRL, OCSP) over plain HTTP on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("revocation HTTP listener stopped: %v", err)
		}
	}()
}

// revocationBaseURL is where certificates point relying parties for CRL and
// OCSP: KRYPTKEEPER_REVOCATION_BASE_URL (the plain-HTTP listener's public
// address) when set, otherwise the hub's public base URL.
func revocationBaseURL(publicBase string) string {
	if v := strings.TrimSpace(os.Getenv("KRYPTKEEPER_REVOCATION_BASE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(publicBase, "/")
}
