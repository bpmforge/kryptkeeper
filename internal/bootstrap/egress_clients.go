// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/x509"
	"net/http"
	"time"

	"kryptkeeper/internal/egress"
)

// egressAllowLoopback is a test seam: production never sets it, so operator
// configured URLs cannot reach 127.0.0.0/8 or ::1.
var egressAllowLoopback bool

// inventoryHTTPClient is the client for inventory-source fetches
// (SEMGREP-002). base_url is operator-configurable and the stored credential
// rides on every request as a custom header, which net/http would replay on a
// cross-host redirect — so cross-host redirects are refused outright. Private
// space is reachable (internal vendor appliances) unless
// KRYPTKEEPER_EGRESS_DENY_PRIVATE=true; link-local/metadata never is.
func inventoryHTTPClient(timeout time.Duration) *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:          true,
		AllowLoopback:         egressAllowLoopback,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               timeout,
	}))
}

// upstreamConnectorHTTPClient is the client for the DigiCert, SCEP, EST and
// WSTEP issuer connectors (W27-35). Same redirect policy as
// inventoryHTTPClient: the credential rides on every request, so a cross-host
// redirect would replay it elsewhere and is refused. A credentialed connector
// (DigiCert API key, EST/WSTEP Basic auth) also refuses plain http, which
// would put the secret on the wire in clear; SCEP carries no credential and
// is commonly served over http (RFC 8894), so it may use either.
func upstreamConnectorHTTPClient(timeout time.Duration, credentialed bool) *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:          true,
		AllowLoopback:         egressAllowLoopback,
		RequireHTTPS:          credentialed && !upstreamAllowPlainHTTP,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               timeout,
	}))
}

// upstreamAllowPlainHTTP is a test seam (httptest stubs are plain http);
// production never sets it.
var upstreamAllowPlainHTTP bool

// pushDeviceHTTPClient is the default client for hub-side pushes to F5,
// Citrix, Kubernetes and plugin-delivery devices. base_url comes from an
// admin-authored credential, so the push must not be able to reach cloud
// metadata or send the credential and private key over plain http: https is
// required (relaxed only by the egressAllowLoopback test seam), proxies are
// ignored, and redirects are refused. roots, when non-nil, replaces the
// system roots (management planes behind an internal CA).
func pushDeviceHTTPClient(roots *x509.CertPool) *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:  true, // management planes live on private space
		AllowLoopback: egressAllowLoopback,
		RequireHTTPS:  !egressAllowLoopback,
		MaxRedirects:  0,
		Timeout:       60 * time.Second,
		RootCAs:       roots,
	}))
}
