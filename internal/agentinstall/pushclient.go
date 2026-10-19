// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"crypto/x509"
	"net/http"
	"time"

	"kryptkeeper/internal/egress"
)

// pushAllowLoopback is a test seam (httptest TLS servers listen on
// loopback); production never sets it.
var pushAllowLoopback bool

// guardedPushClient is the default client for the F5/Citrix/Kubernetes
// pushers when the caller supplies none. BaseURL is credential-supplied, so
// the stdlib default client (proxies from the environment, redirects followed,
// any address, plain http) is not acceptable: the push carries a private key
// and device credentials. https is required, the dialled address is checked
// after DNS resolution (link-local/metadata always refused), and redirects
// are refused. Private space stays reachable: management planes live there.
func guardedPushClient(roots *x509.CertPool) *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:  true,
		AllowLoopback: pushAllowLoopback,
		RequireHTTPS:  true,
		MaxRedirects:  0,
		Timeout:       60 * time.Second,
		RootCAs:       roots,
	}))
}
