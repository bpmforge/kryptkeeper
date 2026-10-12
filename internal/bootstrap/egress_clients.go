// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
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
