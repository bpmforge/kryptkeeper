// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/acme"
	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/clientip"
	"kryptkeeper/internal/est"
	"kryptkeeper/internal/ratelimit"
)

const protocolRateWindow = time.Minute

// newACMEProtocolLimiter keys ACME requests by a VERIFIED account or EAB key
// id (the store lookup is what stops a client minting ids to dodge the per-IP
// limit) and everything else by client IP (W22-39).
func newACMEProtocolLimiter(store acme.Store, eabKey func(kid string) (*acme.EABKey, bool), audit bootstrap.AuditProvider) *ratelimit.ProtocolLimiter {
	perCred, unauth := bootstrap.ProtocolRateLimitsFromEnv()
	resolver := ratelimit.ACMECredentialResolver(
		func(id string) bool { _, ok := store.LoadAccount(id); return ok },
		func(kid string) bool { _, ok := eabKey(kid); return ok },
	)
	return ratelimit.NewProtocolLimiter(perCred, unauth, protocolRateWindow, resolver, throttleAuditor(audit))
}

// newESTProtocolLimiter keys EST requests by HTTP Basic user when that user is
// in the users file. EST client-certificate credentials and SCEP stay on the
// per-IP bucket (follow-up).
func newESTProtocolLimiter(audit bootstrap.AuditProvider) *ratelimit.ProtocolLimiter {
	perCred, unauth := bootstrap.ProtocolRateLimitsFromEnv()
	users := map[string]struct{}{}
	if path := strings.TrimSpace(os.Getenv(envESTUsersFile)); path != "" {
		list, err := est.LoadUsersFile(path)
		if err != nil {
			logging.Infof("est rate limit: %s unreadable, Basic users are limited per IP: %v", envESTUsersFile, err)
		}
		for _, u := range list {
			users[u.Username] = struct{}{}
		}
	}
	resolver := ratelimit.BasicUserResolver(func(name string) bool { _, ok := users[name]; return ok })
	return ratelimit.NewProtocolLimiter(perCred, unauth, protocolRateWindow, resolver, throttleAuditor(audit))
}

func throttleAuditor(audit bootstrap.AuditProvider) ratelimit.ThrottleFunc {
	ips := clientip.FromEnv()
	return func(r *http.Request, scope, key string) {
		appendProtocolAudit(r.Context(), audit, "ratelimit.throttled", "", string(bootstrap.AuditOutcomeDenied), ips.ClientIP(r), "scope="+scope+" key="+key)
	}
}
