// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/est"
)

const (
	envESTUsersFile    = "KRYPTKEEPER_EST_USERS_FILE"
	envESTClientCAFile = "KRYPTKEEPER_EST_CLIENT_CA_FILE"
)

// configureESTAuth turns on the EST credential types the environment
// configures (W20-14, D-112) and says, in one log line each, what is live
// and why anything is not. With neither configured, enrollment stays off;
// cacerts and csrattrs are served regardless.
func configureESTAuth(srv *est.Server, rev ca.RevocationChecker, audit bootstrap.AuditProvider) {
	srv.WithAuditFunc(func(ctx context.Context, ev est.AuditEvent) {
		appendProtocolAudit(ctx, audit, ev.Action, ev.Actor, ev.Outcome, ev.SourceIP, ev.Detail)
	})
	clientCerts := requestClientCertFromEnv()
	var live []string

	if path := strings.TrimSpace(os.Getenv(envESTUsersFile)); path != "" {
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
			log.Printf("est: %s is readable by group/other (mode %v); restrict it to 0600", path, fi.Mode().Perm())
		}
		users, err := est.LoadUsersFile(path)
		if err == nil {
			err = srv.WithBasicUsers(users)
		}
		if err != nil {
			log.Printf("EST HTTP Basic disabled: %s: %v", envESTUsersFile, err)
		} else {
			live = append(live, fmt.Sprintf("HTTP Basic (%d users)", len(users)))
		}
	}

	if path := strings.TrimSpace(os.Getenv(envESTClientCAFile)); path != "" {
		raw, err := os.ReadFile(path)
		pool := x509.NewCertPool()
		switch {
		case err != nil:
			log.Printf("EST client-certificate enrollment disabled: %s: %v", envESTClientCAFile, err)
		case !pool.AppendCertsFromPEM(raw):
			log.Printf("EST client-certificate enrollment disabled: %s holds no PEM certificates", envESTClientCAFile)
		case !clientCerts:
			log.Printf("EST client-certificate enrollment disabled: %s is set but KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT is not true, so no client certificate can arrive", envESTClientCAFile)
		default:
			srv.WithClientCertAnchors(pool)
			live = append(live, "client certificate")
		}
	}

	switch {
	case rev == nil:
		log.Print("EST re-enrollment disabled: no revocation store")
	case !clientCerts:
		log.Print("EST re-enrollment disabled: it needs the hub-issued client certificate, and KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT is not true")
	default:
		srv.WithReenrollment(rev)
		live = append(live, "re-enrollment by hub-issued certificate")
	}

	if !srv.EnrollmentConfigured() {
		log.Printf("EST enrollment disabled: set %s and/or %s (W20-14); cacerts and csrattrs are still served", envESTUsersFile, envESTClientCAFile)
		return
	}
	log.Printf("EST enrollment: %s", strings.Join(live, ", "))
}
