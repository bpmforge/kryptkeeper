// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"math/big"
	"net/http"
	"os"
	"strings"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/scep"
)

const envSCEPLegacyChallenge = "KRYPTKEEPER_SCEP_CHALLENGE"

// scepDisabledReason says why SCEP enrollment stays off, or "" when it may
// run (W20-16, D-121). A static shared challenge is no longer honoured, and
// its variable still being set keeps SCEP off rather than quietly changing
// how devices authenticate.
func scepDisabledReason(legacyChallenge string, enabled bool, haveDB bool) string {
	switch {
	case strings.TrimSpace(legacyChallenge) != "":
		return envSCEPLegacyChallenge + " (one static shared challenge) is no longer supported (W20-16); unset it, set KRYPTKEEPER_SCEP_ENABLED=true, and mint one-time challenges with POST /api/v1/scep/challenges"
	case !enabled:
		return "set KRYPTKEEPER_SCEP_ENABLED=true to enable; devices then enroll with one-time challenges from POST /api/v1/scep/challenges"
	case !haveDB:
		return "one-time challenges need the hub database, and none is configured"
	}
	return ""
}

// scepNotRSAReason explains why SCEP stays off on a non-RSA CA: the PKIOperation
// envelope key-wraps the CSR to the CA's public key and only RSA can unwrap it.
func scepNotRSAReason(caID string) string {
	return "CA " + caID + " does not have an RSA key, and SCEP's PKCS#7 envelope requires one (an ECDSA or Ed25519 CA cannot serve SCEP). " +
		"Create an RSA CA and set KRYPTKEEPER_SCEP_CA_ID to its id, then restart the hub"
}

// scepSetup is SCEP's decision for this process: why it is off, or the
// challenge store it shares with the API.
func scepSetup(coreDB *sql.DB, isPostgres bool) (*scep.DBChallengeStore, string) {
	if reason := scepDisabledReason(os.Getenv(envSCEPLegacyChallenge), bootstrap.SCEPEnabledFromEnv(), coreDB != nil); reason != "" {
		return nil, reason
	}
	return scep.NewDBChallengeStore(coreDB, isPostgres), ""
}

// configureSCEPAudit sends SCEP enrollment outcomes to the hub audit log.
func configureSCEPAudit(srv *scep.Server, audit bootstrap.AuditProvider) {
	srv.WithAuditFunc(func(ctx context.Context, ev scep.AuditEvent) {
		appendProtocolAudit(ctx, audit, ev.Action, ev.Actor, ev.Outcome, ev.SourceIP, ev.Detail)
	})
}

// configureSCEPRenewal gives SCEP renewal (W26-30) the revocation lookup it
// requires. With no store nothing is wired and the server refuses every
// renewal (fail closed).
func configureSCEPRenewal(srv *scep.Server, rev ca.RevocationChecker, caID string) {
	if rev == nil {
		return
	}
	srv.WithRevocationChecker(func(serial *big.Int) (bool, error) {
		revoked, _, _, err := rev.IsRevoked(serial, caID)
		return revoked, err
	})
}

// scepChallengeOption mounts the challenge API when SCEP runs.
func scepChallengeOption(auth *bootstrap.Authenticator, store *scep.DBChallengeStore, caID string, audit bootstrap.AuditProvider) bootstrap.ServerOption {
	if store == nil {
		return nil
	}
	return bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterSCEPChallengeHandlers(mux, auth, store, caID, audit)
	})
}
