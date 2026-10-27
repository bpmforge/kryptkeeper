// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/logging"
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

// configureSCEPLabels enables /scep/<label> endpoints in Intune challenge mode
// (W20-23, D-327) and returns the option that mounts /api/v1/scep/labels. With
// no database there are no labels and /scep/<label> answers 404. Each label's
// gate is the enrollment_permissions of its template, role protocol:scep.
func configureSCEPLabels(srv *scep.Server, coreDB *sql.DB, isPostgres bool, auth *bootstrap.Authenticator, templates bootstrap.TemplateProvider, audit bootstrap.AuditProvider, rev ca.RevocationStore, caID string) bootstrap.ServerOption {
	if coreDB == nil {
		return nil
	}
	mgr, creds, err := bootstrap.NewSCEPIntune("Kryptkeeper/" + version)
	if err != nil {
		logging.Infof("SCEP labels disabled: %v", err)
		return nil
	}
	store := scep.NewDBLabelStore(coreDB, isPostgres)
	srv.WithLabels(store, mgr, func(templateID string) scep.EnrollmentGate {
		return bootstrap.NewProtocolEnrollmentGate(templates, templateID, "scep", audit)
	})
	if rev != nil {
		// A certificate signed but never released (Intune could not be told) is revoked: reason 5, cessationOfOperation.
		srv.WithWithdrawer(func(_ context.Context, c *x509.Certificate) error {
			return rev.Revoke(c.SerialNumber, caID, 5, time.Now().UTC(), ca.CertMeta{
				FingerprintSHA256: fmt.Sprintf("%x", sha256.Sum256(c.Raw)), CommonName: c.Subject.CommonName, SubjectDN: c.Subject.String(),
				SubjectAltNames: ca.SubjectAltNameStrings(c), IssuerDN: c.Issuer.String(), IssuerCN: c.Issuer.CommonName,
				NotBefore: c.NotBefore, NotAfter: c.NotAfter, PublicKeyAlgorithm: ca.StoredPublicKeyAlgorithm(c),
				KeySizeBits: ca.PublicKeyBits(c.PublicKey), SignatureAlgorithm: c.SignatureAlgorithm.String(), Source: "scep",
				CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}),
			})
		})
	}
	if rev == nil {
		// Fail-open window: without a revoker a certificate whose Intune success notification failed is withheld but stays valid (the audit row names its serial).
		logging.Errorf("SCEP Intune labels are enabled without a revoker: a certificate signed but not released to Intune cannot be revoked automatically")
	}
	logging.Info("SCEP labels enabled (POST /api/v1/scep/labels, served at /scep/<label>)")
	return bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterSCEPLabelHandlers(mux, auth, store, templates, creds, audit)
	})
}

// joinServerOptions runs each non-nil option in order.
func joinServerOptions(opts ...bootstrap.ServerOption) bootstrap.ServerOption {
	return func(c *bootstrap.ServerConfig) {
		for _, o := range opts {
			if o != nil {
				o(c)
			}
		}
	}
}
