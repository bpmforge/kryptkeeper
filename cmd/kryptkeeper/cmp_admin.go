// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"math/big"
	"net/http"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/cmp"
)

// cmpEnrollActionType is the pending-action type a deferred CMP enrollment
// waits on. Approving it only records the decision; CMP issues when the
// client's next pollReq sees the approval.
const cmpEnrollActionType = "cmp_enroll"

// cmpRevoker adapts the certificate inventory to cmp.Revoker (W26-08). A CMP
// secret holder may revoke only certificates CMP itself issued, so a serial
// that is unknown, not CMP-issued or already revoked all answer the same.
type cmpRevoker struct {
	certs bootstrap.CertificateProvider
}

var errStopScan = errors.New("stop")

func (c cmpRevoker) Revoke(ctx context.Context, serial *big.Int, reason int, _ string) (string, error) {
	var fingerprint string
	err := bootstrap.ForEachCertificate(ctx, c.certs, bootstrap.CertificateListQuery{Status: "active"}, func(item bootstrap.CertificateItem) error {
		got, ok := new(big.Int).SetString(item.SerialNumber, 10)
		if ok && got.Cmp(serial) == 0 && item.Source == "cmp" {
			fingerprint = item.FingerprintSHA256
			return errStopScan
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopScan) {
		return "", fmt.Errorf("look up certificate: %w", err)
	}
	if fingerprint == "" {
		return "", cmp.ErrUnknownSerial
	}
	// RevokeCertificate persists to the revocation store and invalidates the
	// OCSP/CRL caches, so both show the revocation on the next request.
	res, err := c.certs.RevokeCertificate(ctx, fingerprint, bootstrap.CertificateRevokeRequest{ReasonCode: reason, ReasonText: "revoked via CMP rr"})
	if err != nil {
		return "", fmt.Errorf("revoke: %w", err)
	}
	return res.RevocationScope, nil
}

// cmpApprover adapts the pending-action queue (D-017) to cmp.Approver. The
// certificate approval queue cannot be used: it re-issues from a PKCS#10 PEM
// and CMP has only a synthetic CSR.
//
// Which enrollments wait is chosen by KRYPTKEEPER_CMP_TEMPLATE: when that
// names a template with require_approval, every CMP ir/cr/kur waits for an
// approver. Unset means never.
type cmpApprover struct {
	templateID string
	templates  bootstrap.TemplateProvider
	actions    bootstrap.PendingActionStore
}

func (a cmpApprover) Needs(ctx context.Context) (bool, error) {
	tpl, found, err := a.templates.GetTemplate(ctx, a.templateID)
	if err != nil {
		return false, fmt.Errorf("template lookup: %w", err)
	}
	if !found {
		// Set but missing: fail closed rather than silently skip approval.
		return false, fmt.Errorf("CMP template %q not found", a.templateID)
	}
	return tpl.RequireApproval, nil
}

func (a cmpApprover) Propose(ctx context.Context, txID, subject string) (string, error) {
	params, err := json.Marshal(map[string]string{"tx": txID, "subject": subject, "template_id": a.templateID})
	if err != nil {
		return "", err
	}
	act, err := a.actions.Create(ctx, bootstrap.PendingAction{
		ActionType: cmpEnrollActionType,
		Params:     params,
		ProposedBy: "cmp:" + subject,
		Rationale:  "CMP enrollment requires approval (template " + a.templateID + ")",
	})
	if err != nil {
		return "", err
	}
	return act.ID, nil
}

func (a cmpApprover) State(ctx context.Context, approvalID string) (string, error) {
	act, ok, err := a.actions.Get(ctx, approvalID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "unknown", nil
	}
	switch act.Status {
	case "approved":
		return "approved", nil
	case "rejected", "failed":
		return "rejected", nil
	default: // pending, executing
		return "pending", nil
	}
}

// cmpEnrollExecutor lets the approval queue record an approval; issuance
// itself happens on the client's next pollReq.
func cmpEnrollExecutor(context.Context, bootstrap.PendingAction, bootstrap.AuthPrincipal) (json.RawMessage, error) {
	return json.RawMessage(`{"deferred":true}`), nil
}

func cmpAuditFunc(audit bootstrap.AuditProvider) cmp.AuditFunc {
	return func(ctx context.Context, ev cmp.AuditEvent) {
		appendProtocolAudit(ctx, audit, ev.Action, ev.Actor, ev.Outcome, ev.SourceIP, ev.Detail)
	}
}

// cmpAlertFunc records an alert as audit "alert.<kind>" plus a log line.
func cmpAlertFunc(audit bootstrap.AuditProvider) cmp.AlertFunc {
	return func(ctx context.Context, kind string, detail map[string]string) {
		b, _ := json.Marshal(detail)
		logging.Infof("ALERT %s %s", kind, b)
		appendProtocolAudit(ctx, audit, "alert."+kind, "", string(bootstrap.AuditOutcomeDenied), detail["source_ip"], string(b))
	}
}

// configureCMPCredentials builds the API-managed credential store (W26-09)
// and its admin routes. It returns nils without a database or when the schema
// cannot be created, leaving CMP on the env secret alone.
func configureCMPCredentials(auth *bootstrap.Authenticator, db *sql.DB, isPostgres bool, audit bootstrap.AuditProvider) (cmp.CredentialStore, bootstrap.ServerOption) {
	if db == nil {
		return nil, nil
	}
	passphrase := bootstrap.CredentialStorePassphraseFromEnv()
	store := cmp.NewDBCredentialStore(db, isPostgres, func(sealed string) ([]byte, error) {
		return bootstrap.OpenSecret(passphrase, sealed)
	})
	if err := store.EnsureSchema(); err != nil {
		logging.Warnf("CMP credential schema failed (%v) - CMP credential API disabled", err)
		return nil, nil
	}
	return store, bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterCMPCredentialHandlers(mux, auth, store, func() []byte { return passphrase }, audit)
	})
}
