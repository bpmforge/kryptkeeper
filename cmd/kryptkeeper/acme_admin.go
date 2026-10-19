// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"kryptkeeper/internal/logging"
	"net/http"
	"time"

	"kryptkeeper/internal/acme"
	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/ca"
)

// configureACMEAdmin wires operator-minted EAB credentials (W26-01) and ACME
// provisioners (W26-02) into the ACME server and returns the admin API
// option. Without a hub database provisioners live in memory and no EAB API
// is mounted.
func configureACMEAdmin(srv *acme.Server, auth *bootstrap.Authenticator, db *sql.DB, isPostgres bool, audit bootstrap.AuditProvider,
	caEngine ca.Service, templates bootstrap.TemplateProvider, baseURL string) bootstrap.ServerOption {
	srv.WithAuditFunc(func(ctx context.Context, ev acme.AuditEvent) {
		appendProtocolAudit(ctx, audit, ev.Action, ev.Actor, ev.Outcome, ev.SourceIP, ev.Detail)
	}).WithAlertFunc(acmeAlertSink(audit))

	var provStore acme.ProvisionerStore = acme.NewMemProvisionerStore()
	if db != nil {
		dbStore := acme.NewDBProvisionerStore(db, isPostgres)
		if err := dbStore.EnsureSchema(); err != nil {
			logging.Warnf("ACME provisioner schema failed (%v) - provisioners kept in memory", err)
		} else {
			provStore = dbStore
		}
	}
	srv.WithProvisioners(provStore, func(templateID string) acme.EnrollmentGate {
		return bootstrap.NewProtocolEnrollmentGate(templates, templateID, "acme", audit)
	})
	caExists := func(id string) bool { _, err := caEngine.GetCA(id); return err == nil }
	opts := []bootstrap.ServerOption{bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterACMEProvisionerHandlers(mux, auth, provStore, caExists, templates, baseURL, audit)
	})}

	if db != nil {
		passphrase := bootstrap.CredentialStorePassphraseFromEnv()
		store := acme.NewDBEABAdmin(db, isPostgres, func(sealed string) ([]byte, error) {
			return bootstrap.OpenSecret(passphrase, sealed)
		})
		if err := store.EnsureSchema(); err != nil {
			logging.Warnf("ACME EAB admin schema failed (%v) - EAB API disabled", err)
		} else {
			srv.WithEABAdmin(store)
			eabOpts := bootstrap.ACMEEABOptions{Passphrase: passphrase, ProvisionerExists: func(name string) bool {
				_, found, err := provStore.Get(context.Background(), name)
				return err == nil && found
			}}
			opts = append(opts, bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
				bootstrap.RegisterACMEEABHandlers(mux, auth, store, eabOpts, audit)
			}))
		}
	}
	return func(c *bootstrap.ServerConfig) {
		for _, o := range opts {
			o(c)
		}
	}
}

// acmeAlertSink records ACME alerts as "alert.<kind>" audit entries and logs
// them, like lifecycleAlertSink, so SIEM forwarding picks them up.
func acmeAlertSink(audit bootstrap.AuditProvider) acme.AlertFunc {
	return func(ctx context.Context, kind string, detail map[string]string) {
		logging.Infof("ALERT %s source=%s count=%s", kind, detail["source"], detail["count"])
		if audit == nil {
			return
		}
		if err := audit.AppendEntry(context.WithoutCancel(ctx), bootstrap.AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "alert." + kind, ActorType: "system", ActorID: "acme",
			ResourceType: "protocol", ResourceID: "acme", Outcome: bootstrap.AuditOutcomeSuccess, SourceIP: detail["source"],
			ChangeSummary: "failures=" + detail["count"],
		}); err != nil {
			logging.Errorf("alert %s: audit row not written: %v", kind, err)
		}
	}
}
