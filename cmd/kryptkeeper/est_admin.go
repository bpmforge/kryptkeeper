// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"kryptkeeper/internal/logging"
	"net/http"
	"time"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/est"
)

// configureESTUserAdmin adds the API-managed Basic users (W26-07) as a second
// user source behind the users file, routes the failed-Basic alert to the
// audit log, and returns the option that mounts /api/v1/est/users. Call it
// after configureESTAuth: WithBasicUsers replaces the file users. Without a
// hub database only the alert sink is wired and there is no user API.
func configureESTUserAdmin(srv *est.Server, coreDB *sql.DB, isPostgres bool, auth *bootstrap.Authenticator, audit bootstrap.AuditProvider) bootstrap.ServerOption {
	srv.WithAlertFunc(estAlertSink(audit))
	if coreDB == nil {
		return nil
	}
	store := est.NewDBUserStore(coreDB, isPostgres)
	if err := store.EnsureSchema(context.Background()); err != nil {
		logging.Infof("EST user API disabled: %v", err)
		return nil
	}
	srv.WithUserSource(store)
	logging.Info("EST HTTP Basic: API-managed users enabled (POST /api/v1/est/users)")
	return bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterESTUserHandlers(mux, auth, store, srv.HasFileUser, audit)
	})
}

// estAlertSink records EST alerts as "alert.<kind>" audit entries and logs
// them, the way lifecycleAlertSink does for key alerts.
func estAlertSink(audit bootstrap.AuditProvider) est.AlertFunc {
	return func(ctx context.Context, kind string, detail map[string]string) {
		summary, _ := json.Marshal(detail) // plain strings: cannot fail
		logging.Infof("ALERT %s %s", kind, summary)
		if audit == nil {
			return
		}
		if err := audit.AppendEntry(context.WithoutCancel(ctx), bootstrap.AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "alert." + kind, ActorType: "system", ActorID: "est",
			ResourceType: "protocol", ResourceID: "est", Outcome: bootstrap.AuditOutcomeSuccess,
			SourceIP: detail["source_ip"], ChangeSummary: string(summary),
		}); err != nil {
			logging.Errorf("alert %s: audit row not written: %v", kind, err)
		}
	}
}

// configureESTLabels enables /.well-known/est/<label>/ routes (W26-06) and
// returns the option that mounts /api/v1/est/labels. Each label's gate is the
// template gate for that label's template, so an admin allows EST on it with
// role protocol:est in enrollment_permissions.enroll. Without a hub database
// there is no label store and label paths answer 404.
func configureESTLabels(srv *est.Server, coreDB *sql.DB, isPostgres bool, auth *bootstrap.Authenticator, templates bootstrap.TemplateProvider, audit bootstrap.AuditProvider) bootstrap.ServerOption {
	if coreDB == nil {
		return nil
	}
	store := est.NewDBLabelStore(coreDB, isPostgres)
	if err := store.EnsureSchema(context.Background()); err != nil {
		logging.Infof("EST label routes disabled: %v", err)
		return nil
	}
	srv.WithLabels(store, func(templateID string) est.EnrollmentGate {
		return bootstrap.NewProtocolEnrollmentGate(templates, templateID, "est", audit)
	})
	logging.Info("EST labels enabled (POST /api/v1/est/labels, served at /.well-known/est/<label>/)")
	return bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterESTLabelHandlers(mux, auth, store, templates, audit)
	})
}
