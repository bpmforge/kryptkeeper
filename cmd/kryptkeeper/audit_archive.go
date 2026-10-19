// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"

	"kryptkeeper/internal/bootstrap"
)

// auditArchiveEligible says whether the audit trail lives in the hub's core
// database. The archive job deletes from audit_log through that handle, so
// a file-backed trail, or one redirected with APP_AUDIT_DB_DSN, must not be
// archived against the wrong database.
func auditArchiveEligible(auditDesc string, getenv func(string) string) bool {
	return strings.HasPrefix(auditDesc, "db") && strings.TrimSpace(getenv("APP_AUDIT_DB_DSN")) == ""
}

// auditArchiveOption wires audit retention (W22-07): the propose endpoint
// plus the executor the approval queue runs once a second admin approves.
// Returns nil (feature off) when the trail is not in the core database.
func auditArchiveOption(auth *bootstrap.Authenticator, audit bootstrap.AuditProvider, coreDB *sql.DB, isPostgres bool, auditDesc string, getenv func(string) string) bootstrap.ServerOption {
	if coreDB == nil || !auditArchiveEligible(auditDesc, getenv) {
		logging.Info("audit archive: off (the audit trail is not in the hub database)")
		return nil
	}
	mgr := bootstrap.NewAuditArchiveManager(coreDB, isPostgres, bootstrap.NewPendingActionStoreFromEnv(), audit)
	if err := mgr.EnsureSchema(context.Background()); err != nil {
		logging.Warnf("audit archive: off (cannot create audit_archives: %v)", err)
		return nil
	}
	logging.Infof("audit archive: on (POST /api/v1/audit/archive; retention %d days; a second admin must approve)", bootstrap.AuditRetentionDays())
	return func(c *bootstrap.ServerConfig) {
		bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
			bootstrap.RegisterAuditArchiveHandlers(mux, auth, mgr, audit)
		})(c)
		bootstrap.WithActionExecutor(bootstrap.ActionAuditArchive, mgr.ExecuteArchive)(c)
	}
}
