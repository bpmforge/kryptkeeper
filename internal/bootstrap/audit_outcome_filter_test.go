// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The Audit page's outcome dropdown sent ?outcome= but the handler ignored it,
// so the filter never filtered. It now filters on every AuditOutcome and
// refuses values outside the vocabulary.
func TestAuditHandlerOutcomeFilter(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	audit := realSQLiteAuditProvider(t)
	ctx := context.Background()
	for _, o := range AllAuditOutcomes() {
		if err := audit.AppendEntry(ctx, AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "outcome.filter", ActorType: "user",
			ActorID: "alice", ResourceType: "test", ResourceID: string(o), Outcome: o,
		}); err != nil {
			t.Fatalf("append %q: %v", o, err)
		}
	}
	mux := http.NewServeMux()
	RegisterHandlers(mux, NewAuthenticatorFromEnv(), stubCertSummaryForAudit{}, audit, stubCAProviderForAudit{}, stubTemplateProviderForAudit{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	get := func(q string) (int, []AuditEntry) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?action=outcome.filter&"+q, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var payload struct {
			Data []AuditEntry `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &payload)
		return rec.Code, payload.Data
	}
	for _, o := range AllAuditOutcomes() {
		code, rows := get("outcome=" + string(o))
		if code != http.StatusOK || len(rows) != 1 || rows[0].Outcome != o {
			t.Errorf("outcome=%s: code=%d rows=%+v", o, code, rows)
		}
	}
	if code, rows := get(""); code != http.StatusOK || len(rows) != len(AllAuditOutcomes()) {
		t.Errorf("unfiltered: code=%d rows=%d", code, len(rows))
	}
	if code, _ := get("outcome=bogus"); code != http.StatusBadRequest {
		t.Errorf("unknown outcome must be 400, got %d", code)
	}
}
