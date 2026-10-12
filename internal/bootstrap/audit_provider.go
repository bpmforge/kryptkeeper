// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const auditProviderEnv = "APP_AUDIT_PROVIDER"

const (
	auditProviderFile = "file"
	auditProviderDB   = "db"
)

var auditProviderWarnf = log.Printf

type AuditEntry struct {
	ID            int64        `json:"id"`
	Timestamp     string       `json:"timestamp"`
	Action        string       `json:"action"`
	ActorType     string       `json:"actor_type"`
	ActorID       string       `json:"actor_id"`
	ResourceType  string       `json:"resource_type"`
	ResourceID    string       `json:"resource_id"`
	TraceID       string       `json:"trace_id,omitempty"`
	Outcome       AuditOutcome `json:"outcome"`
	SourceIP      string       `json:"source_ip,omitempty"`
	UserAgent     string       `json:"user_agent,omitempty"`
	SessionID     string       `json:"session_id,omitempty"`
	ChangeSummary string       `json:"change_summary,omitempty"`
	// Tenant is the tenant context this action ran under (W2-04), derived
	// from the request's X-Tenant header — see auditRequestTenant. It is
	// "default" when multi-tenancy is off or no header was given.
	//
	// A separate ActingAsTenant (super-admin "view-as", distinct from a
	// principal's own tenant) is NOT yet recorded: distinguishing the two
	// requires knowing whether the acting principal is a super-admin, and
	// every audit call site only ever receives a plain actor-ID string, not
	// the resolved AuthPrincipal (threading that through would touch ~460
	// call sites across 33 files). W3-01 (identity-bound tenant binding)
	// gives principals a real, non-header-derived identity tenant — once
	// that lands, ActingAsTenant becomes meaningful and buildable here.
	Tenant string `json:"tenant,omitempty"`
}

type AuditListQuery struct {
	Limit        int
	Offset       int
	Order        string
	Action       string
	ActorType    string
	ActorID      string
	ResourceType string
	ResourceID   string
	TraceID      string
	Outcome      AuditOutcome
	After        string
	Before       string
}

type AuditListResult struct {
	Entries []AuditEntry
	Total   int
	Limit   int
}

type AuditProvider interface {
	ListEntries(context.Context, AuditListQuery) (AuditListResult, error)
	AppendEntry(context.Context, AuditEntry) error
}

// ResolveAuditProvider picks and opens the audit store, returning it with a
// description for the startup log. APP_AUDIT_PROVIDER wins when set; unset,
// the DB-backed trail is used whenever the hub has a core database
// (hasCoreDB), because the file store is single-node. An error means there is
// no audit trail and the caller must not start.
func ResolveAuditProvider(hasCoreDB bool) (AuditProvider, string, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(auditProviderEnv)))
	source := auditProviderEnv
	if mode != auditProviderFile && mode != auditProviderDB {
		source = "default"
		if mode != "" {
			auditProviderWarnf("warning: unknown APP_AUDIT_PROVIDER=%q; using the default", mode)
			source = "default, unknown APP_AUDIT_PROVIDER"
		}
		mode = auditProviderFile
		if hasCoreDB {
			mode = auditProviderDB
		}
	}
	var (
		p   AuditProvider
		err error
	)
	if mode == auditProviderDB {
		p, err = newDBAuditProviderFromEnv()
	} else {
		p, err = NewFileAuditProviderFromEnv()
	}
	if err != nil {
		return nil, mode, fmt.Errorf("audit provider %q (%s): %w", mode, source, err)
	}
	return p, fmt.Sprintf("%s (%s)", mode, source), nil
}

func parseAuditLimit(raw string, defaultLimit int) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultLimit
	}
	limit, err := strconv.Atoi(trimmed)
	if err != nil || limit <= 0 {
		return defaultLimit
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func parseAuditOffset(raw string) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}
	offset, err := strconv.Atoi(trimmed)
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}

func parseAuditOrder(raw string) string {
	order := strings.ToLower(strings.TrimSpace(raw))
	if order == "asc" {
		return "asc"
	}
	return "desc"
}

func parseAuditTimestamp(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return ""
	}
	return parsed.UTC().Format(time.RFC3339)
}
