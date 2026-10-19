// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"
)

// dashboardActionDemoEnv opts the file provider into its canned sample rows.
// Without it the history is empty: a real hub must never present fixture
// data (dated April 2026) as its own activity (UI finding 6).
const dashboardActionDemoEnv = "APP_DASHBOARD_ACTION_DEMO"

type fileDashboardActionProvider struct{ demo bool }

func newFileDashboardActionProvider() DashboardActionProvider {
	return &fileDashboardActionProvider{demo: strings.EqualFold(strings.TrimSpace(os.Getenv(dashboardActionDemoEnv)), "true")}
}

func (p *fileDashboardActionProvider) ListHistory(_ context.Context, query DashboardActionHistoryQuery) (DashboardActionHistoryResult, error) {
	var history []DashboardActionHistoryRecord
	if p.demo {
		history = seedDashboardActionHistory()
	}
	filtered := make([]DashboardActionHistoryRecord, 0, len(history))
	for _, rec := range history {
		if query.Status != "" && !strings.EqualFold(rec.Status, query.Status) {
			continue
		}
		if query.Category != "" && !strings.EqualFold(rec.Category, query.Category) {
			continue
		}
		filtered = append(filtered, rec)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].UpdatedAt > filtered[j].UpdatedAt
	})

	result := paginate(filtered, query.Limit, query.Cursor, 25, 100)
	return DashboardActionHistoryResult{
		History:    result.Items,
		Total:      result.Total,
		Limit:      result.Limit,
		NextCursor: result.NextCursor,
		PrevCursor: result.PrevCursor,
	}, nil
}

func (p *fileDashboardActionProvider) AckAction(_ context.Context, actionID string, note string) (DashboardActionAckResult, error) {
	return DashboardActionAckResult{
		ActionID:   actionID,
		Status:     "acknowledged",
		Note:       note,
		AckedAtUTC: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (p *fileDashboardActionProvider) ResolveAction(_ context.Context, actionID string, note string) (DashboardActionResolveResult, error) {
	return DashboardActionResolveResult{
		ActionID:   actionID,
		Status:     "resolved",
		Note:       note,
		ResolvedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func seedDashboardActionHistory() []DashboardActionHistoryRecord {
	return []DashboardActionHistoryRecord{
		{ActionID: "act-expired-certs", Category: "certificate", Status: "open", UpdatedBy: "system", UpdatedAt: "2026-04-08T02:00:00Z", Note: "Detected expired certificate inventory"},
		{ActionID: "act-expiring-certs", Category: "certificate", Status: "acknowledged", UpdatedBy: "bootstrap", UpdatedAt: "2026-04-08T01:00:00Z", Note: "Owner assigned"},
		{ActionID: "act-risky-endpoints", Category: "discovery", Status: "resolved", UpdatedBy: "pki-operator", UpdatedAt: "2026-04-08T00:00:00Z", Note: "Legacy endpoint decommissioned"},
	}
}
