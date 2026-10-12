// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"log"
	"os"
	"strings"
)

const dashboardActionProviderEnv = "APP_DASHBOARD_ACTION_PROVIDER"

const (
	dashboardActionProviderFile = "file"
	dashboardActionProviderDB   = "db"
)

var dashboardActionProviderWarnf = log.Printf

type DashboardActionHistoryRecord struct {
	ActionID  string `json:"action_id"`
	Category  string `json:"category"`
	Status    string `json:"status"`
	UpdatedBy string `json:"updated_by"`
	UpdatedAt string `json:"updated_at"`
	Note      string `json:"note"`
}

type DashboardActionHistoryQuery struct {
	Status   string
	Category string
	Limit    int
	Cursor   int
}

type DashboardActionHistoryResult struct {
	History    []DashboardActionHistoryRecord
	Total      int
	Limit      int
	NextCursor *int
	PrevCursor *int
}

type DashboardActionAckResult struct {
	ActionID   string `json:"action_id"`
	Status     string `json:"status"`
	Note       string `json:"note"`
	AckedAtUTC string `json:"acked_at_utc"`
}

type DashboardActionResolveResult struct {
	ActionID   string `json:"action_id"`
	Status     string `json:"status"`
	Note       string `json:"note"`
	ResolvedAt string `json:"resolved_at"`
}

type DashboardActionProvider interface {
	ListHistory(context.Context, DashboardActionHistoryQuery) (DashboardActionHistoryResult, error)
	AckAction(ctx context.Context, actionID string, note string) (DashboardActionAckResult, error)
	ResolveAction(ctx context.Context, actionID string, note string) (DashboardActionResolveResult, error)
}

func NewDashboardActionProviderFromEnv() DashboardActionProvider {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(dashboardActionProviderEnv)))
	switch mode {
	case "", dashboardActionProviderFile:
		return newFileDashboardActionProvider()
	case dashboardActionProviderDB:
		return newDBDashboardActionProviderFromEnv()
	default:
		dashboardActionProviderWarnf("warning: unknown APP_DASHBOARD_ACTION_PROVIDER=%q; falling back to file", mode)
		return newFileDashboardActionProvider()
	}
}
