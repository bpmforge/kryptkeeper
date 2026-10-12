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

const protocolProviderEnv = "APP_PROTOCOL_PROVIDER"

const (
	protocolProviderFile = "file"
)

var protocolProviderWarnf = log.Printf

type ProtocolStatus struct {
	ACME bool `json:"acme"`
	EST  bool `json:"est"`
	SCEP bool `json:"scep"`
	OCSP bool `json:"ocsp"`
	CRL  bool `json:"crl"`
}

type ProtocolReadinessEntry struct {
	Enabled       bool    `json:"enabled"`
	Healthy       bool    `json:"healthy"`
	LastCheckedAt *string `json:"last_checked_at"`
}

type ProtocolReadiness struct {
	ACME ProtocolReadinessEntry `json:"acme"`
	EST  ProtocolReadinessEntry `json:"est"`
	SCEP ProtocolReadinessEntry `json:"scep"`
	OCSP ProtocolReadinessEntry `json:"ocsp"`
	CRL  ProtocolReadinessEntry `json:"crl"`
}

type ConformanceSuite struct {
	State       string `json:"state"`
	LastRunAt   string `json:"last_run_at"`
	PassingRate int    `json:"passing_rate"`
}

type ProtocolConformance struct {
	ACME ConformanceSuite `json:"acme"`
	EST  ConformanceSuite `json:"est"`
	SCEP ConformanceSuite `json:"scep"`
	OCSP ConformanceSuite `json:"ocsp"`
	CRL  ConformanceSuite `json:"crl"`
}

type ConformanceRecheckResult struct {
	JobID    string `json:"job_id"`
	Suite    string `json:"suite"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	QueuedAt string `json:"queued_at"`
}

type ProtocolProvider interface {
	GetStatus(context.Context) (ProtocolStatus, error)
	GetReadiness(context.Context) (ProtocolReadiness, error)
	GetConformance(context.Context) (ProtocolConformance, error)
	TriggerConformanceRecheck(ctx context.Context, suite string, reason string) (ConformanceRecheckResult, error)
}

func NewProtocolProviderFromEnv() ProtocolProvider {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(protocolProviderEnv)))
	switch mode {
	case "", protocolProviderFile:
		return newFileProtocolProvider()
	default:
		protocolProviderWarnf("warning: unknown APP_PROTOCOL_PROVIDER=%q; falling back to file", mode)
		return newFileProtocolProvider()
	}
}
