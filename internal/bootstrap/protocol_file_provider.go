// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"time"
)

type fileProtocolProvider struct{}

func newFileProtocolProvider() ProtocolProvider {
	return &fileProtocolProvider{}
}

func (p *fileProtocolProvider) GetStatus(_ context.Context) (ProtocolStatus, error) {
	return ProtocolStatus{
		ACME: envBool("APP_PROTOCOL_ACME_ENABLED"),
		EST:  envBool("APP_PROTOCOL_EST_ENABLED"),
		SCEP: envBool("APP_PROTOCOL_SCEP_ENABLED"),
		OCSP: envBool("APP_PROTOCOL_OCSP_ENABLED"),
		CRL:  envBool("APP_PROTOCOL_CRL_ENABLED"),
	}, nil
}

func (p *fileProtocolProvider) GetReadiness(_ context.Context) (ProtocolReadiness, error) {
	build := func(enabledEnv, healthyEnv, lastCheckedEnv string) ProtocolReadinessEntry {
		enabled := envBool(enabledEnv)
		healthy := false
		if enabled {
			healthy = envBoolDefault(healthyEnv, true)
		}
		lastChecked := envOptionalRFC3339(lastCheckedEnv)
		return ProtocolReadinessEntry{Enabled: enabled, Healthy: healthy, LastCheckedAt: lastChecked}
	}

	return ProtocolReadiness{
		ACME: build("APP_PROTOCOL_ACME_ENABLED", "APP_PROTOCOL_ACME_HEALTHY", "APP_PROTOCOL_ACME_LAST_CHECKED_AT"),
		EST:  build("APP_PROTOCOL_EST_ENABLED", "APP_PROTOCOL_EST_HEALTHY", "APP_PROTOCOL_EST_LAST_CHECKED_AT"),
		SCEP: build("APP_PROTOCOL_SCEP_ENABLED", "APP_PROTOCOL_SCEP_HEALTHY", "APP_PROTOCOL_SCEP_LAST_CHECKED_AT"),
		OCSP: build("APP_PROTOCOL_OCSP_ENABLED", "APP_PROTOCOL_OCSP_HEALTHY", "APP_PROTOCOL_OCSP_LAST_CHECKED_AT"),
		CRL:  build("APP_PROTOCOL_CRL_ENABLED", "APP_PROTOCOL_CRL_HEALTHY", "APP_PROTOCOL_CRL_LAST_CHECKED_AT"),
	}, nil
}

func (p *fileProtocolProvider) GetConformance(_ context.Context) (ProtocolConformance, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	build := func(stateEnv, rateEnv, checkedEnv string) ConformanceSuite {
		lastChecked := now
		if v := envOptionalRFC3339(checkedEnv); v != nil {
			lastChecked = *v
		}
		return ConformanceSuite{
			State:       envConformanceState(stateEnv),
			LastRunAt:   lastChecked,
			PassingRate: envClampedInt(rateEnv, 100, 0, 100),
		}
	}

	return ProtocolConformance{
		ACME: build("APP_PROTOCOL_ACME_CONFORMANCE_STATE", "APP_PROTOCOL_ACME_CONFORMANCE_RATE", "APP_PROTOCOL_ACME_CONFORMANCE_LAST_RUN_AT"),
		EST:  build("APP_PROTOCOL_EST_CONFORMANCE_STATE", "APP_PROTOCOL_EST_CONFORMANCE_RATE", "APP_PROTOCOL_EST_CONFORMANCE_LAST_RUN_AT"),
		SCEP: build("APP_PROTOCOL_SCEP_CONFORMANCE_STATE", "APP_PROTOCOL_SCEP_CONFORMANCE_RATE", "APP_PROTOCOL_SCEP_CONFORMANCE_LAST_RUN_AT"),
		OCSP: build("APP_PROTOCOL_OCSP_CONFORMANCE_STATE", "APP_PROTOCOL_OCSP_CONFORMANCE_RATE", "APP_PROTOCOL_OCSP_CONFORMANCE_LAST_RUN_AT"),
		CRL:  build("APP_PROTOCOL_CRL_CONFORMANCE_STATE", "APP_PROTOCOL_CRL_CONFORMANCE_RATE", "APP_PROTOCOL_CRL_CONFORMANCE_LAST_RUN_AT"),
	}, nil
}

func (p *fileProtocolProvider) TriggerConformanceRecheck(_ context.Context, suite string, reason string) (ConformanceRecheckResult, error) {
	now := time.Now().UTC()
	return ConformanceRecheckResult{
		JobID:    fmt.Sprintf("conformance-%d", now.UnixNano()),
		Suite:    suite,
		Status:   "queued",
		Reason:   reason,
		QueuedAt: now.Format(time.RFC3339),
	}, nil
}
