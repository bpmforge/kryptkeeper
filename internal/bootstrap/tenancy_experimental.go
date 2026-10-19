// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"errors"
	"strings"
)

// MultiTenancyExperimentalEnv / MultiTenancyExperimentalAck are the v0.9
// acknowledgement pair. They are only consulted when the gate is re-enforced
// with MultiTenancyGateEnv, and stay as the documented rollback path.
const (
	MultiTenancyExperimentalEnv = "KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL"
	MultiTenancyExperimentalAck = "accept-risk"
)

// MultiTenancyGateEnv set to "enforce" (exact) restores the v0.9 start-up
// refusal, as a rollback switch for operators who want the old posture.
const MultiTenancyGateEnv = "KRYPTKEEPER_MULTI_TENANCY_GATE"

// MultiTenancyExperimentalWarning is the notice main logs whenever
// multi-tenancy is on. The name is kept for its caller in cmd/kryptkeeper.
const MultiTenancyExperimentalWarning = "NOTICE: multi-tenancy is enabled; see docs/design/TENANCY_POSTURE.md for the enforced isolation boundary."

// MultiTenancyExperimentalCheck refuses a multi-tenant start only when the
// operator re-enforces the v0.9 gate and has not acknowledged it. The gate was
// lifted in v0.10 (owner decision 2026-10-16) once the tenant-idor suite
// reported zero cross-tenant leaks on SQLite and PostgreSQL
// (docs/release/MULTI_TENANCY_GATE_DECISION.md).
func MultiTenancyExperimentalCheck(getenv func(string) string) error {
	if !tenancyFlagOn(getenv("MULTI_TENANCY")) {
		return nil
	}
	if getenv(MultiTenancyGateEnv) != "enforce" {
		return nil
	}
	if getenv(MultiTenancyExperimentalEnv) == MultiTenancyExperimentalAck {
		return nil
	}
	return errors.New("multi-tenancy is experimental in this release: tenant isolation is not a security boundary " +
		"(a tenant admin can act across tenants); see docs/design/TENANCY_POSTURE.md; " +
		"set " + MultiTenancyExperimentalEnv + "=" + MultiTenancyExperimentalAck + " to run it anyway")
}

// MultiTenancyEnabled reports whether the MULTI_TENANCY flag is on.
func MultiTenancyEnabled() bool { return multiTenancyEnabled() }

func tenancyFlagOn(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	return v == "1" || v == "true" || v == "on" || v == "yes"
}
