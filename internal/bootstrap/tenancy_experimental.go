// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"errors"
	"strings"
)

// MultiTenancyExperimentalEnv must equal MultiTenancyExperimentalAck for a hub
// with MULTI_TENANCY on to start.
const (
	MultiTenancyExperimentalEnv = "KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL"
	MultiTenancyExperimentalAck = "accept-risk"
)

// MultiTenancyExperimentalWarning is the text logged when the operator has
// acknowledged the experimental status.
const MultiTenancyExperimentalWarning = "WARNING: multi-tenancy is EXPERIMENTAL in this release. Tenant isolation is NOT a security boundary: " +
	"a tenant admin can act across tenants (see docs/design/TENANCY_POSTURE.md)."

// MultiTenancyExperimentalCheck refuses a multi-tenant start unless the
// operator explicitly accepted the risk. The audit findings behind this gate
// (A01-001/002/004/005/006, A01S-3) are scheduled for v0.10.
func MultiTenancyExperimentalCheck(getenv func(string) string) error {
	if !tenancyFlagOn(getenv("MULTI_TENANCY")) {
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
