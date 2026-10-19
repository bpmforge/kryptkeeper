// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"kryptkeeper/internal/logging"
	"os"
	"strings"

	"kryptkeeper/internal/bootstrap"
)

// protocolEnrollmentGate builds the template gate for one protocol from its
// env var (W23-43). Unset means no gate, today's behaviour: failing closed on
// missing config would break every existing deployment. Once set, the gate
// itself fails closed on a missing or unreadable template.
func protocolEnrollmentGate(envVar, protocol string, templates bootstrap.TemplateProvider, audit bootstrap.AuditProvider) func(context.Context, string) error {
	id := strings.TrimSpace(os.Getenv(envVar))
	if id == "" {
		return nil
	}
	logging.Infof("%s enrollment is governed by template %s (enrollment_permissions; allow with role protocol:%s)", protocol, id, protocol)
	return bootstrap.NewProtocolEnrollmentGate(templates, id, protocol, audit)
}
