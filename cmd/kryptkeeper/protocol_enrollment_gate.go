// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"kryptkeeper/internal/logging"
	"os"
	"strings"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/ca"
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

// protocolTemplatePolicy resolves a template's issuance policy for a protocol
// server. A missing template is an error, so issuance fails closed exactly as
// the enrollment gate does.
func protocolTemplatePolicy(templates bootstrap.TemplateProvider) func(context.Context, string) (*ca.TemplatePolicy, error) {
	return func(ctx context.Context, id string) (*ca.TemplatePolicy, error) {
		tpl, found, err := templates.GetTemplate(ctx, id)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("template %s not found", id)
		}
		pol := bootstrap.TemplatePolicy(tpl)
		return &pol, nil
	}
}
