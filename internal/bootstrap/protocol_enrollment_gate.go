// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"time"

	"kryptkeeper/internal/ca"
)

// NewProtocolEnrollmentGate returns the check ACME, EST and SCEP run before
// issuing (W23-43). The protocols never load a template themselves and their
// callers carry no hub role, so one template governs a protocol and the caller
// is the pseudo role "protocol:<protocol>": an admin allows a protocol by
// listing that string in the template's enrollment_permissions.enroll.
//
// It fails closed: a template that is missing, inactive or cannot be read
// denies. Every denial is appended to the audit log; a failed audit append
// is logged but never turns a denial into an allow.
func NewProtocolEnrollmentGate(templates TemplateProvider, templateID, protocol string, audit AuditProvider) func(ctx context.Context, actor string) error {
	role := "protocol:" + protocol
	return func(ctx context.Context, actor string) error {
		record := func(action string, outcome AuditOutcome, err error) {
			if audit == nil {
				return
			}
			actorType, actorID := "user", actor
			if actorID == "" {
				actorType, actorID = "system", "anonymous"
			}
			entry := AuditEntry{
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
				Action:        action,
				ActorType:     actorType,
				ActorID:       actorID,
				ResourceType:  "template",
				ResourceID:    templateID,
				Outcome:       outcome,
				ChangeSummary: fmt.Sprintf(`{"role":%q,"protocol":%q,"template_id":%q}`, role, protocol, templateID),
			}
			if aerr := audit.AppendEntry(context.WithoutCancel(ctx), entry); aerr != nil {
				logging.Warnf("audit append failed action=%s protocol=%s: %v (err: %v)", action, protocol, aerr, err)
			}
		}

		if templates == nil {
			err := fmt.Errorf("%w: no template provider for %s enrollment", ca.ErrPolicyViolation, protocol)
			record("issuance.denied_template_policy", AuditOutcomeDenied, err)
			return err
		}
		tpl, found, err := templates.GetTemplate(ctx, templateID)
		if err != nil {
			err = fmt.Errorf("template lookup: %w", err)
			record("issuance.denied_template_policy", AuditOutcomeFailure, err)
			return err
		}
		if !found || !tpl.Active {
			err := fmt.Errorf("%w: template %q is missing or inactive", ca.ErrPolicyViolation, templateID)
			record("issuance.denied_template_policy", AuditOutcomeDenied, err)
			return err
		}
		err = ca.CheckEnrollment(ca.WithCallerRole(ctx, role), tpl.ID, tpl.EnrollRoles())
		if errors.Is(err, ca.ErrEnrollmentDenied) {
			record("issuance.denied_template_role", AuditOutcomeDenied, err)
		}
		return err
	}
}
