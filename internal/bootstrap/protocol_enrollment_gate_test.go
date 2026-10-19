// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"testing"

	"kryptkeeper/internal/ca"
)

type errTemplateProvider struct{ fakeTemplateProvider }

func (*errTemplateProvider) GetTemplate(context.Context, string) (TemplateItem, bool, error) {
	return TemplateItem{}, false, errors.New("template store down")
}

func TestProtocolEnrollmentGate(t *testing.T) {
	mk := func(active bool, enroll ...string) *fakeTemplateProvider {
		item := TemplateItem{ID: "tpl-p", Active: active}
		if enroll != nil {
			item.EnrollmentPermissions = &EnrollmentPermissions{Enroll: enroll}
		}
		return &fakeTemplateProvider{templates: map[string]TemplateItem{"tpl-p": item}}
	}
	for _, tc := range []struct {
		name       string
		templates  TemplateProvider
		protocol   string
		wantErr    error // errors.Is target; nil = allowed
		wantAnyErr bool
		wantAction string // audit action expected; "" = no audit row
	}{
		{"role not listed is denied and audited", mk(true, "pki-admin"), "acme", ca.ErrEnrollmentDenied, false, "issuance.denied_template_role"},
		{"protocol role listed is allowed", mk(true, "protocol:acme"), "acme", nil, false, ""},
		{"other protocol's role does not leak", mk(true, "protocol:est"), "scep", ca.ErrEnrollmentDenied, false, "issuance.denied_template_role"},
		{"empty enroll is unrestricted", mk(true), "est", nil, false, ""},
		{"inactive template fails closed", mk(false), "acme", ca.ErrPolicyViolation, false, "issuance.denied_template_policy"},
		{"missing template fails closed", &fakeTemplateProvider{}, "acme", ca.ErrPolicyViolation, false, "issuance.denied_template_policy"},
		{"lookup error fails closed", &errTemplateProvider{}, "acme", nil, true, "issuance.denied_template_policy"},
		{"nil provider fails closed", nil, "acme", ca.ErrPolicyViolation, false, "issuance.denied_template_policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := &scepRecordingAudit{}
			err := NewProtocolEnrollmentGate(tc.templates, "tpl-p", tc.protocol, audit)(context.Background(), "acct-1")
			switch {
			case tc.wantAnyErr:
				if err == nil {
					t.Fatal("expected an error")
				}
			case tc.wantErr == nil:
				if err != nil {
					t.Fatalf("expected allow, got %v", err)
				}
			case !errors.Is(err, tc.wantErr):
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantAction == "" {
				if len(audit.entries) != 0 {
					t.Fatalf("unexpected audit rows %+v", audit.entries)
				}
				return
			}
			if len(audit.entries) != 1 || audit.entries[0].Action != tc.wantAction ||
				audit.entries[0].ResourceType != "template" || audit.entries[0].ResourceID != "tpl-p" ||
				audit.entries[0].ActorID != "acct-1" {
				t.Fatalf("audit rows = %+v, want one %s row for tpl-p by acct-1", audit.entries, tc.wantAction)
			}
			if tc.wantErr == ca.ErrEnrollmentDenied && audit.entries[0].Outcome != AuditOutcomeDenied {
				t.Errorf("outcome = %q, want denied", audit.entries[0].Outcome)
			}
		})
	}
}
