// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"testing"
	"time"
)

func TestAuthenticatorValidationReportIncludesMissingBootstrapTokenAndLoginFields(t *testing.T) {
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:         "bootstrap",
			loginEnabled: true,
			loginUser: loginCredential{
				Email:   "",
				Subject: "",
			},
			loginSigning: "",
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}

	report := auth.ValidationReport()
	if len(report.Errors) == 0 {
		t.Fatal("expected startup validation errors")
	}
	if !hasMsg(report.Errors, "APP_AUTH_LOGIN_EMAIL") || !hasMsg(report.Errors, "APP_AUTH_LOGIN_SIGNING_SECRET") {
		t.Fatalf("expected login field errors, got %v", report.Errors)
	}
	// With a login flow enabled the raw token is optional, so its absence is
	// a warning rather than a fatal error.
	if hasMsg(report.Errors, "APP_BOOTSTRAP_TOKEN") {
		t.Fatalf("missing bootstrap token must not be an error when login is enabled: %v", report.Errors)
	}
}

// AS-01: the env.example sample values are longer than the 32-byte floor, so
// they must be refused by name, not by length.
func TestValidationReportRejectsPlaceholderSecrets(t *testing.T) {
	sample := "Change-Me-to-a-different-strong-secret-0123456789"
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:           "bootstrap",
			bootstrapToken: sample,
			loginEnabled:   true,
			loginSigning:   sample,
			loginPepper:    sample,
			apiKeyPepper:   sample,
			loginUser:      loginCredential{Email: "a@b.c", PasswordHash: "x", Subject: "s"},
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}
	report := auth.ValidationReport()
	for _, name := range []string{"APP_BOOTSTRAP_TOKEN", "APP_AUTH_LOGIN_SIGNING_SECRET", "APP_AUTH_LOGIN_PASSWORD_PEPPER", "APP_API_KEY_PEPPER"} {
		if !hasMsg(report.Errors, name) {
			t.Errorf("%s placeholder not rejected: %v", name, report.Errors)
		}
	}
	if err := RejectPlaceholderSecret("KRYPTKEEPER_KEYSTORE_PASSPHRASE", sample); err == nil {
		t.Error("keystore passphrase placeholder not rejected")
	}
	if err := RejectPlaceholderSecret("X", "9f2c4e7a1b3d5f60718293a4b5c6d7e8"); err != nil {
		t.Errorf("real-looking secret rejected: %v", err)
	}
}

func TestAuthenticatorValidationReportWarnsWhenLoginDisabled(t *testing.T) {
	auth := &Authenticator{
		config:           authValidatorConfig{mode: "bootstrap"},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}

	report := auth.ValidationReport()
	if len(report.Warnings) == 0 {
		t.Fatal("expected startup validation warnings")
	}
}
