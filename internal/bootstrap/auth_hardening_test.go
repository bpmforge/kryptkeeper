// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const strongSecret = "0123456789abcdef0123456789abcdef" // 32 bytes

func reportFor(cfg authValidatorConfig) StartupReport {
	return (&Authenticator{config: cfg}).ValidationReport()
}

func hasMsg(msgs []string, sub string) bool {
	for _, m := range msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

func TestValidationReport_OIDCRequiresIssuerAndAudience(t *testing.T) {
	cases := []struct {
		name     string
		iss, aud string
		wantErrs []string
	}{
		{"both set", "https://idp.example", "kk", nil},
		{"missing issuer", "", "kk", []string{"APP_OIDC_ISSUER"}},
		{"missing audience", "https://idp.example", "", []string{"APP_OIDC_AUDIENCE"}},
		{"missing both", "", "", []string{"APP_OIDC_ISSUER", "APP_OIDC_AUDIENCE"}},
		{"whitespace audience", "https://idp.example", "  ", []string{"APP_OIDC_AUDIENCE"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := reportFor(authValidatorConfig{mode: "oidc", oidcIssuer: tc.iss, oidcAudience: tc.aud, oidcJWKSJSON: "{}"})
			if len(r.Errors) != len(tc.wantErrs) {
				t.Fatalf("errors = %v, want %d", r.Errors, len(tc.wantErrs))
			}
			for _, want := range tc.wantErrs {
				if !hasMsg(r.Errors, want) {
					t.Fatalf("missing error mentioning %s in %v", want, r.Errors)
				}
			}
		})
	}
}

func TestValidationReport_OIDCUsesConfigStoreOverrides(t *testing.T) {
	store := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()
	if err := store.Set(ctx, "sso.oidc_issuer", "https://idp.example", "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(ctx, "sso.oidc_audience", "kk", "test"); err != nil {
		t.Fatal(err)
	}
	a := &Authenticator{config: authValidatorConfig{mode: "oidc", oidcJWKSJSON: "{}"}, configStore: store}
	if r := a.ValidationReport(); len(r.Errors) != 0 {
		t.Fatalf("DB-configured issuer/audience must satisfy validation, got %v", r.Errors)
	}
}

func TestAuthenticate_OIDCFailsClosedWithoutIssuerOrAudience(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer a.b.c")
	for _, cfg := range []authValidatorConfig{
		{mode: "oidc", oidcJWKSJSON: "{}", oidcAudience: "kk"},
		{mode: "oidc", oidcJWKSJSON: "{}", oidcIssuer: "https://idp.example"},
	} {
		if _, err := authenticatePrincipal(req, cfg, nil, time.Now()); err == nil {
			t.Fatalf("oidc auth must fail closed with cfg %+v", cfg)
		}
	}
}

func TestValidateHS256JWT_NotBefore(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	exp := float64(now.Add(time.Hour).Unix())
	cases := []struct {
		name    string
		nbf     any
		wantErr bool
	}{
		{"absent", nil, false},
		{"in the past", float64(now.Add(-time.Minute).Unix()), false},
		{"within skew", float64(now.Add(30 * time.Second).Unix()), false},
		{"at skew edge", float64(now.Add(jwtClockSkew).Unix()), false},
		{"future beyond skew", float64(now.Add(5 * time.Minute).Unix()), true},
		{"non-numeric", "soon", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"sub": "svc", "exp": exp}
			if tc.nbf != nil {
				claims["nbf"] = tc.nbf
			}
			_, _, err := validateHS256JWT(signHS256JWT(t, strongSecret, claims), strongSecret, "", "", "", now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateOIDCRS256JWT_NotBefore(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwks := buildTestJWKS(t, "k1", &priv.PublicKey)
	now := time.Unix(1_800_000_000, 0)
	exp := float64(now.Add(time.Hour).Unix())
	cases := []struct {
		name    string
		nbf     any
		wantErr bool
	}{
		{"absent", nil, false},
		{"within skew", float64(now.Add(30 * time.Second).Unix()), false},
		{"future beyond skew", float64(now.Add(5 * time.Minute).Unix()), true},
		{"non-numeric", "soon", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"sub": "svc", "exp": exp}
			if tc.nbf != nil {
				claims["nbf"] = tc.nbf
			}
			_, _, err := validateOIDCRS256JWT(signTestRS256JWT(t, priv, "k1", claims), jwks, "", "", "", now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidationReport_HS256SecretLength(t *testing.T) {
	short := "short-secret"
	login := loginCredential{Email: "a@b", PasswordHash: "x", Subject: "s"}
	cases := []struct {
		name    string
		cfg     authValidatorConfig
		wantErr string
	}{
		{"jwt strong", authValidatorConfig{mode: "jwt", jwtHS256Secret: strongSecret}, ""},
		{"jwt short", authValidatorConfig{mode: "jwt", jwtHS256Secret: short}, "APP_JWT_HS256_SECRET"},
		{"jwt 31 bytes", authValidatorConfig{mode: "jwt", jwtHS256Secret: strongSecret[:31]}, "APP_JWT_HS256_SECRET"},
		{"jwt unset is not a length error", authValidatorConfig{mode: "jwt"}, ""},
		{"login strong", authValidatorConfig{mode: "bootstrap", bootstrapToken: strongSecret, loginEnabled: true, loginUser: login, loginSigning: strongSecret}, ""},
		{"login short", authValidatorConfig{mode: "bootstrap", bootstrapToken: strongSecret, loginEnabled: true, loginUser: login, loginSigning: short}, "APP_AUTH_LOGIN_SIGNING_SECRET"},
		{"sso-only short", authValidatorConfig{mode: "bootstrap", bootstrapToken: strongSecret, samlLoginEnabled: true, loginSigning: short}, "APP_AUTH_LOGIN_SIGNING_SECRET"},
		{"login off, unused short secret", authValidatorConfig{mode: "bootstrap", bootstrapToken: strongSecret, loginSigning: short}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := reportFor(tc.cfg)
			if tc.wantErr == "" {
				if hasMsg(r.Errors, "bytes") {
					t.Fatalf("unexpected length error: %v", r.Errors)
				}
				return
			}
			if !hasMsg(r.Errors, tc.wantErr) || !hasMsg(r.Errors, "bytes") {
				t.Fatalf("want length error for %s, got %v", tc.wantErr, r.Errors)
			}
		})
	}
}

func TestValidationReport_BootstrapToken(t *testing.T) {
	login := loginCredential{Email: "a@b", PasswordHash: "x", Subject: "s"}
	cases := []struct {
		name     string
		cfg      authValidatorConfig
		wantErr  bool
		wantWarn string
	}{
		{"strong token", authValidatorConfig{mode: "bootstrap", bootstrapToken: strongSecret}, false, ""},
		{"short token warns, not errors", authValidatorConfig{mode: "bootstrap", bootstrapToken: "dev-token"}, false, "characters"},
		{"missing, nothing else, errors", authValidatorConfig{mode: "bootstrap"}, true, ""},
		{"missing but login on, warns", authValidatorConfig{mode: "bootstrap", loginEnabled: true, loginUser: login, loginSigning: strongSecret}, false, "only login sessions"},
		{"disabled, no token needed", authValidatorConfig{mode: "bootstrap", bootstrapTokenDisabled: true}, false, "disabled"},
		{"disabled with token set warns it is ignored", authValidatorConfig{mode: "bootstrap", bootstrapTokenDisabled: true, bootstrapToken: strongSecret}, false, "ignored"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := reportFor(tc.cfg)
			if got := hasMsg(r.Errors, "APP_BOOTSTRAP_TOKEN"); got != tc.wantErr {
				t.Fatalf("token error = %v, want %v (%v)", got, tc.wantErr, r.Errors)
			}
			if tc.wantWarn != "" && !hasMsg(r.Warnings, tc.wantWarn) {
				t.Fatalf("want warning containing %q, got %v", tc.wantWarn, r.Warnings)
			}
		})
	}
}

func TestBootstrapTokenAuthentication(t *testing.T) {
	cfg := authValidatorConfig{mode: "bootstrap", bootstrapToken: "right-token"}
	try := func(c authValidatorConfig, token string) error {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		_, _, _, err := authenticateBootstrap(req, c)
		return err
	}
	if err := try(cfg, "right-token"); err != nil {
		t.Fatalf("correct token rejected: %v", err)
	}
	for _, bad := range []string{"wrong-token", "right-toke", "right-token-and-more", "RIGHT-TOKEN", "x"} {
		if err := try(cfg, bad); err == nil {
			t.Fatalf("token %q must be rejected", bad)
		}
	}
	if err := try(authValidatorConfig{mode: "bootstrap"}, "anything"); err == nil {
		t.Fatal("unset bootstrap token must never match")
	}

	disabled := cfg
	disabled.bootstrapTokenDisabled = true
	if err := try(disabled, "right-token"); err == nil {
		t.Fatal("disabled bootstrap token must not authenticate")
	}
}

func TestBootstrapDisabledStillAllowsLoginSession(t *testing.T) {
	cfg := authValidatorConfig{mode: "bootstrap", bootstrapToken: "right-token", bootstrapTokenDisabled: true, loginEnabled: true, loginSigning: strongSecret}
	tok, err := mintHS256JWT("alice", "pki-operator", strongSecret, "", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	sub, role, authType, err := authenticateBootstrap(req, cfg)
	if err != nil || sub != "alice" || role != "pki-operator" || authType != "local" {
		t.Fatalf("session = %q %q %q err=%v", sub, role, authType, err)
	}
}

func TestNewAuthenticatorFromEnv_DisableBootstrapToken(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", strongSecret)
	t.Setenv("KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN", "true")
	if !NewAuthenticatorFromEnv().config.bootstrapTokenDisabled {
		t.Fatal("KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN=true must set the flag")
	}
	t.Setenv("KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN", "")
	if NewAuthenticatorFromEnv().config.bootstrapTokenDisabled {
		t.Fatal("flag must default to off")
	}
}

func TestStartupReport_FatalError(t *testing.T) {
	if err := (StartupReport{Warnings: []string{"w"}}).FatalError(); err != nil {
		t.Fatalf("warnings alone must not be fatal: %v", err)
	}
	err := (StartupReport{Errors: []string{"first problem", "second problem"}}).FatalError()
	if err == nil || !strings.Contains(err.Error(), "first problem") || !strings.Contains(err.Error(), "second problem") {
		t.Fatalf("FatalError must list every error, got %v", err)
	}
}
