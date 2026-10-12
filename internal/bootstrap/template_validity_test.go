// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func TestParseValidityPeriod(t *testing.T) {
	day := 24 * time.Hour
	for in, want := range map[string]time.Duration{
		"":        0,
		"P30D":    30 * day,
		"p30d":    30 * day,
		"P1Y":     365 * day,
		"P10Y":    3650 * day,
		"P1M":     30 * day,
		"P2W":     14 * day,
		"P1DT12H": 36 * time.Hour,
		"PT90M":   90 * time.Minute,
		"P90D":    90 * day,
		"72h":     72 * time.Hour,
		"2160h":   2160 * time.Hour,
		"90d":     90 * day,
		" P1D ":   day,
	} {
		got, err := ParseValidityPeriod(in)
		if err != nil || got != want {
			t.Errorf("ParseValidityPeriod(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"P", "PT", "P1DT", "P0D", "-5h", "soon", "90 days", "P1.5D", "P999999Y", "0"} {
		if d, err := ParseValidityPeriod(in); err == nil {
			t.Errorf("ParseValidityPeriod(%q) = %v, want an error", in, d)
		}
	}
}

func newValidityProvider(t *testing.T, caLifetime time.Duration, tpls map[string]TemplateItem) (CertificateProvider, string) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-validity-passphrase-32-byte"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("V Root", pkix.Name{CommonName: "V Root CA"}, keystore.ECDSAP256, caLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return WithTemplateProvider(NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false),
		&fakeTemplateProvider{templates: tpls}), root.ID
}

func lifetime(t *testing.T, item CertificateItem) time.Duration {
	t.Helper()
	from, err1 := time.Parse(time.RFC3339, item.ValidFrom)
	until, err2 := time.Parse(time.RFC3339, item.ValidUntil)
	if err1 != nil || err2 != nil {
		t.Fatalf("bad validity %q..%q", item.ValidFrom, item.ValidUntil)
	}
	return until.Sub(from)
}

// Certificate lifetime follows the template (ISO-8601 or Go durations),
// is clamped by the issuing CA's own NotAfter, defaults to 90 days, and a
// renewal keeps the predecessor's template validity. The old code parsed
// validity_period with time.ParseDuration only, so every "P…" value fell
// through to the 90-day default.
func TestIssuedValidityFollowsTemplate(t *testing.T) {
	day := 24 * time.Hour
	provider, caID := newValidityProvider(t, 3*365*day, map[string]TemplateItem{
		"t30":    {ID: "t30", Active: true, ValidityPeriod: "P30D"},
		"t1y":    {ID: "t1y", Active: true, ValidityPeriod: "P1Y"},
		"t10y":   {ID: "t10y", Active: true, ValidityPeriod: "P10Y"},
		"tgo":    {ID: "tgo", Active: true, ValidityPeriod: "72h"},
		"tnone":  {ID: "tnone", Active: true},
		"tbad":   {ID: "tbad", Active: true, ValidityPeriod: "someday"},
		"tshort": {ID: "tshort", Active: true, ValidityPeriod: "P30D", ShortLived: true},
	})
	ctx := context.Background()
	issue := func(tpl, cn string) (CertificateItem, error) {
		res, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: tpl, CSRPEM: generateTestCSRPEM(t, cn, cn)})
		return res.CertificateItem, err
	}
	within := func(got, want time.Duration) bool {
		d := got - want
		return d > -time.Minute && d < time.Minute
	}

	for _, tc := range []struct {
		tpl  string
		want time.Duration
	}{
		{"t30", 30 * day},
		{"t1y", 365 * day},
		{"tgo", 72 * time.Hour},
		{"tnone", 90 * day},
		{"tshort", 7 * day},
	} {
		item, err := issue(tc.tpl, tc.tpl+".example.com")
		if err != nil {
			t.Fatalf("%s: %v", tc.tpl, err)
		}
		if got := lifetime(t, item); !within(got, tc.want) {
			t.Errorf("%s: lifetime %v, want %v", tc.tpl, got, tc.want)
		}
	}

	// P10Y outruns a 3-year CA: the CA's NotAfter wins.
	item, err := issue("t10y", "t10y.example.com")
	if err != nil {
		t.Fatalf("t10y: %v", err)
	}
	if got := lifetime(t, item); got >= 3*365*day+time.Hour || got < 3*365*day-2*time.Hour {
		t.Errorf("t10y: lifetime %v, want ~3 years (the CA's remaining life)", got)
	}

	// An unparseable period fails closed instead of silently issuing 90 days.
	if _, err := issue("tbad", "tbad.example.com"); !errors.Is(err, ca.ErrPolicyViolation) {
		t.Errorf("tbad: want ErrPolicyViolation, got %v", err)
	}

	// Renewal reuses the predecessor's template validity.
	first, err := issue("t30", "renew.example.com")
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := provider.RenewCertificate(ctx, first.FingerprintSHA256, CertificateRenewRequest{CSRPEM: generateTestCSRPEM(t, "renew.example.com", "renew.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if got := lifetime(t, renewed.CertificateItem); !within(got, 30*day) {
		t.Errorf("renewal lifetime %v, want 30d", got)
	}
}

func TestTemplateValidityPeriodValidatedOnCreate(t *testing.T) {
	if err := validateTemplateUpsertRequest(TemplateUpsertRequest{
		Name: "n", DisplayName: "n", ValidityPeriod: "someday",
		KeyUsage: []string{"digitalSignature"}, ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"ECDSA"},
	}); !errors.Is(err, errTemplateInvalidCreate) {
		t.Fatalf("want errTemplateInvalidCreate, got %v", err)
	}
}
