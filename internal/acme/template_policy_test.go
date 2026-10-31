// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func newTemplatedACMEServer(t *testing.T, templateID string, resolve TemplatePolicyFunc) *httptest.Server {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("ACME Template Root", pkix.Name{CommonName: "ACME Template Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	srv := NewServerWithStore(ts.URL, engine, rootCA.ID, NewMemStore(), ca.NewMemRevocationStore()).WithTemplatePolicy(templateID, resolve)
	srv.SetHTTP01DialContext(testHTTP01Dial)
	ts.Config.Handler = srv.Handler()
	return ts
}

func staticPolicy(p *ca.TemplatePolicy) TemplatePolicyFunc {
	return func(context.Context, string) (*ca.TemplatePolicy, error) { return p, nil }
}

func subjectDN(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawSubject, &seq); err != nil {
		t.Fatal(err)
	}
	return ca.FormatRDNSequence(seq)
}

// The case from the field: the client can only send a CN, and the template
// appends DC=foo,DC=bar so the certificate fits a DN-constrained CA.
func TestACMEFinalizeAppliesTemplateFixedRDNs(t *testing.T) {
	var asked string
	ts := newTemplatedACMEServer(t, "tpl-dc", func(_ context.Context, id string) (*ca.TemplatePolicy, error) {
		asked = id
		return &ca.TemplatePolicy{ID: id, Subject: &ca.SubjectPolicy{FixedRDNs: []ca.SubjectRDN{{Type: "DC", Value: "foo"}, {Type: "DC", Value: "bar"}}}}, nil
	})
	_, _, cert := runACMEFullOrderFlow(t, ts)
	if asked != "tpl-dc" {
		t.Fatalf("resolver asked for %q", asked)
	}
	if got, want := subjectDN(t, cert), "CN="+cert.DNSNames[0]+",DC=foo,DC=bar"; got != want {
		t.Fatalf("subject %q, want %q", got, want)
	}
}

func TestACMEFinalizeCapsValidityToTemplate(t *testing.T) {
	ts := newTemplatedACMEServer(t, "tpl-short", staticPolicy(&ca.TemplatePolicy{ID: "tpl-short", MaxValidity: 7 * 24 * time.Hour}))
	_, _, cert := runACMEFullOrderFlow(t, ts)
	if life := cert.NotAfter.Sub(cert.NotBefore); life > 7*24*time.Hour+time.Minute {
		t.Fatalf("lifetime %v exceeds the template's 7 days", life)
	}
}

// Template rules other than enrollment roles were ignored for ACME; a breach
// is now a badCSR the client can read.
func TestACMEFinalizeTemplateViolationIsBadCSR(t *testing.T) {
	ts := newTemplatedACMEServer(t, "tpl-names", staticPolicy(&ca.TemplatePolicy{ID: "tpl-names",
		Names: &ca.NamePolicy{AllowedDNSSuffixes: []string{".corp.example"}}}))
	status, _, body, _, _ := runACMEOrderToFinalize(t, ts)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "badCSR") || !strings.Contains(string(body), "tpl-names") {
		t.Fatalf("finalize = %d %s, want 400 badCSR naming the template", status, body)
	}
}

func TestACMEFinalizeFailsClosedWhenTemplateUnavailable(t *testing.T) {
	ts := newTemplatedACMEServer(t, "tpl-gone", func(context.Context, string) (*ca.TemplatePolicy, error) {
		return nil, errors.New("template tpl-gone not found")
	})
	status, _, body, _, _ := runACMEOrderToFinalize(t, ts)
	if status != http.StatusInternalServerError {
		t.Fatalf("finalize = %d %s, want 500", status, body)
	}
}

func TestACMEFinalizeWithoutTemplateIsUnchanged(t *testing.T) {
	called := false
	ts := newTemplatedACMEServer(t, "", func(context.Context, string) (*ca.TemplatePolicy, error) {
		called = true
		return nil, errors.New("must not be asked")
	})
	_, _, cert := runACMEFullOrderFlow(t, ts)
	if called {
		t.Fatal("no template configured, yet the resolver was asked")
	}
	if got := subjectDN(t, cert); got != "CN="+cert.DNSNames[0] {
		t.Fatalf("subject %q", got)
	}
}

func TestProvisionerTemplateReplacesDefault(t *testing.T) {
	s := &Server{templateID: "default-tpl"}
	if v := s.forProvisioner(Provisioner{Name: "p", TemplateID: "prov-tpl"}); v.templateID != "prov-tpl" {
		t.Fatalf("provisioner template: %q", v.templateID)
	}
	if v := s.forProvisioner(Provisioner{Name: "p"}); v.templateID != "default-tpl" {
		t.Fatalf("provisioner without a template keeps the default: %q", v.templateID)
	}
}
