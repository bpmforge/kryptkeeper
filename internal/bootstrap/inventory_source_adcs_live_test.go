// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// W13-04: live ADCS inventory pull over LDAP. The LDAP boundary is an
// injected interface, so these tests exercise the pull/parse/paging
// logic against a fake directory with no real domain controller.

func adcsTestCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	return der
}

// fakeLDAP records how it was queried so a test can prove the paged
// search control was requested, not a plain (truncatable) search.
type fakeLDAP struct {
	bindUser   string
	bindPass   string
	bindErr    error
	entries    []*ldap.Entry
	pagedSize  uint32
	pagedCalls int
}

func (f *fakeLDAP) Bind(username, password string) error {
	f.bindUser, f.bindPass = username, password
	return f.bindErr
}

func (f *fakeLDAP) SearchWithPaging(_ *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	f.pagedCalls++
	f.pagedSize = pagingSize
	return &ldap.SearchResult{Entries: f.entries}, nil
}

func (f *fakeLDAP) Close() error { return nil }

func entryWithCert(dn string, ders ...[]byte) *ldap.Entry {
	return &ldap.Entry{DN: dn, Attributes: []*ldap.EntryAttribute{
		{Name: "userCertificate", ByteValues: ders},
	}}
}

func TestADCSLivePullsAndPagesUserCertificates(t *testing.T) {
	der1 := adcsTestCertDER(t, "one.corp.example.com")
	der2 := adcsTestCertDER(t, "two.corp.example.com")
	fake := &fakeLDAP{entries: []*ldap.Entry{
		entryWithCert("CN=one", der1),
		entryWithCert("CN=two", der2),
	}}
	src := &adcsLiveSource{
		url: "ldaps://dc.example.com:636", bindDN: "CN=svc,DC=corp", password: "s3cret",
		searchBase: "DC=corp,DC=example,DC=com", filter: defaultADCSFilter, pageSize: 1000,
		dial: func(string) (ldapConn, error) { return fake, nil },
	}

	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 synced certs, got %d", len(got))
	}
	if !strings.Contains(got[0].PEM, "BEGIN CERTIFICATE") || got[0].UpstreamStatus != "active" {
		t.Fatalf("cert not PEM-wrapped/active: %+v", got[0])
	}
	// The bind used the injected credential, not the config DN as password.
	if fake.bindUser != "CN=svc,DC=corp" || fake.bindPass != "s3cret" {
		t.Fatalf("bind credential wrong: %q / %q", fake.bindUser, fake.bindPass)
	}
	// Paging must have been requested with a non-zero size — a plain
	// search would let a DC silently truncate the estate at MaxPageSize.
	if fake.pagedCalls != 1 || fake.pagedSize == 0 {
		t.Fatalf("paged search not requested: calls=%d size=%d", fake.pagedCalls, fake.pagedSize)
	}
}

func TestADCSLiveSkipsUnparseableBlobs(t *testing.T) {
	good := adcsTestCertDER(t, "good.example.com")
	fake := &fakeLDAP{entries: []*ldap.Entry{
		entryWithCert("CN=good", good),
		entryWithCert("CN=junk", []byte("not-a-certificate")),
	}}
	src := &adcsLiveSource{
		url: "ldaps://x", bindDN: "CN=svc", password: "p",
		searchBase: "DC=x", filter: defaultADCSFilter, pageSize: 1000,
		dial: func(string) (ldapConn, error) { return fake, nil },
	}
	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("junk blob must be skipped, not fatal: got %d", len(got))
	}
	// Sanity: the surviving cert round-trips.
	block, _ := pem.Decode([]byte(got[0].PEM))
	if block == nil {
		t.Fatal("surviving cert must be valid PEM")
	}
}

func TestADCSLiveBindFailurePropagates(t *testing.T) {
	fake := &fakeLDAP{bindErr: errors.New("invalid credentials")}
	src := &adcsLiveSource{
		url: "ldaps://x", bindDN: "CN=svc", password: "wrong",
		searchBase: "DC=x", filter: defaultADCSFilter, pageSize: 1000,
		dial: func(string) (ldapConn, error) { return fake, nil },
	}
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("a bind failure must surface, not yield a partial result")
	}
}

func TestADCSLiveRequiresConfigAndCredential(t *testing.T) {
	creds := commercialCreds(t, "s3cret")
	// Missing ldap_url.
	if _, err := newADCSLiveSource(context.Background(), `{"search_base":"DC=x"}`, "ldap-cred", creds); err == nil {
		t.Fatal("missing ldap_url must be rejected")
	}
	// Missing search_base.
	if _, err := newADCSLiveSource(context.Background(), `{"ldap_url":"ldaps://x"}`, "ldap-cred", creds); err == nil {
		t.Fatal("missing search_base must be rejected")
	}
	// Missing credential_ref.
	if _, err := newADCSLiveSource(context.Background(), `{"ldap_url":"ldaps://x","search_base":"DC=x","bind_dn":"CN=svc"}`, "", creds); err == nil {
		t.Fatal("missing credential_ref must be rejected")
	}
}

func TestADCSBindPasswordUnwrapsJSONPayloads(t *testing.T) {
	for in, want := range map[string]string{
		`"s3cret!"`:                "s3cret!",
		`{"password":"s3cret!"}`:   "s3cret!",
		"s3cret!\n":                "s3cret!",
		`  "with space inside "  `: "with space inside ",
	} {
		if got := adcsBindPassword([]byte(in)); got != want {
			t.Errorf("adcsBindPassword(%q) = %q, want %q", in, got, want)
		}
	}
}
