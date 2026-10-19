// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/migration"
)

func parseBytes(t *testing.T, b []byte) []migration.SourceObject {
	t.Helper()
	objs, err := New().Parse(context.Background(), migration.Input{Content: b})
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func fixtureObjs(t *testing.T) []migration.SourceObject {
	b, err := os.ReadFile("testdata/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	return parseBytes(t, b)
}

func mapRole(t *testing.T, role string) migration.Mapped {
	t.Helper()
	objs := parseBytes(t, []byte(`{"roles":{"r":`+role+`}}`))
	m, err := New().Map(objs[0])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseBothShapes(t *testing.T) {
	raw := parseBytes(t, []byte(`{"roles":{"b":{"ttl":60},"a":{"ttl":30}}}`))
	wrapped := parseBytes(t, []byte(`{"roles":{"b":{"data":{"ttl":60}},"a":{"data":{"ttl":30}}}}`))
	if len(raw) != 2 || raw[0].Name != "a" || raw[1].SourceKey != "vault:b" || raw[0].Kind != "role" {
		t.Fatalf("raw: %+v", raw)
	}
	if !reflect.DeepEqual(raw, wrapped) {
		t.Fatalf("shapes differ:\n%+v\n%+v", raw, wrapped)
	}
	if len(fixtureObjs(t)) != 3 {
		t.Fatal("fixture should hold 3 roles")
	}
}

func TestRoleSetMapsAtLeast90Percent(t *testing.T) {
	var all []migration.FieldReport
	var unmapped []string
	for _, o := range fixtureObjs(t) {
		m, err := New().Map(o)
		if err != nil || m.Unsupported != "" {
			t.Fatalf("%s: %v %q", o.Name, err, m.Unsupported)
		}
		for _, f := range m.Fields {
			all = append(all, f)
			if f.Status == migration.FieldUnmapped {
				if f.Note == "" {
					t.Fatalf("%s.%s unmapped without a note", o.Name, f.Field)
				}
				unmapped = append(unmapped, o.Name+"."+f.Field)
			}
		}
	}
	real := 0
	for _, f := range all {
		if !strings.HasPrefix(f.Field, "(") {
			real++
		}
	}
	if real < 45 {
		t.Fatalf("fixture too small: %d fields", real)
	}
	if p := migration.PercentMapped(all); p < 90 {
		t.Fatalf("only %d%% mapped", p)
	}
	sort.Strings(unmapped)
	want := []string{"example-dot-com.organization", "example-dot-com.ou", "internal-ec.no_store", "internal-ec.signature_bits", "codesign.use_pss"}
	sort.Strings(want)
	if !reflect.DeepEqual(unmapped, want) {
		t.Fatalf("unmapped set drifted: %v", unmapped)
	}
}

func TestDomainFlagsToNamePolicy(t *testing.T) {
	cases := []struct {
		sub, bare string
		want      ca.NamePolicy
		note      bool
	}{
		{"true", "true", ca.NamePolicy{AllowedDNSSuffixes: []string{"d.io"}}, false},
		{"true", "false", ca.NamePolicy{AllowedDNSSuffixes: []string{".d.io"}}, false},
		{"false", "true", ca.NamePolicy{AllowedDNSNames: []string{"d.io"}}, false},
		{"false", "false", ca.NamePolicy{}, true},
	}
	for _, c := range cases {
		m := mapRole(t, `{"allowed_domains":"d.io","allow_subdomains":`+c.sub+`,"allow_bare_domains":`+c.bare+`}`)
		if !reflect.DeepEqual(*m.Template.NamePolicy, c.want) {
			t.Fatalf("sub=%s bare=%s: %+v", c.sub, c.bare, *m.Template.NamePolicy)
		}
		noted := false
		for _, f := range m.Fields {
			if f.Field == "allowed_domains" && f.Status == migration.FieldPartial && strings.Contains(f.Note, "no effect") {
				noted = true
			}
		}
		if noted != c.note {
			t.Fatalf("sub=%s bare=%s: note=%v", c.sub, c.bare, noted)
		}
	}
	m := mapRole(t, `{"allow_any_name":true,"allowed_domains":["x.io"]}`)
	if m.Template.NamePolicy != nil {
		t.Fatal("allow_any_name must leave NamePolicy nil")
	}
	m = mapRole(t, `{"allowed_domains":["x.io"],"allow_subdomains":true,"allowed_uri_sans":["spiffe://corp/*","urn:exact"]}`)
	np := m.Template.NamePolicy
	if !np.AllowURISANs || !reflect.DeepEqual(np.AllowedURIPrefixes, []string{"spiffe://corp/"}) {
		t.Fatalf("uri: %+v", np)
	}
	un := false
	for _, f := range m.Fields {
		if f.Field == "allowed_uri_sans[urn:exact]" && f.Status == migration.FieldUnmapped {
			un = true
		}
	}
	if !un {
		t.Fatal("non-prefix URI SAN not reported unmapped")
	}
}

func TestTTLForms(t *testing.T) {
	for role, want := range map[string]string{
		`{"ttl":3600}`:                   "P1D",
		`{"ttl":"72h"}`:                  "P3D",
		`{"ttl":"86400"}`:                "P1D",
		`{"max_ttl":"720h"}`:             "P30D",
		`{"ttl":"24h","max_ttl":"720h"}`: "P1D",
		`{}`:                             "P32D",
		`{"ttl":0,"max_ttl":0}`:          "P32D",
	} {
		if m := mapRole(t, role); m.Template.ValidityPeriod != want {
			t.Fatalf("%s: got %s want %s", role, m.Template.ValidityPeriod, want)
		}
	}
	m := mapRole(t, `{"ttl":"nonsense"}`)
	if m.Template.ValidityPeriod != "P32D" {
		t.Fatal("unreadable ttl should fall back to the default")
	}
	for _, f := range m.Fields {
		if f.Field == "ttl" && f.Status != migration.FieldUnmapped {
			t.Fatalf("unreadable ttl: %+v", f)
		}
	}
}

func TestEd25519Unsupported(t *testing.T) {
	if m := mapRole(t, `{"key_type":"ed25519"}`); !strings.Contains(m.Unsupported, "Ed25519") {
		t.Fatalf("got %q", m.Unsupported)
	}
}

func TestUnknownEKUNameUnmapped(t *testing.T) {
	m := mapRole(t, `{"ext_key_usage":["ServerAuth","Bogus"],"ext_key_usage_oids":["1.2.3"]}`)
	got := map[string]migration.FieldStatus{}
	for _, f := range m.Fields {
		got[f.Field] = f.Status
	}
	if got["ext_key_usage[Bogus]"] != migration.FieldUnmapped || got["ext_key_usage_oids[1.2.3]"] != migration.FieldUnmapped {
		t.Fatalf("fields: %+v", got)
	}
	if !reflect.DeepEqual(m.Template.ExtendedKeyUsage, []string{"clientAuth", "serverAuth"}) {
		t.Fatalf("eku %v", m.Template.ExtendedKeyUsage)
	}
}

func TestCodeSigningRoleEKU(t *testing.T) {
	m := mapRole(t, `{"server_flag":false,"client_flag":false,"code_signing_flag":true}`)
	if !reflect.DeepEqual(m.Template.ExtendedKeyUsage, []string{"codeSigning"}) {
		t.Fatalf("eku %v", m.Template.ExtendedKeyUsage)
	}
	if m := mapRole(t, `{"server_flag":false,"client_flag":false}`); m.Unsupported != "no extended key usage" {
		t.Fatalf("got %q", m.Unsupported)
	}
}

func TestKeyTypeAndSize(t *testing.T) {
	cases := map[string]struct {
		algs []string
		bits int
	}{
		`{}`:                                 {[]string{"RSA"}, 2048},
		`{"key_type":"ec"}`:                  {[]string{"ECDSA"}, 256},
		`{"key_type":"any","key_bits":3072}`: {[]string{"RSA", "ECDSA"}, 3072},
	}
	for role, w := range cases {
		m := mapRole(t, role)
		if !reflect.DeepEqual(m.Template.AllowedAlgorithms, w.algs) || m.Template.MinKeySize != w.bits {
			t.Fatalf("%s: %v %d", role, m.Template.AllowedAlgorithms, m.Template.MinKeySize)
		}
	}
	m := mapRole(t, `{"key_usage":["CertSign","DigitalSignature"]}`)
	if !reflect.DeepEqual(m.Template.KeyUsage, []string{"digitalSignature"}) {
		t.Fatalf("ku %v", m.Template.KeyUsage)
	}
}

func TestMapDeterministic(t *testing.T) {
	for _, o := range fixtureObjs(t) {
		a, _ := New().Map(o)
		b, _ := New().Map(o)
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if string(ja) != string(jb) {
			t.Fatalf("%s: nondeterministic", o.Name)
		}
	}
}

func TestAbsentServerAndClientFlagsDefaultTrue(t *testing.T) {
	m := mapRole(t, `{}`)
	if !reflect.DeepEqual(m.Template.ExtendedKeyUsage, []string{"clientAuth", "serverAuth"}) {
		t.Fatalf("eku %v", m.Template.ExtendedKeyUsage)
	}
}
