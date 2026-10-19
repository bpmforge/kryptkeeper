// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package adcs

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"kryptkeeper/internal/adsync"
	"kryptkeeper/internal/migration"
)

var update = flag.Bool("update", false, "rewrite testdata/templates_20.json")

func ticks(days int) string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(-int64(days)*86400*10_000_000))
	return base64.StdEncoding.EncodeToString(b[:])
}

func ku(b byte) string { return base64.StdEncoding.EncodeToString([]byte{b, 0}) }

const ekuServer, ekuClient = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"

type tmplSpec struct {
	cn      string
	version string
	keySize string
	days    int
	eku     []string
	csp     string
	extra   map[string][]string
}

func (s tmplSpec) entry() map[string]any {
	attrs := map[string][]string{
		"cn": {s.cn}, "displayName": {s.cn + " Display"}, "msPKI-Cert-Template-OID": {"1.3.6.1.4.1.311.21.8." + s.cn},
		"msPKI-Template-Schema-Version": {s.version}, "msPKI-Minimal-Key-Size": {s.keySize},
		"pKIExpirationPeriod": {ticks(s.days)}, "pKIOverlapPeriod": {ticks(42)}, "pKIKeyUsage": {ku(0xA0)},
		"pKIExtendedKeyUsage": s.eku, "pKIDefaultCSPs": {s.csp}, "msPKI-Enrollment-Flag": {"32"},
		"msPKI-Certificate-Name-Flag": {"1"}, "msPKI-Private-Key-Flag": {"16842752"},
	}
	for k, v := range s.extra {
		attrs[k] = v
	}
	return map[string]any{"dn": "CN=" + s.cn + ",CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example", "attributes": attrs}
}

const rsaCSP = "1,Microsoft RSA SChannel Cryptographic Provider"
const ecCSP = "1,Microsoft Software Key Storage Provider ECDSA_P256"

func specs() []tmplSpec {
	var out []tmplSpec
	sizes := []string{"2048", "3072", "4096"}
	days := []int{365, 730, 1825}
	for i := 0; i < 14; i++ {
		eku := []string{ekuServer}
		if i%2 == 1 {
			eku = []string{ekuClient}
		}
		if i%5 == 0 {
			eku = []string{ekuServer, ekuClient}
		}
		out = append(out, tmplSpec{cn: fmt.Sprintf("Tpl%02d", i), version: []string{"2", "3"}[i%2], keySize: sizes[i%3], days: days[i%3], eku: eku, csp: rsaCSP})
	}
	out = append(out,
		tmplSpec{cn: "CustomEKU1", version: "2", keySize: "2048", days: 365, eku: []string{ekuServer, "1.3.6.1.4.1.99999.1"}, csp: rsaCSP},
		tmplSpec{cn: "CustomEKU2", version: "3", keySize: "4096", days: 730, eku: []string{ekuClient, "1.3.6.1.4.1.99999.2"}, csp: rsaCSP},
		tmplSpec{cn: "EcdsaA", version: "3", keySize: "256", days: 365, eku: []string{ekuServer}, csp: ecCSP},
		tmplSpec{cn: "EcdsaB", version: "3", keySize: "384", days: 1825, eku: []string{ekuClient}, csp: ecCSP},
		tmplSpec{cn: "LegacyV1A", version: "1", keySize: "1024", days: 365, eku: []string{ekuServer}, csp: rsaCSP},
		tmplSpec{cn: "LegacyV1B", version: "1", keySize: "1024", days: 730, eku: []string{ekuClient}, csp: rsaCSP},
	)
	return out
}

func buildFixture() []byte {
	entries := []map[string]any{}
	for _, s := range specs() {
		entries = append(entries, s.entry())
	}
	raw, _ := json.MarshalIndent(map[string]any{"templates": entries}, "", "  ")
	return append(raw, '\n')
}

func fixture(t *testing.T) []byte {
	t.Helper()
	if *update {
		if err := os.WriteFile("testdata/templates_20.json", buildFixture(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile("testdata/templates_20.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(buildFixture()) {
		t.Fatal("testdata/templates_20.json is stale; run go test -update")
	}
	return got
}

func parse(t *testing.T) []migration.SourceObject {
	t.Helper()
	objs, err := New().Parse(context.Background(), migration.Input{Content: fixture(t)})
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func TestParseExportAndBareArray(t *testing.T) {
	objs := parse(t)
	if len(objs) != 20 {
		t.Fatalf("export: %d objects", len(objs))
	}
	var wrapped struct {
		Templates json.RawMessage `json:"templates"`
	}
	_ = json.Unmarshal(fixture(t), &wrapped)
	bare, err := New().Parse(context.Background(), migration.Input{Content: wrapped.Templates})
	if err != nil || len(bare) != 20 {
		t.Fatalf("bare array: %d, %v", len(bare), err)
	}
	if objs[0].Kind != "template" || objs[0].Name != "Tpl00" || !strings.HasPrefix(objs[0].SourceKey, "CN=Tpl00,") {
		t.Fatalf("bad object: %+v", objs[0])
	}
}

func TestMapTwentyTemplates(t *testing.T) {
	sp := specs()
	objs := parse(t)
	mapped, unsupported := 0, 0
	validity := map[int]string{365: "P365D", 730: "P730D", 1825: "P1825D"}
	for i, o := range objs {
		m, err := New().Map(o)
		if err != nil {
			t.Fatal(err)
		}
		if m.Unsupported != "" {
			if !strings.Contains(m.Unsupported, "v1") || !strings.HasPrefix(sp[i].cn, "LegacyV1") {
				t.Fatalf("%s unexpectedly unsupported: %s", sp[i].cn, m.Unsupported)
			}
			unsupported++
			continue
		}
		mapped++
		var wantEKU []string
		for _, oid := range sp[i].eku {
			if n, ok := migration.EKUFromOID(oid); ok {
				wantEKU = append(wantEKU, n)
			}
		}
		var wantKey int
		fmt.Sscan(sp[i].keySize, &wantKey)
		tm := m.Template
		if tm.MinKeySize != wantKey || tm.ValidityPeriod != validity[sp[i].days] || !reflect.DeepEqual(tm.ExtendedKeyUsage, wantEKU) {
			t.Fatalf("%s: got key=%d validity=%s eku=%v", sp[i].cn, tm.MinKeySize, tm.ValidityPeriod, tm.ExtendedKeyUsage)
		}
		if tm.RenewalOverlap != "P42D" || !reflect.DeepEqual(tm.KeyUsage, []string{"digitalSignature", "keyEncipherment"}) {
			t.Fatalf("%s: overlap=%s ku=%v", sp[i].cn, tm.RenewalOverlap, tm.KeyUsage)
		}
		if strings.HasPrefix(sp[i].cn, "Ecdsa") != reflect.DeepEqual(tm.AllowedAlgorithms, []string{"ECDSA"}) {
			t.Fatalf("%s: algorithms %v", sp[i].cn, tm.AllowedAlgorithms)
		}
		if !tm.AutoEnroll || tm.RequireApproval {
			t.Fatalf("%s: flags", sp[i].cn)
		}
		for _, f := range m.Fields {
			if f.Status == "" {
				t.Fatalf("field without status: %+v", f)
			}
		}
	}
	if mapped != 18 || unsupported != 2 {
		t.Fatalf("mapped=%d unsupported=%d", mapped, unsupported)
	}
}

func mapSpec(t *testing.T, s tmplSpec) migration.Mapped {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"templates": []any{s.entry()}})
	objs, err := New().Parse(context.Background(), migration.Input{Content: b})
	if err != nil {
		t.Fatal(err)
	}
	m, err := New().Map(objs[0])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCustomEKUOIDGoesToUnmappedList(t *testing.T) {
	m := mapSpec(t, tmplSpec{cn: "C", version: "2", keySize: "2048", days: 365, eku: []string{ekuServer, "1.2.3.4"}, csp: rsaCSP})
	found := false
	for _, f := range m.Fields {
		if f.Field == "pKIExtendedKeyUsage[1.2.3.4]" && f.Status == migration.FieldUnmapped && f.Note == "custom OID" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom OID not reported: %+v", m.Fields)
	}
	only := mapSpec(t, tmplSpec{cn: "C", version: "2", keySize: "2048", days: 365, eku: []string{"1.2.3.4"}, csp: rsaCSP})
	if only.Unsupported != "no mappable extended key usage" {
		t.Fatalf("got %q", only.Unsupported)
	}
}

func TestEnrollmentAndNameFlags(t *testing.T) {
	m := mapSpec(t, tmplSpec{cn: "F", version: "2", keySize: "2048", days: 365, eku: []string{ekuClient}, csp: rsaCSP,
		extra: map[string][]string{"msPKI-Enrollment-Flag": {"2"}, "msPKI-Certificate-Name-Flag": {"33554432"}}})
	if !m.Template.RequireApproval || m.Template.AutoEnroll || m.Template.EnrolleeType != "user" {
		t.Fatalf("flags: %+v", m.Template)
	}
	m = mapSpec(t, tmplSpec{cn: "F", version: "2", keySize: "2048", days: 365, eku: []string{ekuClient}, csp: rsaCSP,
		extra: map[string][]string{"msPKI-Enrollment-Flag": {"32"}, "msPKI-Certificate-Name-Flag": {"1"}}})
	if m.Template.RequireApproval || !m.Template.AutoEnroll || m.Template.EnrolleeType != "machine" {
		t.Fatalf("flags: %+v", m.Template)
	}
}

func TestUnreadableExpirationPeriodIsUnsupported(t *testing.T) {
	for _, bad := range []string{"", "!!notbase64", base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), base64.StdEncoding.EncodeToString(make([]byte, 8))} {
		m := mapSpec(t, tmplSpec{cn: "E", version: "2", keySize: "2048", days: 365, eku: []string{ekuClient}, csp: rsaCSP,
			extra: map[string][]string{"pKIExpirationPeriod": {bad}}})
		if m.Unsupported != "missing or unreadable pKIExpirationPeriod" {
			t.Fatalf("%q: got %q", bad, m.Unsupported)
		}
	}
}

type fakeLDAP struct {
	t       *testing.T
	entries []adsync.LDAPEntry
	closed  bool
	base    string
	filter  string
}

func (f *fakeLDAP) Search(base, filter string, _ []string) ([]adsync.LDAPEntry, error) {
	f.base, f.filter = base, filter
	return f.entries, nil
}
func (f *fakeLDAP) Add(string, map[string][]string) error { f.t.Fatal("Add called"); return nil }
func (f *fakeLDAP) Modify(string, []adsync.LDAPChange) error {
	f.t.Fatal("Modify called")
	return nil
}
func (f *fakeLDAP) Delete(string) error { f.t.Fatal("Delete called"); return nil }
func (f *fakeLDAP) Close() error        { f.closed = true; return nil }

func TestReadIsReadOnly(t *testing.T) {
	// The directory returns raw bytes for the binary attributes.
	rawTicks, _ := base64.StdEncoding.DecodeString(ticks(365))
	rawKU := string([]byte{0xA0, 0})
	fl := &fakeLDAP{t: t, entries: []adsync.LDAPEntry{{DN: "CN=Web,CN=Certificate Templates,DC=x", Attributes: map[string][]string{
		"cn": {"Web"}, "msPKI-Template-Schema-Version": {"2"}, "pKIExpirationPeriod": {string(rawTicks)}, "pKIKeyUsage": {rawKU},
		"pKIExtendedKeyUsage": {ekuServer}, "pKIDefaultCSPs": {rsaCSP},
	}}}}
	old := dial
	dial = func(string, string, string, bool) (adsync.LDAPClient, error) { return fl, nil }
	defer func() { dial = old }()

	objs, err := New().Read(context.Background(), migration.ReadOptions{URL: "ldaps://x", BaseDN: "CN=Certificate Templates,DC=x"})
	if err != nil || len(objs) != 1 {
		t.Fatalf("read: %v %d", err, len(objs))
	}
	if !fl.closed || fl.filter != "(objectClass=pKICertificateTemplate)" || fl.base != "CN=Certificate Templates,DC=x" {
		t.Fatalf("search: %+v", fl)
	}
	m, err := New().Map(objs[0])
	if err != nil || m.Unsupported != "" || m.Template.ValidityPeriod != "P365D" || m.Template.KeyUsage[0] != "digitalSignature" {
		t.Fatalf("map of live object: %+v %v", m, err)
	}
}

func TestReadRequiresBaseDN(t *testing.T) {
	if _, err := New().Read(context.Background(), migration.ReadOptions{URL: "ldaps://x"}); err == nil || !strings.Contains(err.Error(), "base_dn required") {
		t.Fatalf("got %v", err)
	}
}

func TestMapDeterministic(t *testing.T) {
	for _, o := range parse(t) {
		a, _ := New().Map(o)
		b, _ := New().Map(o)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: nondeterministic", o.Name)
		}
	}
}

type sink struct{ names map[string]bool }

func (s *sink) FindByName(_ context.Context, n string) (string, bool, error) {
	return "", s.names[n], nil
}
func (s *sink) Create(context.Context, migration.Template) (string, error) { return "id", nil }
func (s *sink) Disable(context.Context, string) error                      { return nil }
func (s *sink) HasPendingApprovals(context.Context, string) (bool, error)  { return false, nil }

type store struct{ migration.Store }

func (store) FindActiveItem(context.Context, string, string) (migration.BatchItem, bool, error) {
	return migration.BatchItem{}, false, nil
}

func TestDryRunThroughService(t *testing.T) {
	svc := migration.NewService(&sink{names: map[string]bool{}}, store{}, New())
	d, err := svc.DryRun(context.Background(), migration.Input{Source: Source, Content: fixture(t)})
	if err != nil {
		t.Fatal(err)
	}
	if d.Counts[migration.ActionCreate] != 18 || d.Counts[migration.ActionSkip] != 2 || d.Unsupported != 2 {
		t.Fatalf("counts: %+v unsupported=%d", d.Counts, d.Unsupported)
	}
}

// B5 (ADCS cutover rehearsal): templates for domain controllers, Kerberos and
// RAS became machine autoenroll templates and a workstation tried to enroll
// them. Their purpose is read from the EKU set (and, for RAS, whose EKUs are
// plain client+server auth, the template name): they are not autoenrolled and
// are restricted until an admin grants them.
func TestDCKerberosRASTemplatesAreRestricted(t *testing.T) {
	const (
		ekuKDC       = "1.3.6.1.5.2.3.5"
		ekuSmartcard = "1.3.6.1.4.1.311.20.2.2"
		ekuIKE       = "1.3.6.1.5.5.8.2.2"
	)
	restricted := []tmplSpec{
		{cn: "DomainControllerAuthentication", version: "2", keySize: "2048", days: 365, eku: []string{ekuClient, ekuServer, ekuSmartcard}, csp: rsaCSP},
		{cn: "KerberosAuthentication", version: "2", keySize: "2048", days: 365, eku: []string{ekuClient, ekuServer, ekuSmartcard, ekuKDC}, csp: rsaCSP},
		{cn: "RASAndIASServer", version: "2", keySize: "2048", days: 365, eku: []string{ekuClient, ekuServer}, csp: rsaCSP},
		{cn: "CustomKDC", version: "2", keySize: "2048", days: 365, eku: []string{ekuServer, ekuKDC}, csp: rsaCSP},
		{cn: "IPsecGateway", version: "2", keySize: "2048", days: 365, eku: []string{ekuServer, ekuIKE}, csp: rsaCSP},
		{cn: "OCSPResponseSigning", version: "3", keySize: "2048", days: 14, eku: []string{"1.3.6.1.5.5.7.3.9"}, csp: rsaCSP},
		{cn: "CustomOCSP", version: "2", keySize: "2048", days: 14, eku: []string{"1.3.6.1.5.5.7.3.9"}, csp: rsaCSP},
		{cn: "CAExchange", version: "2", keySize: "2048", days: 365, eku: []string{"1.3.6.1.4.1.311.21.5"}, csp: rsaCSP},
		{cn: "CrossCA", version: "2", keySize: "2048", days: 365, csp: rsaCSP},
		{cn: "EnrollmentAgent", version: "2", keySize: "2048", days: 730, eku: []string{"1.3.6.1.4.1.311.20.2.1"}, csp: rsaCSP},
		{cn: "KeyRecoveryAgent", version: "2", keySize: "2048", days: 730, eku: []string{"1.3.6.1.4.1.311.21.6"}, csp: rsaCSP},
		// EKUs held only in the v2+ application-policy attribute count too.
		{cn: "AppPolicyKDC", version: "2", keySize: "2048", days: 365, eku: []string{ekuServer}, csp: rsaCSP,
			extra: map[string][]string{"msPKI-Certificate-Application-Policy": {ekuServer, ekuKDC}}},
	}
	for _, s := range restricted {
		m := mapSpec(t, s)
		// A template with no mappable EKU is not imported at all, so it can
		// never be offered; the rest must be restricted.
		if m.Unsupported != "" {
			if strings.Contains(s.cn, "OCSP") || !strings.Contains(m.Unsupported, "extended key usage") {
				t.Fatalf("%s unsupported: %s", s.cn, m.Unsupported)
			}
			continue
		}
		if m.Template.AutoEnroll || strings.Join(m.Template.EnrollRoles, ",") != "pki-admin,protocol:wstep:restricted" {
			t.Fatalf("%s must not be offered to general autoenrollment: auto=%v roles=%v", s.cn, m.Template.AutoEnroll, m.Template.EnrollRoles)
		}
		if len(m.Notes) != 1 || !strings.Contains(m.Notes[0], "protocol:wstep") {
			t.Fatalf("%s: the dry run must say how to grant it: %v", s.cn, m.Notes)
		}
	}
	general := []tmplSpec{
		{cn: "Workstation", version: "2", keySize: "2048", days: 365, eku: []string{ekuClient}, csp: rsaCSP},
		// Smart-card logon on a USER template is an ordinary user certificate.
		{cn: "SmartcardUser", version: "2", keySize: "2048", days: 365, eku: []string{ekuClient, ekuSmartcard}, csp: rsaCSP,
			extra: map[string][]string{"msPKI-Certificate-Name-Flag": {"33554432"}}},
	}
	for _, s := range general {
		m := mapSpec(t, s)
		if !m.Template.AutoEnroll || m.Template.EnrollRoles != nil || len(m.Notes) != 0 {
			t.Fatalf("%s must stay a general autoenroll template: %+v notes=%v", s.cn, m.Template, m.Notes)
		}
	}
}
