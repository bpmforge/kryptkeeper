// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keyfactor

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"kryptkeeper/internal/migration"
)

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/templates.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseBytes(t *testing.T, b []byte) []migration.SourceObject {
	t.Helper()
	objs, err := New().Parse(context.Background(), migration.Input{Content: b})
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func mapped(t *testing.T, o migration.SourceObject) migration.Mapped {
	t.Helper()
	m, err := New().Map(o)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func unmappedOf(m migration.Mapped) []string {
	var out []string
	for _, f := range m.Fields {
		if f.Status == migration.FieldUnmapped {
			out = append(out, f.Field)
		}
	}
	sort.Strings(out)
	return out
}

func TestParseArrayAndWrapped(t *testing.T) {
	arr := parseBytes(t, fixtureBytes(t))
	wrapped := parseBytes(t, []byte(`{"templates":`+string(fixtureBytes(t))+`}`))
	if len(arr) != 5 || !reflect.DeepEqual(arr, wrapped) {
		t.Fatalf("shapes differ: %d vs %d", len(arr), len(wrapped))
	}
	if arr[0].SourceKey != "keyfactor:1" || arr[0].Name != "WebServer" || arr[0].Kind != "template" {
		t.Fatalf("object: %+v", arr[0])
	}
}

func TestMapTemplates(t *testing.T) {
	objs := parseBytes(t, fixtureBytes(t))
	web, cli, ec, custom, dsa := mapped(t, objs[0]), mapped(t, objs[1]), mapped(t, objs[2]), mapped(t, objs[3]), mapped(t, objs[4])

	w := web.Template
	if w.MinKeySize != 2048 || !reflect.DeepEqual(w.AllowedAlgorithms, []string{"RSA"}) ||
		!reflect.DeepEqual(w.KeyUsage, []string{"digitalSignature", "keyEncipherment"}) ||
		!reflect.DeepEqual(w.ExtendedKeyUsage, []string{"serverAuth"}) || w.DisplayName != "Web Server" || w.OID == "" ||
		w.ValidityPeriod != "P365D" || w.AutoEnroll || w.RequireApproval || w.EnrolleeType != "machine" {
		t.Fatalf("web: %+v", w)
	}
	wantWeb := []string{"AllowedRequesters", "ConfigurationTenant", "EnrollmentFields", "ForestRoot", "KeyRetention", "KeyRetentionDays", "RFCEnforcement", "TemplateRegexes", "UseAllowedRequesters"}
	if got := unmappedOf(web); !reflect.DeepEqual(got, wantWeb) {
		t.Fatalf("web unmapped: %v", got)
	}
	for _, f := range web.Fields {
		if f.Field == "AllowedRequesters" && !strings.Contains(f.Note, "ACL") {
			t.Fatalf("requester note: %+v", f)
		}
	}

	if cli.Template.MinKeySize != 3072 || !reflect.DeepEqual(cli.Template.KeyUsage, []string{"digitalSignature", "keyEncipherment"}) ||
		!reflect.DeepEqual(cli.Template.ExtendedKeyUsage, []string{"clientAuth"}) || len(unmappedOf(cli)) != 0 {
		t.Fatalf("client: %+v unmapped=%v", cli.Template, unmappedOf(cli))
	}

	if !reflect.DeepEqual(ec.Template.AllowedAlgorithms, []string{"ECDSA"}) || ec.Template.MinKeySize != 256 ||
		!reflect.DeepEqual(ec.Template.KeyUsage, []string{"digitalSignature", "keyAgreement"}) ||
		!reflect.DeepEqual(ec.Template.ExtendedKeyUsage, []string{"clientAuth", "serverAuth"}) {
		t.Fatalf("ec: %+v", ec.Template)
	}

	// 224 = digitalSignature + contentCommitment + keyEncipherment.
	if !reflect.DeepEqual(custom.Template.KeyUsage, []string{"digitalSignature", "contentCommitment", "keyEncipherment"}) {
		t.Fatalf("custom key usage: %v", custom.Template.KeyUsage)
	}
	if got := unmappedOf(custom); !reflect.DeepEqual(got, []string{"ExtendedKeyUsages[1.3.6.1.4.1.99999.7]"}) {
		t.Fatalf("custom unmapped: %v", got)
	}
	if !reflect.DeepEqual(custom.Template.ExtendedKeyUsage, []string{"serverAuth"}) || custom.Unsupported != "" {
		t.Fatalf("custom eku: %+v", custom)
	}

	if !strings.Contains(dsa.Unsupported, "key type") {
		t.Fatalf("dsa: %q", dsa.Unsupported)
	}
}

func TestKeyUsageCABitsAndZero(t *testing.T) {
	o := migration.SourceObject{Name: "x", Raw: map[string]any{"TemplateName": "x", "KeyType": "RSA", "KeyUsage": json.Number("130"),
		"ExtendedKeyUsages": []any{map[string]any{"Oid": "1.3.6.1.5.5.7.3.1"}}}}
	m := mapped(t, o)
	if !reflect.DeepEqual(unmappedOf(m), []string{"KeyUsage[cRLSign]"}) || !reflect.DeepEqual(m.Template.KeyUsage, []string{"digitalSignature"}) {
		t.Fatalf("%+v", m)
	}
	o.Raw["KeyUsage"] = json.Number("0")
	if m := mapped(t, o); m.Unsupported == "" {
		t.Fatal("zero key usage must be unsupported")
	}
}

func TestEveryFieldAccountedFor(t *testing.T) {
	for _, o := range parseBytes(t, fixtureBytes(t)) {
		m := mapped(t, o)
		count := map[string]int{}
		for _, f := range m.Fields {
			count[f.Field]++
		}
		for k := range o.Raw {
			if count[k] != 1 {
				t.Fatalf("%s: input key %q has %d reports", o.Name, k, count[k])
			}
		}
	}
}

func TestMapDeterministic(t *testing.T) {
	for _, o := range parseBytes(t, fixtureBytes(t)) {
		ja, _ := json.Marshal(mapped(t, o))
		jb, _ := json.Marshal(mapped(t, o))
		if string(ja) != string(jb) {
			t.Fatalf("%s: nondeterministic", o.Name)
		}
	}
}

type sink struct{}

func (sink) FindByName(context.Context, string) (string, bool, error)   { return "", false, nil }
func (sink) Create(context.Context, migration.Template) (string, error) { return "id", nil }
func (sink) Disable(context.Context, string) error                      { return nil }
func (sink) HasPendingApprovals(context.Context, string) (bool, error)  { return false, nil }

type store struct{ migration.Store }

func (store) FindActiveItem(context.Context, string, string) (migration.BatchItem, bool, error) {
	return migration.BatchItem{}, false, nil
}

func TestDryRunThroughService(t *testing.T) {
	d, err := migration.NewService(sink{}, store{}, New()).DryRun(context.Background(), migration.Input{Source: Source, Content: fixtureBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	if d.Counts[migration.ActionCreate] != 4 || d.Counts[migration.ActionSkip] != 1 || d.Unsupported != 1 {
		t.Fatalf("counts %+v unsupported=%d", d.Counts, d.Unsupported)
	}
}
