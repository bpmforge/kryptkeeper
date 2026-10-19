// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certcentral

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"kryptkeeper/internal/migration"
)

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/export.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T) []migration.SourceObject {
	t.Helper()
	objs, err := New().Parse(context.Background(), migration.Input{Content: fixtureBytes(t)})
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

func TestParseExport(t *testing.T) {
	objs := parse(t)
	if len(objs) != 4 {
		t.Fatalf("want one object per product, got %d", len(objs))
	}
	if objs[0].SourceKey != "certcentral:ssl_basic" || objs[0].Name != "certcentral-ssl_basic" || objs[0].Kind != "product" {
		t.Fatalf("object: %+v", objs[0])
	}
}

func TestProductToTemplate(t *testing.T) {
	objs := parse(t)
	ssl := mapped(t, objs[0])
	st := ssl.Template
	if st.ValidityPeriod != "P730D" || st.Name != "certcentral-ssl_basic" || st.DisplayName != "Standard SSL" ||
		!reflect.DeepEqual(st.ExtendedKeyUsage, []string{"serverAuth", "clientAuth"}) ||
		!reflect.DeepEqual(st.KeyUsage, []string{"digitalSignature", "keyEncipherment"}) ||
		!reflect.DeepEqual(st.AllowedAlgorithms, []string{"RSA", "ECDSA"}) || st.MinKeySize != 2048 {
		t.Fatalf("ssl: %+v", st)
	}
	var hashUnmapped bool
	for _, f := range ssl.Fields {
		if f.Field == "signature_hash_types" && f.Status == migration.FieldUnmapped {
			hashUnmapped = true
		}
	}
	if !hashUnmapped {
		t.Fatalf("signature_hash_types should be unmapped: %+v", ssl.Fields)
	}
	cli := mapped(t, objs[1]).Template
	if cli.EnrolleeType != "user" || cli.ValidityPeriod != "P1095D" || !reflect.DeepEqual(cli.ExtendedKeyUsage, []string{"clientAuth", "emailProtection"}) {
		t.Fatalf("client: %+v", cli)
	}
	cs := mapped(t, objs[2]).Template
	if !reflect.DeepEqual(cs.ExtendedKeyUsage, []string{"codeSigning"}) || !reflect.DeepEqual(cs.KeyUsage, []string{"digitalSignature"}) || cs.ValidityPeriod != "P1095D" {
		t.Fatalf("code signing: %+v", cs)
	}
	if m := mapped(t, objs[3]); m.Unsupported != "unsupported product type email_security_plus" {
		t.Fatalf("got %q", m.Unsupported)
	}
	empty := migration.SourceObject{Name: "certcentral-x", Raw: map[string]any{"name_id": "x", "type": "ssl_certificate", "allowed_validity_years": []any{}}}
	if m := mapped(t, empty); m.Unsupported == "" {
		t.Fatal("empty validity years must be unsupported")
	}
}

func TestOrganizationsReportedNotTemplates(t *testing.T) {
	objs := parse(t)
	templates := 0
	for _, o := range objs {
		m := mapped(t, o)
		if m.Unsupported == "" {
			templates++
		}
		got := map[string]migration.FieldReport{}
		for _, f := range m.Fields {
			if strings.HasPrefix(f.Field, "organizations[") {
				got[f.Field] = f
			}
		}
		if len(got) != 2 {
			t.Fatalf("%s: organizations in report: %v", o.Name, got)
		}
		if f := got["organizations[Example Corp]"]; f.Status != migration.FieldPartial || !strings.Contains(f.Note, "OrganizationID") {
			t.Fatalf("active org: %+v", f)
		}
		if f := got["organizations[Acquired Co]"]; f.Status != migration.FieldUnmapped || f.Note != "inactive organization" {
			t.Fatalf("inactive org: %+v", f)
		}
		// Sorted by Field, so Acquired Co precedes Example Corp.
		var order []string
		for _, f := range m.Fields {
			if strings.HasPrefix(f.Field, "organizations[") {
				order = append(order, f.Field)
			}
		}
		if order[0] != "organizations[Acquired Co]" {
			t.Fatalf("not sorted: %v", order)
		}
	}
	if templates != 3 {
		t.Fatalf("4 products should give 3 templates, got %d", templates)
	}
}

func TestMapDeterministic(t *testing.T) {
	for _, o := range parse(t) {
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
	if d.Counts[migration.ActionCreate] != 3 || d.Counts[migration.ActionSkip] != 1 || d.Unsupported != 1 {
		t.Fatalf("counts %+v unsupported=%d", d.Counts, d.Unsupported)
	}
}
