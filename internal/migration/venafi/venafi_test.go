// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package venafi

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

const web = `\VED\Policy\Certificates\Web Servers`

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/policy_tree.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T) map[string]migration.SourceObject {
	t.Helper()
	objs, err := New().Parse(context.Background(), migration.Input{Content: fixtureBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]migration.SourceObject{}
	for _, o := range objs {
		out[o.Raw["path"].(string)] = o
	}
	return out
}

func mapped(t *testing.T, o migration.SourceObject) migration.Mapped {
	t.Helper()
	m, err := New().Map(o)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseInheritanceAndContainers(t *testing.T) {
	objs := parse(t)
	if len(objs) != 4 {
		t.Fatalf("want 4 objects (empty container skipped), got %d", len(objs))
	}
	if _, ok := objs[`\VED\Policy\Certificates\Empty`]; ok {
		t.Fatal("container folder produced an object")
	}
	ws := objs[web]
	eff := ws.Raw["effective"].(map[string][]string)
	own := ws.Raw["own"].(map[string][]string)
	if got := eff["Management Type"]; !reflect.DeepEqual(got, []string{"Enrollment"}) {
		t.Fatalf("child must override parent: %v", got)
	}
	if len(own) != 11 || ws.SourceKey != "venafi:"+web || ws.Kind != "folder" {
		t.Fatalf("own=%d key=%s", len(own), ws.SourceKey)
	}
	// Web-Servers sets no Contact itself; it inherits the parent's.
	inh := objs[`\VED\Policy\Certificates\Web-Servers`].Raw
	if got := inh["effective"].(map[string][]string)["Contact"]; !reflect.DeepEqual(got, []string{"AD+corp:pki-team"}) {
		t.Fatalf("inherited contact: %v", got)
	}
	if _, ok := inh["own"].(map[string][]string)["Contact"]; ok {
		t.Fatal("inherited attribute leaked into own")
	}
}

func TestFolderExportMapsAtLeast90Percent(t *testing.T) {
	var all []migration.FieldReport
	var unmapped []string
	for p, o := range parse(t) {
		m := mapped(t, o)
		if m.Unsupported != "" {
			t.Fatalf("%s: %s", p, m.Unsupported)
		}
		for _, f := range m.Fields {
			all = append(all, f)
			if f.Status == migration.FieldUnmapped {
				if f.Note == "" {
					t.Fatalf("%s.%s unmapped without a note", p, f.Field)
				}
				unmapped = append(unmapped, o.Name+"."+f.Field)
			}
		}
	}
	if p := migration.PercentMapped(all); p < 90 {
		t.Fatalf("only %d%% mapped", p)
	}
	sort.Strings(unmapped)
	if want := []string{"Certificates-Web-Servers.Certificate Authority"}; !reflect.DeepEqual(unmapped, want) {
		t.Fatalf("unmapped set drifted: %v", unmapped)
	}
}

func TestOwnershipAndRenewalIncluded(t *testing.T) {
	objs := parse(t)
	ws := mapped(t, objs[web]).Template
	if ws.OwnerHint != "AD+corp:alice,local:{guid}" || !ws.RequireApproval || !ws.AutoEnroll || ws.RenewalOverlap != "P30D" {
		t.Fatalf("web servers: %+v", ws)
	}
	if ws.MinKeySize != 3072 || ws.ValidityPeriod != "P365D" || !reflect.DeepEqual(ws.AllowedAlgorithms, []string{"RSA"}) {
		t.Fatalf("web servers key/validity: %+v", ws)
	}
	if ws.NamePolicy == nil || !reflect.DeepEqual(ws.NamePolicy.AllowedDNSSuffixes, []string{"corp.example.com", "example.com"}) {
		t.Fatalf("name policy: %+v", ws.NamePolicy)
	}
	in := mapped(t, objs[`\VED\Policy\Certificates\Internal`]).Template
	if in.AutoEnroll || in.RenewalOverlap != "P14D" || in.ValidityPeriod != "P90D" || in.RequireApproval ||
		!reflect.DeepEqual(in.AllowedAlgorithms, []string{"ECDSA"}) || in.MinKeySize != 256 {
		t.Fatalf("internal: %+v", in)
	}
	// Inheritance feeds template values: Web-Servers inherits the contact.
	if h := mapped(t, objs[`\VED\Policy\Certificates\Web-Servers`]).Template; h.OwnerHint != "AD+corp:pki-team" {
		t.Fatalf("inherited owner: %q", h.OwnerHint)
	}
	for _, o := range objs {
		m := mapped(t, o)
		if !reflect.DeepEqual(m.Template.KeyUsage, []string{"digitalSignature", "keyEncipherment"}) ||
			!reflect.DeepEqual(m.Template.ExtendedKeyUsage, []string{"clientAuth", "serverAuth"}) || m.Template.EnrolleeType != "machine" {
			t.Fatalf("%s: synthesized defaults %+v", o.Name, m.Template)
		}
	}
}

func TestNameDerivation(t *testing.T) {
	objs := parse(t)
	ws := objs[web]
	if ws.Name != "Certificates-Web-Servers" {
		t.Fatalf("name %q", ws.Name)
	}
	if m := mapped(t, ws); m.Template.DisplayName != "Web Servers" {
		t.Fatalf("display %q", m.Template.DisplayName)
	}
	if got := folderName(`\VED\Policy\A  B\C d`); got != "A-B-C-d" {
		t.Fatalf("got %q", got)
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

func TestCollisionsReportedAsConflicts(t *testing.T) {
	svc := migration.NewService(sink{}, store{}, New())
	d, err := svc.DryRun(context.Background(), migration.Input{Source: Source, Content: fixtureBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	if d.Counts[migration.ActionCreate] != 3 || d.Counts[migration.ActionConflict] != 1 {
		t.Fatalf("counts %+v", d.Counts)
	}
	for _, e := range d.Entries {
		switch e.SourceKey {
		case "venafi:" + web:
			if e.Action != migration.ActionCreate {
				t.Fatalf("first by (Name, SourceKey) must be create: %+v", e)
			}
		case `venafi:\VED\Policy\Certificates\Web-Servers`:
			if e.Action != migration.ActionConflict || !strings.Contains(e.Reason, "duplicate name") {
				t.Fatalf("collision: %+v", e)
			}
		}
	}
}

func TestMapDeterministic(t *testing.T) {
	for _, o := range parse(t) {
		a, b := mapped(t, o), mapped(t, o)
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if string(ja) != string(jb) {
			t.Fatalf("%s: nondeterministic", o.Name)
		}
	}
}

func TestUnsupportedAlgorithmAndUnknownAttribute(t *testing.T) {
	o := migration.SourceObject{Name: "x", Raw: map[string]any{"path": `\VED\Policy\x`,
		"own":       map[string][]string{"Key Algorithm": {"DSA"}, "Weird": {"1"}},
		"effective": map[string][]string{"Key Algorithm": {"DSA"}, "Weird": {"1"}}}}
	m := mapped(t, o)
	if !strings.Contains(m.Unsupported, "key algorithm") {
		t.Fatalf("got %q", m.Unsupported)
	}
	var weird bool
	for _, f := range m.Fields {
		if f.Field == "Weird" && f.Status == migration.FieldUnmapped && f.Note == "no equivalent" {
			weird = true
		}
	}
	if !weird {
		t.Fatalf("unknown attribute not reported: %+v", m.Fields)
	}
}
