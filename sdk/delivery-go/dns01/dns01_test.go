// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package dns01

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

type fake struct{}

func (fake) Present(_ *delivery.Host, req abi.DNS01PresentRequest) (abi.DNS01PresentResult, error) {
	return abi.DNS01PresentResult{RecordID: "r1", Zone: "example.com"}, nil
}

func (fake) Cleanup(_ *delivery.Host, req abi.DNS01CleanupRequest) (abi.DNS01CleanupResult, error) {
	return abi.DNS01CleanupResult{Removed: req.RecordID == "r1"}, nil
}

func TestHandle(t *testing.T) {
	h := delivery.NewHost(nil)
	out, err := Handle(fake{}, h, abi.OpDNS01Present, []byte(`{"fqdn":"_acme-challenge.example.com","value":"abc_DEF-123"}`))
	if err != nil {
		t.Fatal(err)
	}
	var res abi.DNS01PresentResult
	if err := json.Unmarshal(out, &res); err != nil || res.RecordID != "r1" || res.Zone != "example.com" {
		t.Fatalf("result %s err %v", out, err)
	}
	out, err = Handle(fake{}, h, abi.OpDNS01Cleanup, []byte(`{"fqdn":"_acme-challenge.example.com","value":"abc","record_id":"r1"}`))
	if err != nil || !strings.Contains(string(out), `"removed":true`) {
		t.Fatalf("cleanup %s err %v", out, err)
	}
	if _, err := Handle(fake{}, h, abi.OpPush, []byte(`{}`)); err == nil {
		t.Fatal("a dns01 plugin must refuse a delivery op")
	}
}

func TestCheckNameRefusesPathAndQueryCharacters(t *testing.T) {
	for _, fqdn := range []string{"", "a.example.com.", "a/b.example.com", "a.example.com?x=1", "a b.example.com", "a#.example.com", "é.example.com"} {
		if CheckName(fqdn, "v") == nil {
			t.Errorf("fqdn %q accepted", fqdn)
		}
	}
	for _, v := range []string{"", `a"b`, "a b", `a\b`, strings.Repeat("a", 256)} {
		if CheckName("_acme-challenge.example.com", v) == nil {
			t.Errorf("value %q accepted", v)
		}
	}
	if err := CheckName("_acme-challenge.a-b.example.com", "x_Y-9"); err != nil {
		t.Fatal(err)
	}
}

func TestParentCandidatesAndRelativeName(t *testing.T) {
	got := ParentCandidates("_acme-challenge.www.example.co.uk")
	want := []string{"www.example.co.uk", "example.co.uk", "co.uk"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if RelativeName("_acme-challenge.example.com", "example.com") != "_acme-challenge" || RelativeName("example.com", "example.com") != "@" {
		t.Fatal("relative names wrong")
	}
}

type memSet struct {
	vals   []string
	writes int
}

func (m *memSet) Zone(string) (string, error)        { return "example.com", nil }
func (m *memSet) Read(_, _ string) ([]string, error) { return append([]string(nil), m.vals...), nil }
func (m *memSet) Encode(v string) string             { return `"` + v + `"` }
func (m *memSet) Decode(s string) string             { return strings.Trim(s, `"`) }
func (m *memSet) Write(_, _ string, _, next []string) error {
	m.writes++
	m.vals = append([]string(nil), next...)
	return nil
}

func TestRRSetKeepsOtherValues(t *testing.T) {
	m := &memSet{vals: []string{`"foreign"`}}
	if _, err := PresentRRSet(m, "_acme-challenge.example.com", "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := PresentRRSet(m, "_acme-challenge.example.com", "two"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.vals, ","); got != `"foreign","one","two"` {
		t.Fatalf("after present: %s", got)
	}
	writes := m.writes
	if _, err := PresentRRSet(m, "_acme-challenge.example.com", "one"); err != nil || m.writes != writes {
		t.Fatal("presenting a value that is already there must not write")
	}
	if _, err := CleanupRRSet(m, "_acme-challenge.example.com", "one", "example.com"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.vals, ","); got != `"foreign","two"` {
		t.Fatalf("cleanup of one value changed others: %s", got)
	}
	res, err := CleanupRRSet(m, "_acme-challenge.example.com", "one", "")
	if err != nil || !res.Removed {
		t.Fatalf("cleanup of a value that is gone: %+v %v", res, err)
	}
	for _, v := range []string{"two"} {
		if _, err := CleanupRRSet(m, "_acme-challenge.example.com", v, ""); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(m.vals, ","); got != `"foreign"` {
		t.Fatalf("final: %s", got)
	}
}
