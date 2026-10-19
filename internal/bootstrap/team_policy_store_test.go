// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	kkdb "kryptkeeper/internal/db"
)

func newTestTeamPolicyStore(t *testing.T) (*dbTeamPolicyStore, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	s := newDBTeamPolicyStore(db, false)
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, db
}

func TestTeamPolicyRoundTripBothLists(t *testing.T) {
	s, _ := newTestTeamPolicyStore(t)
	ctx := context.Background()
	in := TeamPolicy{Tenant: "acme", Team: "payments", AllowedCAs: []string{"ca-b", " ca-a", "ca-b"},
		AllowedDNSSuffixes: []string{".pay.example"}, MaxValidityDays: 90, MonthlyQuota: 10}
	saved, err := s.Put(ctx, in, 0, "alice")
	if err != nil || saved.Version != 1 {
		t.Fatalf("create: %+v %v", saved, err)
	}
	got, found, err := s.Get(ctx, "acme", "payments")
	if err != nil || !found {
		t.Fatalf("get: %v %v", found, err)
	}
	if strings.Join(got.AllowedCAs, ",") != "ca-a,ca-b" || got.AllowedTemplates == nil || got.AllowedDNSNames == nil || got.UpdatedBy != "alice" {
		t.Fatalf("round trip = %+v", got)
	}
	if _, err := s.Put(ctx, in, 0, "bob"); !errors.Is(err, errTeamPolicyExists) {
		t.Fatalf("duplicate create err = %v", err)
	}
	got.MonthlyQuota = 5
	if _, err := s.Put(ctx, got, 7, "bob"); !errors.Is(err, errTeamPolicyStale) {
		t.Fatalf("wrong base version err = %v", err)
	}
	upd, err := s.Put(ctx, got, 1, "bob")
	if err != nil || upd.Version != 2 || upd.CreatedAt != got.CreatedAt {
		t.Fatalf("update: %+v %v", upd, err)
	}
	if other, _ := s.List(ctx, "beta", false); len(other) != 0 {
		t.Fatalf("beta sees %+v", other)
	}
	if all, _ := s.List(ctx, "beta", true); len(all) != 1 {
		t.Fatalf("all = %+v", all)
	}
	if ok, err := s.Delete(ctx, "acme", "payments"); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if _, err := s.Put(ctx, upd, 2, "bob"); !errors.Is(err, errTeamPolicyStale) {
		t.Fatalf("update of deleted row err = %v", err)
	}
}

func TestValidateTeamPolicyTable(t *testing.T) {
	ok := TeamPolicy{Team: "payments", MaxValidityDays: 90, MonthlyQuota: 1}
	many := make([]string, 101)
	for i := range many {
		many[i] = "ca-" + strings.Repeat("x", i%50) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	for _, tc := range []struct {
		name string
		mod  func(*TeamPolicy)
		bad  bool
	}{
		{"valid", func(*TeamPolicy) {}, false},
		{"empty team", func(p *TeamPolicy) { p.Team = "  " }, true},
		{"slash in team", func(p *TeamPolicy) { p.Team = "a/b" }, true},
		{"control char in team", func(p *TeamPolicy) { p.Team = "a\nb" }, true},
		{"long team", func(p *TeamPolicy) { p.Team = strings.Repeat("t", 121) }, true},
		{"101 entries", func(p *TeamPolicy) { p.AllowedCAs = many }, true},
		{"empty entry", func(p *TeamPolicy) { p.AllowedTemplates = []string{" "} }, true},
		{"long entry", func(p *TeamPolicy) { p.AllowedCAs = []string{strings.Repeat("a", 254)} }, true},
		{"wildcard suffix", func(p *TeamPolicy) { p.AllowedDNSSuffixes = []string{"*.x"} }, true},
		{"good suffix", func(p *TeamPolicy) { p.AllowedDNSSuffixes = []string{".x.example"} }, false},
		{"validity 0 = no cap", func(p *TeamPolicy) { p.MaxValidityDays = 0 }, false},
		{"validity -1", func(p *TeamPolicy) { p.MaxValidityDays = -1 }, true},
		{"validity 3651", func(p *TeamPolicy) { p.MaxValidityDays = 3651 }, true},
		{"validity 3650", func(p *TeamPolicy) { p.MaxValidityDays = 3650 }, false},
		{"quota -1", func(p *TeamPolicy) { p.MonthlyQuota = -1 }, true},
		{"quota over", func(p *TeamPolicy) { p.MonthlyQuota = 1000001 }, true},
		{"quota zero", func(p *TeamPolicy) { p.MonthlyQuota = 0 }, false},
	} {
		p := ok
		tc.mod(&p)
		p.normalizeLists()
		if msg := validateTeamPolicy(p); (msg != "") != tc.bad {
			t.Errorf("%s: msg=%q, want bad=%v", tc.name, msg, tc.bad)
		}
	}
}

func TestTeamPolicyLooseningTable(t *testing.T) {
	base := TeamPolicy{AllowedCAs: []string{"ca-1", "ca-2"}, AllowedTemplates: []string{"t-1"}, AllowedDNSSuffixes: []string{".a"},
		AllowedDNSNames: []string{"x.a"}, MaxValidityDays: 90, MonthlyQuota: 10}
	with := func(f func(*TeamPolicy)) TeamPolicy {
		p := base
		p.AllowedCAs = append([]string(nil), base.AllowedCAs...)
		f(&p)
		return p
	}
	for _, tc := range []struct {
		name  string
		old   TeamPolicy
		next  TeamPolicy
		loose bool
	}{
		{"CA added to non-empty", base, with(func(p *TeamPolicy) { p.AllowedCAs = append(p.AllowedCAs, "ca-3") }), true},
		{"CA swapped (one added)", base, with(func(p *TeamPolicy) { p.AllowedCAs = []string{"ca-1", "ca-9"} }), true},
		{"template added", base, with(func(p *TeamPolicy) { p.AllowedTemplates = []string{"t-1", "t-2"} }), true},
		{"suffix added", base, with(func(p *TeamPolicy) { p.AllowedDNSSuffixes = []string{".a", ".b"} }), true},
		{"name added", base, with(func(p *TeamPolicy) { p.AllowedDNSNames = []string{"x.a", "y.a"} }), true},
		{"CA list emptied", base, with(func(p *TeamPolicy) { p.AllowedCAs = nil }), true},
		{"template list emptied", base, with(func(p *TeamPolicy) { p.AllowedTemplates = nil }), true},
		{"suffix list emptied", base, with(func(p *TeamPolicy) { p.AllowedDNSSuffixes = nil }), true},
		{"name list emptied", base, with(func(p *TeamPolicy) { p.AllowedDNSNames = nil }), true},
		{"validity raised", base, with(func(p *TeamPolicy) { p.MaxValidityDays = 91 }), true},
		{"validity non-zero to 0", base, with(func(p *TeamPolicy) { p.MaxValidityDays = 0 }), true},
		{"quota raised", base, with(func(p *TeamPolicy) { p.MonthlyQuota = 11 }), true},
		{"quota non-zero to 0", base, with(func(p *TeamPolicy) { p.MonthlyQuota = 0 }), true},
		{"CA narrowed, one left", base, with(func(p *TeamPolicy) { p.AllowedCAs = []string{"ca-1"} }), false},
		{"empty list filled (restricts)", with(func(p *TeamPolicy) { p.AllowedCAs = nil }), base, false},
		{"validity lowered", base, with(func(p *TeamPolicy) { p.MaxValidityDays = 30 }), false},
		{"validity 0 to non-zero", with(func(p *TeamPolicy) { p.MaxValidityDays = 0 }), base, false},
		{"quota lowered", base, with(func(p *TeamPolicy) { p.MonthlyQuota = 3 }), false},
		{"quota 0 to non-zero", with(func(p *TeamPolicy) { p.MonthlyQuota = 0 }), base, false},
		{"empty stays empty", with(func(p *TeamPolicy) { p.AllowedCAs = nil }), with(func(p *TeamPolicy) { p.AllowedCAs = nil }), false},
		{"no-op", base, base, false},
	} {
		if got := teamPolicyLoosening(tc.old, tc.next); (len(got) > 0) != tc.loose {
			t.Errorf("%s: reasons=%v, want loosening=%v", tc.name, got, tc.loose)
		}
	}
}
