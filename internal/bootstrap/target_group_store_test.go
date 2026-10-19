// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	_ "modernc.org/sqlite"
)

func newFreshTargetGroupStore(t *testing.T) *sqlTargetGroupStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "groups.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqlTargetGroupStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTargetGroupStoreUpsertMoveDelete(t *testing.T) {
	ctx := context.Background()
	s := newFreshTargetGroupStore(t)

	if _, err := s.Upsert(ctx, TargetGroup{Name: "a", RenewalThresholdDays: 30, TargetIDs: []string{"t2", "t1", "t1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upsert(ctx, TargetGroup{Name: "b", RenewalThresholdDays: 60}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %+v, %v", got, err)
	}
	if !reflect.DeepEqual(got[0].TargetIDs, []string{"t1", "t2"}) || got[1].TargetIDs == nil || len(got[1].TargetIDs) != 0 {
		t.Fatalf("members = %+v / %+v", got[0].TargetIDs, got[1].TargetIDs)
	}

	// t1 moves to b; replacing a's membership drops t2.
	if _, err := s.Upsert(ctx, TargetGroup{Name: "b", RenewalThresholdDays: 45, TargetIDs: []string{"t1"}}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.List(ctx)
	if !reflect.DeepEqual(got[0].TargetIDs, []string{"t2"}) || !reflect.DeepEqual(got[1].TargetIDs, []string{"t1"}) || got[1].RenewalThresholdDays != 45 {
		t.Fatalf("after move: %+v", got)
	}
	if days := groupDaysByTarget(got); days["t1"] != 45 || days["t2"] != 30 {
		t.Fatalf("groupDaysByTarget = %v", days)
	}

	if _, err := s.Upsert(ctx, TargetGroup{Name: "a", RenewalThresholdDays: 399}); !errors.Is(err, errGroupInvalidThreshold) {
		t.Fatalf("399 err = %v", err)
	}
	if err := s.Delete(ctx, DefaultTenant, "b"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, DefaultTenant, "b"); !errors.Is(err, errTargetGroupNotFound) {
		t.Fatalf("second delete err = %v", err)
	}
	got, _ = s.List(ctx)
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("after delete: %+v", got)
	}
	var orphans int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM target_group_members WHERE group_name = 'b'`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("members of a deleted group survive: %d, %v", orphans, err)
	}
}

func TestTargetGroupStoreNamesArePerTenant(t *testing.T) {
	ctx := context.Background()
	s := newFreshTargetGroupStore(t)
	for _, tn := range []string{"acme", "globex"} {
		if _, err := s.Upsert(ctx, TargetGroup{Name: "prod", Tenant: tn, RenewalThresholdDays: 30}); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.List(ctx); len(got) != 2 {
		t.Fatalf("same name in two tenants collided: %+v", got)
	}
	if err := s.Delete(ctx, "acme", "prod"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(ctx); len(got) != 1 || got[0].Tenant != "globex" {
		t.Fatalf("delete crossed tenants: %+v", got)
	}
}

func TestValidateGroupName(t *testing.T) {
	for _, ok := range []string{"prod", "web-tier.1", "A_b"} {
		if validateGroupName(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-lead", "has space", "a/b", string(make([]byte, 65))} {
		if validateGroupName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
