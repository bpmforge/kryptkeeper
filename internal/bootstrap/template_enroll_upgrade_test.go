// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUpgradeWindowsEnrollLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "templates.json")
	perms := func(r ...string) *EnrollmentPermissions { return &EnrollmentPermissions{Enroll: r} }
	items := []TemplateItem{
		{ID: "a", Name: "KKMachine", OID: "1.2.3.1", AutoEnroll: true, EnrollmentPermissions: perms("pki-operator")},
		{ID: "b", Name: "Open", OID: "1.2.3.2", AutoEnroll: true},
		{ID: "c", Name: "AdminOnly", OID: "1.2.3.3", AutoEnroll: true, EnrollmentPermissions: perms("pki-admin")},
		{ID: "d", Name: "Manual", OID: "1.2.3.4", EnrollmentPermissions: perms("pki-operator")},
		{ID: "e", Name: "HasWstep", OID: "1.2.3.5", AutoEnroll: true, EnrollmentPermissions: perms("pki-admin", "protocol:wstep:dc01.corp")},
		{ID: "f", Name: "Restricted", OID: "1.2.3.6", EnrollmentPermissions: perms("pki-admin", "protocol:wstep:restricted")},
	}
	body, _ := json.Marshal(items)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	p := &fileTemplateProvider{filePath: path}

	res := UpgradeWindowsEnrollLists(p)
	if !res.Ran || !reflect.DeepEqual(res.Widened, []string{"KKMachine"}) || !reflect.DeepEqual(res.Refused, []string{"AdminOnly", "Manual"}) {
		t.Fatalf("result = %+v", res)
	}
	got, _ := p.loadItems()
	want := map[string][]string{
		"a": {"pki-operator", "protocol:wstep"}, "b": nil, "c": {"pki-admin"}, "d": {"pki-operator"},
		"e": {"pki-admin", "protocol:wstep:dc01.corp"}, "f": {"pki-admin", "protocol:wstep:restricted"},
	}
	for _, it := range got {
		if !reflect.DeepEqual(it.EnrollRoles(), want[it.ID]) {
			t.Errorf("%s roles = %v, want %v", it.ID, it.EnrollRoles(), want[it.ID])
		}
		if it.Revision != 0 {
			t.Errorf("%s revision bumped to %d", it.ID, it.Revision)
		}
	}

	// Idempotent, and an admin narrowing a list afterwards is never re-widened.
	got[0].EnrollmentPermissions = perms("pki-operator")
	if err := p.saveItems(got); err != nil {
		t.Fatal(err)
	}
	if res := UpgradeWindowsEnrollLists(p); res.Ran {
		t.Fatalf("second run did work: %+v", res)
	}
	again, _ := p.loadItems()
	if !reflect.DeepEqual(again[0].EnrollRoles(), []string{"pki-operator"}) {
		t.Fatalf("re-widened: %v", again[0].EnrollRoles())
	}
}

func TestUpgradeWindowsEnrollListsFreshInstallMarksDone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "templates.json")
	p := &fileTemplateProvider{filePath: path}
	if res := UpgradeWindowsEnrollLists(p); !res.Ran {
		t.Fatal("fresh install should record the marker")
	}
	if _, err := os.Stat(path + enrollUpgradeMarker); err != nil {
		t.Fatalf("marker missing: %v", err)
	}
}

// A store that exists but cannot be parsed is retried on the next start: no
// marker, so the upgrade still runs once the file is readable.
func TestUpgradeWindowsEnrollListsUnreadableStoreNotMarked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "templates.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &fileTemplateProvider{filePath: path}
	if res := UpgradeWindowsEnrollLists(p); res.Ran {
		t.Fatalf("ran on an unreadable store: %+v", res)
	}
	if _, err := os.Stat(path + enrollUpgradeMarker); !os.IsNotExist(err) {
		t.Fatalf("marker written for an unreadable store: %v", err)
	}
}
