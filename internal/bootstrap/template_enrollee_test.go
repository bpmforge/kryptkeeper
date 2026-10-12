// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// W20-17: a template's enrollee type is stored explicitly, defaults to
// machine, round-trips through create and replace, and rejects anything but
// machine or user.
func TestTemplateEnrolleeType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "templates.json")
	if err := os.WriteFile(path, []byte(`{"items":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &fileTemplateProvider{filePath: path}
	ctx := context.Background()
	base := func(name, enrollee string) TemplateUpsertRequest {
		return TemplateUpsertRequest{Name: name, DisplayName: name, ValidityPeriod: "8760h",
			KeyUsage: []string{"digitalSignature"}, ExtendedKeyUsage: []string{"clientAuth"},
			AllowedAlgorithms: []string{"ECDSA"}, Active: true, EnrolleeType: enrollee}
	}

	def, err := p.CreateTemplate(ctx, base("Default", ""))
	if err != nil {
		t.Fatal(err)
	}
	if def.EnrolleeType != "machine" || def.Enrollee() != "machine" {
		t.Errorf("default enrollee_type %q, want machine stored explicitly", def.EnrolleeType)
	}
	user, err := p.CreateTemplate(ctx, base("Users", "user"))
	if err != nil {
		t.Fatal(err)
	}
	if user.Enrollee() != "user" {
		t.Errorf("user template stored as %q", user.EnrolleeType)
	}
	if _, err := p.CreateTemplate(ctx, base("Bad", "computer")); !errors.Is(err, errTemplateInvalidCreate) {
		t.Errorf("enrollee_type computer: err %v, want errTemplateInvalidCreate", err)
	}
	replaced, err := p.ReplaceTemplate(ctx, def.ID, base("Default", "user"), def.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Enrollee() != "user" {
		t.Errorf("replace did not change enrollee_type: %q", replaced.EnrolleeType)
	}
	got, ok, err := p.GetTemplate(ctx, user.ID)
	if err != nil || !ok || got.EnrolleeType != "user" {
		t.Errorf("reload: %+v ok=%v err=%v", got.EnrolleeType, ok, err)
	}
}

// A template file written before W20-17 has no enrollee_type: those were
// all machine templates, and must stay machine templates.
func TestTemplateEnrolleeLegacyIsMachine(t *testing.T) {
	var item TemplateItem
	if err := json.Unmarshal([]byte(`{"id":"tpl-old","name":"KKMachine","oid":"1.2.3"}`), &item); err != nil {
		t.Fatal(err)
	}
	if item.Enrollee() != "machine" {
		t.Fatalf("legacy template enrollee %q, want machine", item.Enrollee())
	}
}
