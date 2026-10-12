// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"errors"
	"strings"
	"testing"
)

func TestCoreDBStartupDecision(t *testing.T) {
	migErr := errors.New("run sqlite migrations: apply migration 000020_tenant_scoping: SQL logic error: duplicate column name: tenant (1)")

	if err := CoreDBStartupDecision("ca", migErr); err == nil {
		t.Fatal("provider=ca with a migration failure must be fatal")
	} else if !strings.Contains(err.Error(), "000020_tenant_scoping") || !strings.Contains(err.Error(), "Fix:") {
		t.Errorf("message must name the migration and the fix, got %q", err)
	}
	if err := CoreDBStartupDecision(" CA ", errors.New("dial tcp: refused")); err == nil {
		t.Error("provider match is case/space-insensitive; plain open failure must be fatal too")
	}
	if err := CoreDBStartupDecision("ca", nil); err != nil {
		t.Errorf("no error must not be fatal: %v", err)
	}
	for _, p := range []string{"", "mock", "file"} {
		if err := CoreDBStartupDecision(p, migErr); err != nil {
			t.Errorf("provider %q never opens the core DB for the CA; got %v", p, err)
		}
	}
}
