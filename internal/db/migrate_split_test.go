// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

// A ';' inside a whole-line comment must not split the comment into a bogus
// statement (000057's header comment did exactly that under applyUpTolerant).
func TestSplitSQLStatementsIgnoresCommentLines(t *testing.T) {
	got := splitSQLStatements("-- note; with semicolon\nALTER TABLE a ADD COLUMN b TEXT;\n-- tail; x\nALTER TABLE a ADD COLUMN c TEXT;")
	want := []string{"ALTER TABLE a ADD COLUMN b TEXT;", "ALTER TABLE a ADD COLUMN c TEXT;"}
	if len(got) != len(want) {
		t.Fatalf("got %d statements %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("stmt %d = %q, want %q", i, got[i], want[i])
		}
	}
}
