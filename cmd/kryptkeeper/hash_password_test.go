// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestHashPasswordFrom(t *testing.T) {
	hash, err := hashPasswordFrom(strings.NewReader("s3cret-pass\n"), " pepper ")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected PHC string %q", hash)
	}
	if strings.Contains(hash, "s3cret-pass") {
		t.Fatal("hash must not contain the password")
	}
	if _, err := hashPasswordFrom(strings.NewReader("\n"), ""); err == nil {
		t.Fatal("empty password must be refused")
	}
}
