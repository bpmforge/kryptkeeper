// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"errors"
	"testing"
)

type listOnlySvc struct {
	Service
	cas []*CA
	err error
}

func (l listOnlySvc) ListCAs() ([]*CA, error) { return l.cas, l.err }

func TestResolveCAID(t *testing.T) {
	t.Run("configured wins without listing", func(t *testing.T) {
		id, err := ResolveCAID(listOnlySvc{err: errors.New("unused")}, "ca-x")
		if err != nil || id != "ca-x" {
			t.Fatalf("got %q, %v", id, err)
		}
	})
	t.Run("first stored CA", func(t *testing.T) {
		id, err := ResolveCAID(listOnlySvc{cas: []*CA{{ID: "a"}, {ID: "b"}}}, "")
		if err != nil || id != "a" {
			t.Fatalf("got %q, %v", id, err)
		}
	})
	t.Run("none is ErrNoCAConfigured", func(t *testing.T) {
		_, err := ResolveCAID(listOnlySvc{}, "")
		if !errors.Is(err, ErrNoCAConfigured) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("list failure is not first-run", func(t *testing.T) {
		_, err := ResolveCAID(listOnlySvc{err: errors.New("db locked")}, "")
		if err == nil || errors.Is(err, ErrNoCAConfigured) {
			t.Fatalf("a read failure must not look like zero CAs, got %v", err)
		}
	})
}
