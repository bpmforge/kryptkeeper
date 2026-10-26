// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"testing"
)

type capableFake struct {
	IssuerConnector
	id  string
	can bool
}

func (c capableFake) ID() string                                  { return c.id }
func (c capableFake) Revoke(context.Context, RevokeRequest) error { return nil }
func (c capableFake) CanRevoke() bool                             { return c.can }

type revokeOnlyFake struct {
	IssuerConnector
	id string
}

func (c revokeOnlyFake) ID() string                                  { return c.id }
func (c revokeOnlyFake) Revoke(context.Context, RevokeRequest) error { return nil }

func TestRegistrySupportsRevokeConsultsRevokeCapable(t *testing.T) {
	reg := NewRegistry()
	reg.Register(capableFake{id: "yes", can: true})
	reg.Register(capableFake{id: "no", can: false})
	reg.Register(revokeOnlyFake{id: "plain"})
	for id, want := range map[string]bool{"yes": true, "no": false, "plain": true, "missing": false} {
		if got := reg.SupportsRevoke(id); got != want {
			t.Errorf("SupportsRevoke(%s) = %v, want %v", id, got, want)
		}
	}
}
