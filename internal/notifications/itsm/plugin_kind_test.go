// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"errors"
	"testing"
)

type probeConn struct {
	*fakeConnector
	probed int
	err    error
}

func (p *probeConn) Probe(context.Context) error { p.probed++; return p.err }

// A plugin connection is built by the plugin factory, not by a native kind's
// factory, and a connector with a Probe is tested through it: Find would
// report a plugin without a find op as healthy without calling the service.
func TestPluginConnectionUsesPluginFactoryAndProbe(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Store().CreateConnection(ctx, Connection{ID: "p1", Kind: KindPlugin, Name: "Z", CredentialRef: "r", PluginID: "kryptkeeper.zendesk", Enabled: true}, h.clock.now()); err != nil {
		t.Fatal(err)
	}
	got, err := h.svc.Store().GetConnection(ctx, "p1")
	if err != nil || got.PluginID != "kryptkeeper.zendesk" || got.Kind != KindPlugin {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	pc := &probeConn{fakeConnector: h.conn}
	var built Connection
	src := NewConnectorSource(h.svc.Store(), nil, nil, nil, func(_ context.Context, c Connection) (Connector, error) {
		built = c
		return pc, nil
	})
	svc := NewService(Config{Store: h.svc.Store(), Conns: src, Now: h.clock.now})
	if err := svc.TestConnection(ctx, "p1"); err != nil || pc.probed != 1 || built.PluginID != "kryptkeeper.zendesk" {
		t.Fatalf("probe: err=%v probed=%d built=%+v", err, pc.probed, built)
	}
	pc.err = ErrPermanent
	if err := svc.TestConnection(ctx, "p1"); !errors.Is(err, ErrPermanent) {
		t.Fatalf("probe error must surface: %v", err)
	}
	off := NewConnectorSource(h.svc.Store(), nil, nil, nil, nil)
	if _, err := off(ctx, "p1"); err == nil {
		t.Fatal("a plugin connection with no plugin runtime must fail closed")
	}
}
