// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os/user"

	"kryptkeeper/internal/agentclient"
	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/privexec"
)

// hostDiscovery runs the agent's certificate walk through privexec (W34-09),
// so a root-owned keystore is read when the sudoers drop-in or the helper
// allows it, with no change to the install allowlist (D-114).
type hostDiscovery struct {
	mode privexec.Mode
	user string
	// priv is the privexec-wrapped executor, plain the unwrapped one.
	priv, plain privexec.Executor
}

// newHostDiscovery builds the discovery executor for KRYPTKEEPER_PRIVILEGE_MODE
// (none, nopasswd or helper; empty is none).
func newHostDiscovery(rawMode string) (hostDiscovery, error) {
	mode, err := privexec.ParseMode(rawMode)
	if err != nil {
		return hostDiscovery{}, fmt.Errorf("KRYPTKEEPER_PRIVILEGE_MODE: %w", err)
	}
	if mode == privexec.ModePassword {
		return hostDiscovery{}, fmt.Errorf("KRYPTKEEPER_PRIVILEGE_MODE=password is not offered to the agent: it would need a stored sudo password; use nopasswd or helper")
	}
	local := privexec.LocalExecutor{}
	priv, err := privexec.Wrap(local, privexec.Config{Mode: mode, HelperSHA: privexec.HelperSHA256()})
	if err != nil {
		return hostDiscovery{}, err
	}
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return hostDiscovery{mode: mode, user: name, priv: priv, plain: local}, nil
}

func (d hostDiscovery) discover(ctx context.Context, paths []string) ([]agentclient.DiscoveredCert, *agentclient.HostInventory, error) {
	if d.priv == nil {
		certs, err := agentdiscovery.WalkCerts(paths)
		return certs, nil, err
	}
	return agentdiscovery.DiscoverLocalHost(ctx, paths, d.priv, d.plain, d.user, string(d.mode))
}
