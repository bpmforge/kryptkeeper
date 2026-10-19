// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"regexp"
	"runtime"
	"strings"

	"kryptkeeper/internal/agentclient"
	"kryptkeeper/internal/agentinstall"
)

// W34-09: the agent's discovery walk, run through the same host scan the hub
// uses for SSH targets so a root-owned keystore is read when the privilege mode
// allows it, and so posture inputs (file ownership, listeners) come back with
// the certificates.

const (
	maxReportedUnreadable = 50
	maxReportedFiles      = 2000
	maxReportedListeners  = 512
)

var reDeniedPath = regexp.MustCompile(`/[^\s:'"]+`)

// DiscoverLocalHost scans paths on this host. priv is the executor the walk
// runs on (privexec-wrapped per KRYPTKEEPER_PRIVILEGE_MODE), plain the
// unwrapped one. On platforms without the exec-based scan it falls back to
// WalkCerts and reports no host pass (the hub then treats posture as unknown).
func DiscoverLocalHost(ctx context.Context, paths []string, priv, plain agentinstall.Executor, user, mode string) ([]agentclient.DiscoveredCert, *agentclient.HostInventory, error) {
	if runtime.GOOS != "linux" || priv == nil {
		certs, err := WalkCerts(paths)
		return certs, nil, err
	}
	res := NewAgentlessSSHScanner(priv, "localhost", paths).WithUnprivileged(plain).ForAgent().Scan(ctx)
	certs := make([]agentclient.DiscoveredCert, 0, len(res.Certs))
	for _, c := range res.Certs {
		c.Source = strings.TrimPrefix(c.Source, "agentless-ssh:")
		certs = append(certs, c)
	}
	return certs, HostInventoryFrom(res, user, mode), nil
}

// HostInventoryFrom flattens a host scan into the inventory-push shape.
func HostInventoryFrom(res AgentlessScanResult, user, mode string) *agentclient.HostInventory {
	if mode == "" {
		mode = "none"
	}
	h := &agentclient.HostInventory{Scanned: true, PrivilegeMode: mode, User: user,
		UnreadablePaths: []agentclient.UnreadablePath{}, Files: []agentclient.HostFile{}, Listeners: []agentclient.HostListener{},
		ConfigRefs: res.ConfigRefs}
	seen := map[string]bool{}
	for _, e := range res.Errors {
		if !strings.Contains(strings.ToLower(e), "permission denied") {
			continue
		}
		p := reDeniedPath.FindString(strings.TrimPrefix(e, res.Host+":"))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		h.UnreadableTotal++
		if len(h.UnreadablePaths) < maxReportedUnreadable {
			h.UnreadablePaths = append(h.UnreadablePaths, agentclient.UnreadablePath{Path: p, Error: "permission denied"})
		}
	}
	for _, f := range res.Files {
		if len(h.Files) >= maxReportedFiles {
			break
		}
		h.Files = append(h.Files, agentclient.HostFile{Path: f.Path, Kind: f.Kind, Owner: f.Owner, Group: f.Group, Mode: f.Mode,
			UID: f.UID, GID: f.GID, CertFingerprints: f.CertFingerprints})
	}
	for _, l := range res.Listeners {
		if len(h.Listeners) >= maxReportedListeners {
			break
		}
		h.Listeners = append(h.Listeners, agentclient.HostListener{Port: l.Port, PID: l.PID, UID: l.UID, GID: l.GID, User: l.User,
			Exe: l.Exe, Comm: l.Comm, Cwd: l.Cwd, Tech: l.Tech, ConfigRefs: l.ConfigRefs, AppDirs: l.AppDirs})
	}
	return h
}
