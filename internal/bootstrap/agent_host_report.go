// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"time"

	"kryptkeeper/internal/agentdiscovery"
)

// W34-09: what an agent's host pass says about its own machine, computed by the
// hub from the raw facts in the inventory push so agent hosts get the same
// posture as SSH targets. A pre-W34 agent sends none of it and gets
// PostureKnown=false: its files are unknown, never assumed standard.

const (
	maxAgentHostFiles     = 2000
	maxAgentHostListeners = 512
	maxAgentReportFiles   = 200
	maxAgentReportPaths   = 10
)

// AgentUnreadablePath is a path the agent could not open.
type AgentUnreadablePath struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// AgentHostFile is one file the agent reported, with the hub-computed posture.
type AgentHostFile struct {
	Path        string   `json:"path"`
	Kind        string   `json:"kind"`
	Owner       string   `json:"owner,omitempty"`
	Group       string   `json:"group,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Posture     string   `json:"posture"`
	ServiceTech string   `json:"service_tech,omitempty"`
	Findings    []string `json:"findings,omitempty"`
}

// AgentHostReport is the latest host pass of one agent.
type AgentHostReport struct {
	ReceivedAt string `json:"received_at"`
	// PostureKnown is false for an agent that predates W34-09.
	PostureKnown    bool                  `json:"posture_known"`
	PrivilegeMode   string                `json:"privilege_mode,omitempty"`
	ScanUser        string                `json:"scan_user,omitempty"`
	UnreadableCount int                   `json:"unreadable_count"`
	UnreadablePaths []AgentUnreadablePath `json:"unreadable_paths,omitempty"`
	// Findings holds INSUFFICIENT_PRIVILEGE (with the fix for the mode) and the
	// per-file posture findings, "CODE: detail" strings as on SSH targets.
	Findings        []string        `json:"findings,omitempty"`
	Files           []AgentHostFile `json:"files,omitempty"`
	PostureCounts   map[string]int  `json:"posture_counts,omitempty"`
	ListenerCount   int             `json:"listener_count"`
	ListenersHidden int             `json:"listeners_hidden"`
}

// agentHostPush is the host-pass part of POST /api/v1/agent/inventory.
type agentHostPush struct {
	HostScanned     bool                  `json:"host_scanned"`
	PrivilegeMode   string                `json:"privilege_mode"`
	ScanUser        string                `json:"scan_user"`
	UnreadablePaths []AgentUnreadablePath `json:"unreadable_paths"`
	UnreadableTotal int                   `json:"unreadable_total"`
	Files           []agentPushFile       `json:"files"`
	Listeners       []agentPushListener   `json:"listeners"`
	ConfigRefs      map[string]string     `json:"config_refs"`
}

type agentPushFile struct {
	Path             string   `json:"path"`
	Kind             string   `json:"kind"`
	Owner            string   `json:"owner"`
	Group            string   `json:"group"`
	Mode             string   `json:"mode"`
	UID              *int     `json:"uid"`
	GID              *int     `json:"gid"`
	CertFingerprints []string `json:"cert_fingerprints"`
}

type agentPushListener struct {
	Port       int      `json:"port"`
	PID        int      `json:"pid"`
	UID        *int     `json:"uid"`
	GID        *int     `json:"gid"`
	User       string   `json:"user"`
	Exe        string   `json:"exe"`
	Comm       string   `json:"comm"`
	Cwd        string   `json:"cwd"`
	Tech       string   `json:"tech"`
	ConfigRefs []string `json:"config_refs"`
	AppDirs    []string `json:"app_dirs"`
}

func idOrUnknown(p *int) int {
	if p == nil {
		return agentdiscovery.UnknownID
	}
	return *p
}

var validAgentFileKinds = map[string]bool{"pem": true, "jks": true, "p12": true, "key": true, "config": true}

// buildAgentHostReport classifies an agent's host pass. A push with no host
// marker (and no host data at all) is a pre-W34 agent.
func buildAgentHostReport(p agentHostPush, now time.Time) AgentHostReport {
	rep := AgentHostReport{ReceivedAt: now.UTC().Format(time.RFC3339)}
	if !p.HostScanned && p.Files == nil && p.Listeners == nil && p.UnreadablePaths == nil {
		return rep
	}
	rep.PostureKnown = true
	rep.PrivilegeMode, rep.ScanUser = p.PrivilegeMode, p.ScanUser
	if rep.PrivilegeMode == "" {
		rep.PrivilegeMode = "none"
	}

	var paths []string
	seen := map[string]bool{}
	for _, u := range p.UnreadablePaths {
		if u.Path == "" || seen[u.Path] {
			continue
		}
		seen[u.Path] = true
		paths = append(paths, u.Path)
		if len(rep.UnreadablePaths) < maxAgentReportPaths {
			rep.UnreadablePaths = append(rep.UnreadablePaths, AgentUnreadablePath{Path: u.Path, Error: u.Error})
		}
	}
	// The agent caps the list it sends; its total is the truth when larger.
	rep.UnreadableCount = max(len(paths), p.UnreadableTotal)
	if rep.UnreadableCount > 0 {
		rep.Findings = append(rep.Findings, formatInsufficientPrivilege("", rep.ScanUser, rep.PrivilegeMode, paths, rep.UnreadableCount))
	}

	listeners := make([]agentdiscovery.Listener, 0, len(p.Listeners))
	for _, l := range p.Listeners {
		if len(listeners) >= maxAgentHostListeners {
			break
		}
		al := agentdiscovery.Listener{Port: l.Port, PID: l.PID, UID: idOrUnknown(l.UID), GID: idOrUnknown(l.GID), User: l.User,
			Exe: l.Exe, Comm: l.Comm, Cwd: l.Cwd, Tech: l.Tech, ConfigRefs: l.ConfigRefs, AppDirs: l.AppDirs}
		if !al.UIDKnown() {
			rep.ListenersHidden++
		}
		listeners = append(listeners, al)
	}
	rep.ListenerCount = len(listeners)

	facts := make([]agentdiscovery.FileFact, 0, len(p.Files))
	for _, f := range p.Files {
		if len(facts) >= maxAgentHostFiles {
			break
		}
		kind := f.Kind
		if !validAgentFileKinds[kind] {
			kind = agentdiscovery.FileKindPEM
		}
		facts = append(facts, agentdiscovery.FileFact{Path: f.Path, Kind: kind, UID: idOrUnknown(f.UID), GID: idOrUnknown(f.GID),
			Mode: f.Mode, Owner: f.Owner, Group: f.Group, Statted: f.Mode != "", ServiceUID: agentdiscovery.UnknownID})
	}
	agentdiscovery.ClassifyHostFiles(facts, listeners, p.ConfigRefs)
	rep.PostureCounts = map[string]int{}
	for _, f := range facts {
		rep.PostureCounts[f.Posture]++
		rep.Findings = append(rep.Findings, f.Findings...)
		if len(rep.Files) < maxAgentReportFiles && (f.Posture != agentdiscovery.PostureStandard || len(f.Findings) > 0) {
			rep.Files = append(rep.Files, AgentHostFile{Path: f.Path, Kind: f.Kind, Owner: f.Owner, Group: f.Group, Mode: f.Mode,
				Posture: f.Posture, ServiceTech: f.ServiceTech, Findings: f.Findings})
		}
	}
	return rep
}
