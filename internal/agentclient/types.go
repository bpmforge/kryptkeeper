// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package agentclient provides a client for the Kryptkeeper Hub agent API.
// Satellite agents use this to register, report inventory, and fetch renewal tasks.
package agentclient

import (
	"fmt"
	"strings"
	"time"
)

// AgentType is the platform/OS of a satellite agent.
type AgentType string

const (
	AgentTypeLinux   AgentType = "linux"
	AgentTypeMac     AgentType = "mac"
	AgentTypeWindows AgentType = "windows"
)

// RegisterRequest is sent by an agent on first registration.
type RegisterRequest struct {
	Name string    `json:"name"`
	Type AgentType `json:"type"`
	// EnrollmentSecret is the W5-07 enrollment evidence the hub requires
	// unless registration is left open; omitted when empty.
	EnrollmentSecret string `json:"enrollment_secret,omitempty"`
}

// RegisterResponse is returned by the Hub after successful registration.
type RegisterResponse struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
}

// DiscoveredCert represents a certificate found by the agent on the local host.
type DiscoveredCert struct {
	Fingerprint   string    `json:"fingerprint"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Source        string    `json:"source"`
	AutoRenewable bool      `json:"auto_renewable"`
	// DNSNames is the cert's SAN DNS list (W19-13). Omitted by pre-W19-13
	// agents; the hub falls back to parsing Subject's CN for those.
	DNSNames []string `json:"dns_names,omitempty"`
}

// ServerType identifies the web server software serving a TLS endpoint.
type ServerType string

const (
	ServerNginx   ServerType = "nginx"
	ServerApache  ServerType = "apache"
	ServerHAProxy ServerType = "haproxy"
)

// Endpoint describes an installable TLS endpoint discovered on the host: where
// the cert and key live, what software serves them, and where to verify after
// install. This is the install contract the Hub needs to close the renewal loop
// (discover → issue → install → verify).
type Endpoint struct {
	ServerType ServerType `json:"server_type"`
	CertPath   string     `json:"cert_path"`
	KeyPath    string     `json:"key_path,omitempty"`
	ServerName string     `json:"server_name,omitempty"`
	ListenPort int        `json:"listen_port,omitempty"`
	ConfigPath string     `json:"config_path,omitempty"`
}

// VerifyHostPort returns the host:port the agent should TLS-dial to confirm the
// renewed cert is being served. Falls back to localhost and port 443.
func (e Endpoint) VerifyHostPort() string {
	host := e.ServerName
	if host == "" || host == "_" || strings.HasPrefix(host, "*") {
		host = "localhost"
	}
	port := e.ListenPort
	if port == 0 {
		port = 443
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// RenewalTask is a task pushed from the Hub telling the agent to renew a cert.
// The install-hint fields (v1.3 autopilot) tell the agent where to write the
// renewed cert/key, how to reload, and where to verify — all empty when the
// task has no installable endpoint (renew-only).
//
// No CAURL field (removed W19-26): this client never read it -- the ACME
// renewer builds its directory URL from its own HubURL instead (see
// acme_renewer.go: r.HubURL + "/acme/directory"), so the Hub has nothing to
// tell it here. Document this at the deployment layer too: an agent's ACME
// directory is always derived from KRYPTKEEPER_HUB_URL.
type RenewalTask struct {
	TaskID      string    `json:"task_id"`
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	Action      string    `json:"action"`
	NotAfter    time.Time `json:"not_after"`

	// Install hints (v1.3). Populated when the Hub matches the cert to a
	// reported endpoint; empty for renew-only tasks.
	ServerType     ServerType `json:"server_type,omitempty"`
	CertPath       string     `json:"cert_path,omitempty"`
	KeyPath        string     `json:"key_path,omitempty"`
	ReloadMethod   string     `json:"reload_method,omitempty"`
	VerifyHostPort string     `json:"verify_host_port,omitempty"`

	// Identifiers is the DNS SAN/CN list the hub computed for this task's
	// ACME order (W19-13). Empty when a pre-W19-13 hub issued the task; the
	// renewer then falls back to parsing Subject's CN, never to using
	// Subject itself as an identifier.
	Identifiers []string `json:"identifiers,omitempty"`
}

// RenewalResult is the install/verify outcome an agent reports back to the Hub
// after acting on a RenewalTask (v1.3 W2 — closes the renewal loop).
type RenewalResult struct {
	TaskID            string `json:"task_id"`
	Fingerprint       string `json:"fingerprint"`
	Outcome           string `json:"outcome"`
	ServedFingerprint string `json:"served_fingerprint,omitempty"`
	RolledBack        bool   `json:"rolled_back"`
	Detail            string `json:"detail,omitempty"`
}
