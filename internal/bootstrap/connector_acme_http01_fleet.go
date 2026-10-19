// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/agentinstall"
)

// W27-23: fleet http-01. The hub is often unreachable at the certificate's
// name; the host that serves the name is. In http01_mode "fleet" the key
// authorization is written under that host's webroot over its managed
// target's SSH connection and removed again once the CA has validated.
//
// The solver talks to an agentinstall.Executor, so an agent-backed executor
// can replace SSH later without touching this file (no generic remote-command
// channel exists in internal/agentclient today).

const defaultFleetWebroot = "/var/www/html"

// acmeHTTP01Host maps a name to the managed target that serves it on port 80.
type acmeHTTP01Host struct {
	Domain   string `json:"domain"`
	TargetID string `json:"target_id"`
	Webroot  string `json:"webroot,omitempty"`
}

// The token is CA-supplied and becomes a path component on a customer host.
var fleetTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

const fleetChallengePrefix = "/.well-known/acme-challenge/"

type fleetPlacement struct {
	targetID string
	file     string
}

type fleetHTTP01Solver struct {
	c      *acmeIssuerConnector
	hosts  map[string]acmeHTTP01Host // keyed by lower-cased domain
	conns  map[string]*fleetConn     // keyed by target id
	placed map[string]fleetPlacement // keyed by identifier
}

type fleetConn struct {
	exec    agentinstall.Executor
	closeFn func() error
}

var _ http01Responder = (*fleetHTTP01Solver)(nil)

func validateFleetHost(h acmeHTTP01Host) (acmeHTTP01Host, error) {
	h.Domain = strings.ToLower(strings.TrimSpace(h.Domain))
	if h.Domain == "" || strings.TrimSpace(h.TargetID) == "" {
		return h, errors.New("acme connector http01_hosts entries need domain and target_id")
	}
	if strings.Contains(h.Domain, "*") {
		return h, fmt.Errorf("http-01 cannot validate wildcard %q; use dns-01", h.Domain)
	}
	if h.Webroot == "" {
		h.Webroot = defaultFleetWebroot
	}
	if !strings.HasPrefix(h.Webroot, "/") || strings.Contains(h.Webroot, "..") ||
		strings.ContainsAny(h.Webroot, "\x00\"' \t\r\n\\") {
		return h, fmt.Errorf("http01_hosts webroot for %s must be an absolute path without '..', quotes or spaces", h.Domain)
	}
	h.Webroot = strings.TrimRight(h.Webroot, "/")
	return h, nil
}

func newFleetHTTP01Solver(c *acmeIssuerConnector) (*fleetHTTP01Solver, error) {
	if len(c.cfg.HTTP01Hosts) == 0 {
		return nil, errors.New("acme connector http01_mode fleet needs http01_hosts")
	}
	s := &fleetHTTP01Solver{
		c: c, hosts: map[string]acmeHTTP01Host{},
		conns: map[string]*fleetConn{}, placed: map[string]fleetPlacement{},
	}
	for _, raw := range c.cfg.HTTP01Hosts {
		h, err := validateFleetHost(raw)
		if err != nil {
			return nil, err
		}
		s.hosts[h.Domain] = h
	}
	return s, nil
}

func (s *fleetHTTP01Solver) exec(ctx context.Context, h acmeHTTP01Host) (agentinstall.Executor, error) {
	if conn, ok := s.conns[h.TargetID]; ok {
		return conn.exec, nil
	}
	targets := s.c.targets
	if targets == nil {
		targets = newManagedTargetStoreFromEnv()
	}
	if targets == nil {
		return nil, errors.New("managed target store not configured")
	}
	target, err := targets.Get(ctx, h.TargetID)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", h.TargetID, err)
	}
	exec, closeFn, err := s.c.dialFleetHost(ctx, target)
	if err != nil {
		return nil, err
	}
	s.conns[h.TargetID] = &fleetConn{exec: exec, closeFn: closeFn}
	return exec, nil
}

func (s *fleetHTTP01Solver) put(ctx context.Context, identifier, path, keyAuth string) error {
	h, ok := s.hosts[strings.ToLower(identifier)]
	if !ok {
		return fmt.Errorf("no http01_hosts entry for %s", identifier)
	}
	token := strings.TrimPrefix(path, fleetChallengePrefix)
	if token == path || !fleetTokenRe.MatchString(token) {
		return fmt.Errorf("refusing http-01 path for %s: unexpected challenge token", identifier)
	}
	exec, err := s.exec(ctx, h)
	if err != nil {
		return err
	}
	file := h.Webroot + path
	dir := h.Webroot + strings.TrimSuffix(fleetChallengePrefix, "/")
	if _, err := exec.Run(ctx, "mkdir", "-p", "--", dir); err != nil {
		return fmt.Errorf("create %s on target %s: %w", dir, h.TargetID, err)
	}
	// Recorded before the write so a partial write is still cleaned up.
	s.placed[identifier] = fleetPlacement{targetID: h.TargetID, file: file}
	// World-readable on purpose: the key authorization is public web content.
	if err := exec.WriteFile(file, []byte(keyAuth), 0o644); err != nil {
		return fmt.Errorf("write challenge to target %s: %w", h.TargetID, err)
	}
	return nil
}

func (s *fleetHTTP01Solver) release(ctx context.Context, identifier string) error {
	p, ok := s.placed[identifier]
	if !ok {
		return nil
	}
	conn, ok := s.conns[p.targetID]
	if !ok {
		delete(s.placed, identifier)
		return nil
	}
	if _, err := conn.exec.Run(ctx, "rm", "-f", "--", p.file); err != nil {
		return fmt.Errorf("remove %s from target %s: %w", p.file, p.targetID, err)
	}
	delete(s.placed, identifier)
	return nil
}

func (s *fleetHTTP01Solver) close() {
	if len(s.placed) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		for identifier := range s.placed {
			if err := s.release(ctx, identifier); err != nil {
				logging.Infof("acme connector %s: http-01 cleanup for %s: %v", s.c.id, identifier, err)
			}
		}
		cancel()
	}
	for id, conn := range s.conns {
		if conn.closeFn != nil {
			if err := conn.closeFn(); err != nil {
				logging.Infof("acme connector %s: closing ssh to target %s: %v", s.c.id, id, err)
			}
		}
		delete(s.conns, id)
	}
}

// dialFleetHost opens the SSH connection for one target with the same
// credential and host-key pinning as ExecuteRenewal. FOLLOW-UP: dedupe with
// the rollout dial (W27-15).
func (c *acmeIssuerConnector) dialFleetHost(ctx context.Context, target ManagedTarget) (agentinstall.Executor, func() error, error) {
	if target.InstallMode != "ssh" && target.InstallMode != "keychain" {
		return nil, nil, fmt.Errorf("fleet http-01 needs an ssh-mode target for %s", target.ID)
	}
	if c.tenant != "" && target.Tenant != "" && c.tenant != target.Tenant {
		return nil, nil, fmt.Errorf("target %s belongs to another tenant", target.ID)
	}
	if strings.TrimSpace(target.CredentialRef) == "" {
		return nil, nil, errRenewalNoCredential
	}
	if c.creds == nil {
		return nil, nil, errors.New("outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
	}
	re := NewRenewalExecutor(c.inventory, c.creds)
	payload, err := re.resolveSSHCredential(ctx, target.CredentialRef)
	if err != nil {
		return nil, nil, err
	}
	signer, hostKey, err := payload.parse()
	if err != nil {
		return nil, nil, err
	}
	port := payload.Port
	if port == 0 {
		port = 22
	}
	pinned := pinnedHostKeyFor(target, hostKey)
	dial := re.dial
	if c.fleetDial != nil {
		dial = c.fleetDial
	}
	return dial(ctx, agentinstall.SSHTarget{
		Host:              target.Host,
		Port:              port,
		User:              payload.User,
		Signer:            signer,
		HostKeyCallback:   agentinstall.PinnedHostKeyCallback(pinned),
		HostKeyAlgorithms: hostKeyAlgorithmsFor(pinned),
	})
}
