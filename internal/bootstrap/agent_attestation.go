// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/subtle"
	"fmt"
	"log"
	"os"
	"strings"
)

// W5-07 (PE-7/D-061/FR-P23): agent enrollment is closed by default.
// Anonymous self-registration was a standing security gap — anyone who
// could reach the hub could mint an agent identity. Existing agents are
// unaffected: they hold per-agent tokens; only NEW registration is gated.
//
// Migration path (documented, per the acceptance):
//  1. Set KRYPTKEEPER_AGENT_OPEN_REGISTRATION=true to keep enrolments
//     working during the transition (loud warning at startup).
//  2. Configure KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS and roll the secret
//     out to provisioning tooling.
//  3. Remove the open-registration flag.
//
// Secret rotation: SECRETS is a CSV — append the new secret, re-provision
// agents, then drop the old entry.

// AgentEnrollmentEvidence is what a registering agent presents. Secret is
// the shipping evidence kind; TPM quotes, mTLS peer certificates, and
// SPIFFE SVIDs plug in here as additional fields without changing the
// handler contract.
type AgentEnrollmentEvidence struct {
	Secret string
}

// AgentEnrollmentGate decides whether a registration may proceed.
type AgentEnrollmentGate struct {
	openRegistration bool
	secrets          [][]byte
}

// NewAgentEnrollmentGateFromEnv resolves the gate:
// secrets configured → secret required; open-registration flag → legacy
// open mode (loud warning); NEITHER → closed, every registration refused
// with an instructive message.
func NewAgentEnrollmentGateFromEnv() *AgentEnrollmentGate {
	gate := &AgentEnrollmentGate{}
	for _, s := range strings.Split(os.Getenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			gate.secrets = append(gate.secrets, []byte(s))
		}
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION")), "true") {
		gate.openRegistration = true
		if len(gate.secrets) == 0 {
			log.Print("WARNING: agent registration is OPEN (KRYPTKEEPER_AGENT_OPEN_REGISTRATION=true) — anyone reaching this hub can enrol an agent; configure KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS and remove the flag (W5-07 migration path)")
		}
	}
	return gate
}

// Check refuses anonymous registration. Configured secrets win over the
// open flag — once secrets exist, they are required.
func (g *AgentEnrollmentGate) Check(ev AgentEnrollmentEvidence) error {
	if g == nil {
		return fmt.Errorf("agent enrollment gate not configured")
	}
	if len(g.secrets) > 0 {
		presented := []byte(ev.Secret)
		for _, secret := range g.secrets {
			if subtle.ConstantTimeCompare(presented, secret) == 1 {
				return nil
			}
		}
		return fmt.Errorf("agent enrollment refused: invalid or missing enrollment secret")
	}
	if g.openRegistration {
		return nil
	}
	return fmt.Errorf("agent enrollment is closed: configure KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS (or, during migration only, KRYPTKEEPER_AGENT_OPEN_REGISTRATION=true)")
}
