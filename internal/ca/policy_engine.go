// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"kryptkeeper/internal/keystore"
)

// W5-05 (D-046/FR-P8): the issuance-time policy engine. Rules live in the
// issuance_policies table — data, not compile-time — and every issuance
// variant consults them before signing. Refusals cite the policy and the
// rule, because a refused requester's next question is always "which rule".

// PolicyRules is one policy's JSON rules document. Absent/zero fields are
// unrestricted, EXCEPT AllowCACerts: issuing a CA certificate through the
// leaf path is refused by default and must be opted into.
type PolicyRules struct {
	AllowedAlgorithms []string `json:"allowed_algorithms,omitempty"`
	MinRSABits        int      `json:"min_rsa_bits,omitempty"`
	MaxValidityDays   int      `json:"max_validity_days,omitempty"`
	AllowCACerts      bool     `json:"allow_ca_certs,omitempty"`
}

// IssuancePolicy is one row.
type IssuancePolicy struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Enabled bool        `json:"enabled"`
	CAID    string      `json:"ca_id"` // "" = every CA
	Rules   PolicyRules `json:"rules"`
}

// PolicyViolationError is the typed refusal; Error() cites policy + rule.
type PolicyViolationError struct {
	Policy string
	Rule   string
	Detail string
}

func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("issuance policy %q: rule %s: %s", e.Policy, e.Rule, e.Detail)
}

// PolicyEngine evaluates issuance requests against the table.
type PolicyEngine struct {
	db       *sql.DB
	postgres bool
	now      func() time.Time
}

func NewPolicyEngine(db *sql.DB, postgres bool) (*PolicyEngine, error) {
	if db == nil {
		return nil, fmt.Errorf("policy engine requires a database")
	}
	return &PolicyEngine{db: db, postgres: postgres, now: time.Now}, nil
}

func (p *PolicyEngine) rebind(q string) string {
	if !p.postgres {
		return q
	}
	out := make([]byte, 0, len(q)+8)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, fmt.Sprintf("$%d", n)...)
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

// UpsertPolicy writes a policy row (programmatic/admin surface; the HTTP
// API is future work — the acceptance needs data-driven enforcement).
func (p *PolicyEngine) UpsertPolicy(pol IssuancePolicy) (IssuancePolicy, error) {
	if pol.Name == "" {
		return IssuancePolicy{}, fmt.Errorf("issuance policy: name is required")
	}
	if pol.ID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return IssuancePolicy{}, fmt.Errorf("issuance policy: id: %w", err)
		}
		pol.ID = "pol-" + hex.EncodeToString(b)
	}
	rules, err := json.Marshal(pol.Rules)
	if err != nil {
		return IssuancePolicy{}, fmt.Errorf("issuance policy: rules marshal: %w", err)
	}
	enabled := 0
	if pol.Enabled {
		enabled = 1
	}
	now := p.now().UTC().Format(time.RFC3339)
	_, err = p.db.Exec(p.rebind(`
		INSERT INTO issuance_policies (id, name, enabled, ca_id, rules, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = excluded.name,
			enabled = excluded.enabled,
			ca_id = excluded.ca_id,
			rules = excluded.rules,
			updated_at = excluded.updated_at`),
		pol.ID, pol.Name, enabled, pol.CAID, string(rules), now, now)
	if err != nil {
		return IssuancePolicy{}, fmt.Errorf("issuance policy: persist: %w", err)
	}
	return pol, nil
}

// DeletePolicy removes a policy row.
func (p *PolicyEngine) DeletePolicy(id string) error {
	_, err := p.db.Exec(p.rebind(`DELETE FROM issuance_policies WHERE id = ?`), id)
	return err
}

// ListPolicies returns every policy row.
func (p *PolicyEngine) ListPolicies() ([]IssuancePolicy, error) {
	rows, err := p.db.Query(`SELECT id, name, enabled, ca_id, rules FROM issuance_policies ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("issuance policy: list: %w", err)
	}
	defer rows.Close()
	var out []IssuancePolicy
	for rows.Next() {
		pol, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pol)
	}
	return out, rows.Err()
}

func scanPolicy(rows *sql.Rows) (IssuancePolicy, error) {
	var pol IssuancePolicy
	var enabled int
	var rulesJSON string
	if err := rows.Scan(&pol.ID, &pol.Name, &enabled, &pol.CAID, &rulesJSON); err != nil {
		return IssuancePolicy{}, err
	}
	pol.Enabled = enabled == 1
	if err := json.Unmarshal([]byte(rulesJSON), &pol.Rules); err != nil {
		return IssuancePolicy{}, fmt.Errorf("issuance policy %s: rules parse: %w", pol.ID, err)
	}
	return pol, nil
}

// requestedAlgorithm derives the requested algorithm name and RSA modulus
// size from the request's ACTUAL key material — never from client-declared
// strings. Unknown key types return "" and are refused by any policy with
// an algorithm allow-list.
func requestedAlgorithm(req IssuanceRequest) (name string, rsaBits int) {
	if req.PQCCSR != nil {
		return string(req.PQCCSR.Algorithm), 0
	}
	if req.HybridCSR != nil {
		return string(req.HybridCSR.Algorithm), 0
	}
	if req.CSR == nil {
		return "", 0
	}
	switch pub := req.CSR.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		switch {
		case bits <= 2048:
			return string(keystore.RSA2048), bits
		default:
			return string(keystore.RSA4096), bits
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return string(keystore.ECDSAP256), 0
		case elliptic.P384():
			return string(keystore.ECDSAP384), 0
		}
		return "ECDSA-" + pub.Curve.Params().Name, 0
	case ed25519.PublicKey:
		return string(keystore.Ed25519), 0
	}
	return "", 0
}

// loadPoliciesFor returns the enabled policies that apply to caID.
func (p *PolicyEngine) loadPoliciesFor(caID string) ([]IssuancePolicy, error) {
	rows, err := p.db.Query(p.rebind(`
		SELECT id, name, enabled, ca_id, rules FROM issuance_policies
		WHERE enabled = 1 AND (ca_id = '' OR ca_id = ?)
		ORDER BY name, id`), caID)
	if err != nil {
		return nil, fmt.Errorf("issuance policy: load: %w", err)
	}
	defer rows.Close()
	var out []IssuancePolicy
	for rows.Next() {
		pol, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pol)
	}
	return out, rows.Err()
}

// Check evaluates req against every enabled policy applying to caID.
// Every violated rule refuses, so with multiple policies the most
// restrictive wins by construction. No policies = no restriction.
func (p *PolicyEngine) Check(caID string, req IssuanceRequest) error {
	policies, err := p.loadPoliciesFor(caID)
	if err != nil {
		// Fail closed: an unreadable policy table must not mean
		// unrestricted issuance.
		return fmt.Errorf("issuance policy evaluation unavailable (refusing issuance): %w", err)
	}
	if len(policies) == 0 {
		return nil
	}

	algo, rsaBits := requestedAlgorithm(req)
	for _, pol := range policies {
		if len(pol.Rules.AllowedAlgorithms) > 0 {
			allowed := false
			for _, a := range pol.Rules.AllowedAlgorithms {
				if a == algo {
					allowed = true
					break
				}
			}
			if !allowed {
				return &PolicyViolationError{Policy: pol.Name, Rule: "allowed_algorithms",
					Detail: fmt.Sprintf("requested algorithm %q is not in the allow-list %v", algo, pol.Rules.AllowedAlgorithms)}
			}
		}
		if pol.Rules.MinRSABits > 0 && rsaBits > 0 && rsaBits < pol.Rules.MinRSABits {
			return &PolicyViolationError{Policy: pol.Name, Rule: "min_rsa_bits",
				Detail: fmt.Sprintf("requested RSA modulus is %d bits, floor is %d", rsaBits, pol.Rules.MinRSABits)}
		}
		if pol.Rules.MaxValidityDays > 0 {
			maxValidity := time.Duration(pol.Rules.MaxValidityDays) * 24 * time.Hour
			if req.Validity > maxValidity {
				return &PolicyViolationError{Policy: pol.Name, Rule: "max_validity_days",
					Detail: fmt.Sprintf("requested %s exceeds %dd", req.Validity, pol.Rules.MaxValidityDays)}
			}
		}
		if req.IsCA && !pol.Rules.AllowCACerts {
			return &PolicyViolationError{Policy: pol.Name, Rule: "allow_ca_certs",
				Detail: "CA certificate issuance through the leaf path is not allowed by this policy"}
		}
	}
	return nil
}
