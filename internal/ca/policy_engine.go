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
	"strconv"
	"strings"
	"sync/atomic"
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
	// PolicyID and Observed (e.g. "2048 bits") let the admin API cite the
	// exact row and value without parsing Detail. Error() is unchanged.
	PolicyID string
	Observed string
}

// Is makes errors.Is(err, ErrPolicyViolation) true for a policy refusal, so
// handlers return the same 422 policy_violation as for template refusals.
func (e *PolicyViolationError) Is(target error) bool { return target == ErrPolicyViolation }

// PolicyInput is the policy-relevant projection of an issuance request. The
// real path derives it from the CSR's actual key; dry-run may supply it
// hypothetically.
type PolicyInput struct {
	Algorithm string
	RSABits   int
	Validity  time.Duration
	IsCA      bool
}

// PolicyVerdict is the full evaluation result: every applicable policy name
// and EVERY violated rule (Check refuses on the first, dry-run shows all).
type PolicyVerdict struct {
	Allowed    bool
	Evaluated  []string
	Violations []*PolicyViolationError
}

func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("issuance policy %q: rule %s: %s", e.Policy, e.Rule, e.Detail)
}

// PolicyEngine evaluates issuance requests against the table.
type PolicyEngine struct {
	db       *sql.DB
	postgres bool
	now      func() time.Time
	// hook observes every refusal from Check (audit trail). Atomic so it can
	// be installed after the engine is already serving.
	hook atomic.Pointer[func(caID string, v *PolicyViolationError)]
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
		return rsaAlgorithmName(bits), bits
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

// rsaAlgorithmName buckets a modulus size into the allow-list names, the one
// classification the issuance gate applies to a CSR's RSA key.
func rsaAlgorithmName(bits int) string {
	switch {
	case bits <= 2048:
		return string(keystore.RSA2048)
	case bits <= 3072:
		return string(keystore.RSA3072)
	default:
		return string(keystore.RSA4096)
	}
}

// rsaKeyLadder is the modulus sizes a client can be told to generate.
var rsaKeyLadder = []int{2048, 3072, 4096, 8192, 16384}

// RSAProbe answers "which RSA modulus will issuance accept" over the policies
// that applied to one CA when it was loaded, so a request that probes many
// templates costs one policy read instead of one per probe.
type RSAProbe struct{ policies []IssuancePolicy }

// RSAProbe loads the enabled policies that apply to caID once.
func (p *PolicyEngine) RSAProbe(caID string) (*RSAProbe, error) {
	policies, err := p.loadPoliciesFor(caID)
	if err != nil {
		return nil, err
	}
	return &RSAProbe{policies: policies}, nil
}

// AcceptedRSABits is RSAProbe(caID).AcceptedRSABits for a single probe.
func (p *PolicyEngine) AcceptedRSABits(caID string, atLeast int, templateAlgos []string) (bits int, ok bool, reason string, err error) {
	probe, err := p.RSAProbe(caID)
	if err != nil {
		return 0, false, "", err
	}
	return probe.AcceptedRSABits(atLeast, templateAlgos)
}

// AcceptedRSABits returns the smallest RSA modulus, at least atLeast and
// among templateAlgos when that is non-empty, that the policies accept. It
// runs the engine's own rules (evaluatePolicies) rather than re-reading
// them, so what a protocol advertises is exactly what issuance will later
// enforce. ok is false, with the refusal as reason, when no size is accepted.
// The error is always nil; the signature matches PolicyEngine.AcceptedRSABits.
func (r *RSAProbe) AcceptedRSABits(atLeast int, templateAlgos []string) (bits int, ok bool, reason string, err error) {
	cands := []int{max(atLeast, 2048)}
	for _, n := range rsaKeyLadder {
		if n > cands[0] {
			cands = append(cands, n)
		}
	}
	reason = "the template permits no RSA key size"
	for _, n := range cands {
		alg := rsaAlgorithmName(n)
		if !algorithmAllowed(templateAlgos, alg) {
			continue
		}
		v := evaluatePolicies(r.policies, PolicyInput{Algorithm: alg, RSABits: n})
		if v.Allowed {
			return n, true, "", nil
		}
		reason = v.Violations[0].Error()
	}
	return 0, false, reason, nil
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

// GetPolicy returns one policy row by id; ok=false when it does not exist.
func (p *PolicyEngine) GetPolicy(id string) (IssuancePolicy, bool, error) {
	rows, err := p.db.Query(p.rebind(`SELECT id, name, enabled, ca_id, rules FROM issuance_policies WHERE id = ?`), id)
	if err != nil {
		return IssuancePolicy{}, false, fmt.Errorf("issuance policy: get: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return IssuancePolicy{}, false, rows.Err()
	}
	pol, err := scanPolicy(rows)
	if err != nil {
		return IssuancePolicy{}, false, err
	}
	return pol, true, nil
}

// RSAFloor returns the smallest RSA modulus every enabled policy accepts and
// the name of the policy that sets it (0, "" when none restricts RSA). A
// policy's floor is the larger of min_rsa_bits and the smallest RSA-N in its
// allow-list; an allow-list naming no RSA size refuses RSA outright and adds
// no floor. Policies scoped to one CA count too: a template is not bound to
// a CA, so it must satisfy the strictest of them.
func (p *PolicyEngine) RSAFloor() (int, string, error) {
	policies, err := p.ListPolicies()
	if err != nil {
		return 0, "", err
	}
	bits, name := 0, ""
	for _, pol := range policies {
		if !pol.Enabled {
			continue
		}
		f := pol.Rules.MinRSABits
		smallest := 0
		for _, a := range pol.Rules.AllowedAlgorithms {
			if n, ok := rsaAlgorithmBits(a); ok && (smallest == 0 || n < smallest) {
				smallest = n
			}
		}
		f = max(f, smallest)
		if f > bits {
			bits, name = f, pol.Name
		}
	}
	return bits, name, nil
}

// IsRSAAlgorithm reports whether an algorithm name ("RSA", "RSA-3072",
// "rsa2048", "RSASSA-PSS") names an RSA key, for callers that must not apply
// RSA key-size rules to anything else.
func IsRSAAlgorithm(alg string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(alg)), "RSA")
}

// rsaAlgorithmBits parses "RSA-3072".
func rsaAlgorithmBits(alg string) (int, bool) {
	rest, ok := strings.CutPrefix(alg, "RSA-")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	return n, err == nil && n > 0
}

// SetViolationHook installs fn to be called once per refused Check.
func (p *PolicyEngine) SetViolationHook(fn func(caID string, v *PolicyViolationError)) {
	if fn == nil {
		p.hook.Store(nil)
		return
	}
	p.hook.Store(&fn)
}

// DB exposes the handle and dialect for sibling stores (policy history).
func (p *PolicyEngine) DB() (*sql.DB, bool) { return p.db, p.postgres }

// Evaluate checks in against every enabled policy applying to caID and
// returns all violations. Rows are read per call (no cache) so a tightened
// rule takes effect on the next request. A load error is returned so callers
// can fail closed.
func (p *PolicyEngine) Evaluate(caID string, in PolicyInput) (PolicyVerdict, error) {
	policies, err := p.loadPoliciesFor(caID)
	if err != nil {
		return PolicyVerdict{}, err
	}
	return evaluatePolicies(policies, in), nil
}

// evaluatePolicies is the rule set itself, over already-loaded policies, so a
// caller that evaluates many inputs reads the table once (RSAProbe).
func evaluatePolicies(policies []IssuancePolicy, in PolicyInput) PolicyVerdict {
	v := PolicyVerdict{Allowed: true}
	for _, pol := range policies {
		v.Evaluated = append(v.Evaluated, pol.Name)
		viol := func(rule, detail, observed string) {
			v.Violations = append(v.Violations, &PolicyViolationError{Policy: pol.Name, PolicyID: pol.ID, Rule: rule, Detail: detail, Observed: observed})
		}
		if len(pol.Rules.AllowedAlgorithms) > 0 {
			allowed := false
			for _, a := range pol.Rules.AllowedAlgorithms {
				if a == in.Algorithm {
					allowed = true
					break
				}
			}
			if !allowed {
				viol("allowed_algorithms", fmt.Sprintf("requested algorithm %q is not in the allow-list %v", in.Algorithm, pol.Rules.AllowedAlgorithms), in.Algorithm)
			}
		}
		if pol.Rules.MinRSABits > 0 && in.RSABits > 0 && in.RSABits < pol.Rules.MinRSABits {
			viol("min_rsa_bits", fmt.Sprintf("requested RSA modulus is %d bits, floor is %d", in.RSABits, pol.Rules.MinRSABits), fmt.Sprintf("%d bits", in.RSABits))
		}
		if pol.Rules.MaxValidityDays > 0 {
			maxValidity := time.Duration(pol.Rules.MaxValidityDays) * 24 * time.Hour
			if in.Validity > maxValidity {
				viol("max_validity_days", fmt.Sprintf("requested %s exceeds %dd", in.Validity, pol.Rules.MaxValidityDays), in.Validity.String())
			}
		}
		if in.IsCA && !pol.Rules.AllowCACerts {
			viol("allow_ca_certs", "CA certificate issuance through the leaf path is not allowed by this policy", "is_ca=true")
		}
	}
	v.Allowed = len(v.Violations) == 0
	return v
}

// Check evaluates req against every enabled policy applying to caID.
// Every violated rule refuses, so with multiple policies the most
// restrictive wins by construction. No policies = no restriction.
func (p *PolicyEngine) Check(caID string, req IssuanceRequest) error {
	algo, rsaBits := requestedAlgorithm(req)
	v, err := p.Evaluate(caID, PolicyInput{Algorithm: algo, RSABits: rsaBits, Validity: req.Validity, IsCA: req.IsCA})
	if err != nil {
		// Fail closed: an unreadable policy table must not mean
		// unrestricted issuance.
		return fmt.Errorf("issuance policy evaluation unavailable (refusing issuance): %w", err)
	}
	if v.Allowed {
		return nil
	}
	first := v.Violations[0]
	if fn := p.hook.Load(); fn != nil {
		(*fn)(caID, first)
	}
	return first
}

// RequestedAlgorithm exposes the key-derived algorithm/bits logic so the
// dry-run endpoint classifies a CSR exactly as the real issue path does.
func RequestedAlgorithm(req IssuanceRequest) (string, int) { return requestedAlgorithm(req) }
