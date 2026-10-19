// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// W29-11 (D-152): CI OIDC trust for code-signing issuance. A trust rule says
// "tokens from this issuer, for this audience, from repos/refs matching these
// patterns, may obtain a certificate from this CA". Rules are created only
// through the approval queue (proposer != approver, quorum), so widening who
// can obtain a signing certificate is always a two-person decision. Removing
// a rule is the safe direction and stays single-control.
//
// The verifier reuses the W6-02 RS256/JWKS path (validateOIDCRS256JWTManaged)
// rather than adding a JWT library: that path owns signature, exp, nbf, iss
// and aud. Everything read from the payload BEFORE it succeeds is untrusted
// and used only to pick candidate rules.

// ActionCodesignTrustRule is the approval-queue action type that creates a
// trust rule.
const ActionCodesignTrustRule = "codesign.oidc_trust_rule"

const (
	// codesignMaxSkew bounds every clock-skew allowance this verifier grants;
	// there is deliberately no env knob. The jti is retained until
	// exp+codesignMaxSkew so a replay inside the skew window is still caught.
	codesignMaxSkew = 2 * time.Minute
	// codesignMaxTokenAge caps exp-iat: CI tokens live minutes, a day-long
	// token is not a CI token.
	codesignMaxTokenAge = time.Hour
	codesignMaxToken    = 2048
	codesignIssuerMax   = 256
	codesignDetailMax   = 200
)

// Closed refusal reason codes (audit only; the HTTP caller sees a generic 401).
const (
	ReasonUntrustedIssuer = "untrusted_issuer"
	ReasonTokenInvalid    = "token_invalid"
	ReasonNoMatchingRule  = "no_matching_rule"
	ReasonReplay          = "replay"
	ReasonMissingJTI      = "missing_jti"
	ReasonMalformed       = "malformed"
)

// CodesignTrustRule is one approved issuer/audience/repo/ref -> CA binding.
type CodesignTrustRule struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	Issuer      string `json:"issuer"`
	Audience    string `json:"audience"`
	RepoPattern string `json:"repo_pattern"`
	RefPattern  string `json:"ref_pattern"`
	CAID        string `json:"ca_id"`
	Tenant      string `json:"tenant"`
	CreatedBy   string `json:"created_by"`
	ApprovedBy  string `json:"approved_by"`
	CreatedAt   string `json:"created_at"`
}

// codesignClaimSet names the claims that carry the repository and ref for a
// provider. Table-driven so GitHub and GitLab share one code path.
type codesignClaimSet struct{ Repo, Ref string }

var codesignClaimSets = map[string]codesignClaimSet{
	"github": {Repo: "repository", Ref: "ref"},
	"gitlab": {Repo: "project_path", Ref: "ref"},
}

// CodesignTrustStore persists trust rules and the jti replay ledger.
type CodesignTrustStore interface {
	EnsureSchema(ctx context.Context) error
	CreateRule(ctx context.Context, r CodesignTrustRule) (CodesignTrustRule, error)
	GetRule(ctx context.Context, id string) (CodesignTrustRule, bool, error)
	ListRules(ctx context.Context) ([]CodesignTrustRule, error)
	RulesForIssuer(ctx context.Context, issuer string) ([]CodesignTrustRule, error)
	DeleteRule(ctx context.Context, id string) error
	// ConsumeJTI records (issuer,jti); fresh=false means it was already seen
	// (replay). Atomic via INSERT ... ON CONFLICT DO NOTHING + RowsAffected,
	// valid on both engines. It also prunes rows whose expires_at has passed.
	ConsumeJTI(ctx context.Context, issuer, jti string, expiresAt time.Time) (fresh bool, err error)
}

// Mirrors migration 000241; idempotent for the per-store EnsureSchema convention.
const codesignOIDCSchema = `
CREATE TABLE IF NOT EXISTS codesign_oidc_trust_rules (
    id TEXT PRIMARY KEY, provider TEXT NOT NULL,
    issuer TEXT NOT NULL, audience TEXT NOT NULL,
    repo_pattern TEXT NOT NULL, ref_pattern TEXT NOT NULL,
    ca_id TEXT NOT NULL, tenant TEXT NOT NULL DEFAULT 'default',
    created_by TEXT NOT NULL, approved_by TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_codesign_trust_issuer ON codesign_oidc_trust_rules(issuer);
CREATE TABLE IF NOT EXISTS codesign_oidc_jti (
    issuer TEXT NOT NULL, jti TEXT NOT NULL, expires_at TEXT NOT NULL, PRIMARY KEY (issuer, jti));
CREATE INDEX IF NOT EXISTS idx_codesign_jti_exp ON codesign_oidc_jti(expires_at);`

type dbCodesignTrustStore struct {
	db *sql.DB
	ph func(n int) string
}

func (s *dbCodesignTrustStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, codesignOIDCSchema)
	return err
}

const codesignRuleSelect = `SELECT id, provider, issuer, audience, repo_pattern, ref_pattern,
	ca_id, tenant, created_by, approved_by, created_at FROM codesign_oidc_trust_rules`

func (s *dbCodesignTrustStore) CreateRule(ctx context.Context, r CodesignTrustRule) (CodesignTrustRule, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return CodesignTrustRule{}, err
	}
	r.ID = "ctr-" + hex.EncodeToString(b)
	r.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	if r.Tenant == "" {
		r.Tenant = DefaultTenant
	}
	q := fmt.Sprintf(`INSERT INTO codesign_oidc_trust_rules
		(id, provider, issuer, audience, repo_pattern, ref_pattern, ca_id, tenant, created_by, approved_by, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11))
	if _, err := s.db.ExecContext(ctx, q, r.ID, r.Provider, r.Issuer, r.Audience, r.RepoPattern,
		r.RefPattern, r.CAID, r.Tenant, r.CreatedBy, r.ApprovedBy, r.CreatedAt); err != nil {
		return CodesignTrustRule{}, err
	}
	return r, nil
}

func (s *dbCodesignTrustStore) query(ctx context.Context, where string, args ...any) ([]CodesignTrustRule, error) {
	rows, err := s.db.QueryContext(ctx, codesignRuleSelect+where+" ORDER BY created_at DESC, id ASC", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CodesignTrustRule
	for rows.Next() {
		var r CodesignTrustRule
		if err := rows.Scan(&r.ID, &r.Provider, &r.Issuer, &r.Audience, &r.RepoPattern, &r.RefPattern,
			&r.CAID, &r.Tenant, &r.CreatedBy, &r.ApprovedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *dbCodesignTrustStore) GetRule(ctx context.Context, id string) (CodesignTrustRule, bool, error) {
	rules, err := s.query(ctx, " WHERE id = "+s.ph(1), id)
	if err != nil || len(rules) == 0 {
		return CodesignTrustRule{}, false, err
	}
	return rules[0], true, nil
}

func (s *dbCodesignTrustStore) ListRules(ctx context.Context) ([]CodesignTrustRule, error) {
	return s.query(ctx, "")
}

func (s *dbCodesignTrustStore) RulesForIssuer(ctx context.Context, issuer string) ([]CodesignTrustRule, error) {
	return s.query(ctx, " WHERE issuer = "+s.ph(1), issuer)
}

func (s *dbCodesignTrustStore) DeleteRule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM codesign_oidc_trust_rules WHERE id = "+s.ph(1), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("trust rule %s not found", id)
	}
	return nil
}

func (s *dbCodesignTrustStore) ConsumeJTI(ctx context.Context, issuer, jti string, expiresAt time.Time) (bool, error) {
	// Prune first so an expired row never blocks a reused jti. Expiry text is
	// fixed-width UTC RFC3339, so lexical comparison is chronological.
	if _, err := s.db.ExecContext(ctx, "DELETE FROM codesign_oidc_jti WHERE expires_at < "+s.ph(1),
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		return false, err
	}
	q := fmt.Sprintf(`INSERT INTO codesign_oidc_jti (issuer, jti, expires_at) VALUES (%s, %s, %s)
		ON CONFLICT (issuer, jti) DO NOTHING`, s.ph(1), s.ph(2), s.ph(3))
	res, err := s.db.ExecContext(ctx, q, issuer, jti, expiresAt.UTC().Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// NewCodesignTrustStoreFromEnv opens the shared DB and ensures the schema.
// Returns nil if the DB is unavailable (callers tolerate nil).
func NewCodesignTrustStoreFromEnv() CodesignTrustStore {
	state := newDBProviderState[*dbCodesignTrustStore](
		"codesign-oidc-trust",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbCodesignTrustStore { return &dbCodesignTrustStore{db: db, ph: sqlitePlaceholder} },
		func(db *sql.DB) *dbCodesignTrustStore { return &dbCodesignTrustStore{db: db, ph: postgresPlaceholder} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("codesign-oidc-trust", state.openErr) // logs the outage itself
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("codesign-oidc-trust", err) // logs the outage itself
		return nil
	}
	return state.store
}

// validateTrustRule refuses rules broad enough to trust a whole forge. A bare
// "*" repo pattern would trust every repository on GitHub, so the repo
// pattern must name an owner segment, and refs must be fully-qualified.
func validateTrustRule(r CodesignTrustRule) error {
	if _, ok := codesignClaimSets[r.Provider]; !ok {
		return fmt.Errorf("provider %q is not supported (github, gitlab)", r.Provider)
	}
	// requireHTTPSURL alone would admit http://localhost; a signing-trust
	// issuer must be https with no exception.
	issuer := strings.TrimRight(r.Issuer, "/")
	if u, err := url.Parse(issuer); err != nil || u.Scheme != "https" {
		return errors.New("issuer must be an https URL")
	}
	if err := requireHTTPSURL(issuer); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if strings.TrimSpace(r.Audience) == "" {
		return errors.New("audience is required")
	}
	if strings.TrimSpace(r.CAID) == "" {
		return errors.New("ca_id is required")
	}
	for name, p := range map[string]string{"repo_pattern": r.RepoPattern, "ref_pattern": r.RefPattern} {
		if p == "" {
			return fmt.Errorf("%s is required", name)
		}
		if strings.Contains(p, "**") {
			return fmt.Errorf("%s: ** is not supported (* matches within one path segment)", name)
		}
		if _, err := path.Match(p, ""); errors.Is(err, path.ErrBadPattern) {
			return fmt.Errorf("%s: malformed pattern", name)
		}
	}
	if !strings.Contains(r.RepoPattern, "/") || strings.HasPrefix(r.RepoPattern, "*") {
		return errors.New("repo_pattern must name an owner (contain '/' and not start with '*')")
	}
	if !strings.HasPrefix(r.RefPattern, "refs/") {
		return errors.New("ref_pattern must start with refs/")
	}
	return nil
}

func normalizeTrustRule(r CodesignTrustRule) CodesignTrustRule {
	r.Issuer = strings.TrimRight(strings.TrimSpace(r.Issuer), "/")
	r.Audience = strings.TrimSpace(r.Audience)
	r.CAID = strings.TrimSpace(r.CAID)
	return r
}

// ProposeCodesignTrustRule queues a rule for approval; it never writes the
// rule itself. A CA outside the proposer's tenant is refused here, early, and
// again by the executor (the CA's tenant mapping may change while queued).
func ProposeCodesignTrustRule(ctx context.Context, pending PendingActionStore, pd AuthPrincipal, r CodesignTrustRule, rationale string) (PendingAction, error) {
	r = normalizeTrustRule(r)
	if err := validateTrustRule(r); err != nil {
		return PendingAction{}, err
	}
	if !caVisibleToTenant(ctx, activeTenantStore, pd, r.CAID) {
		return PendingAction{}, errors.New("ca_id is not visible to your tenant")
	}
	if pending == nil {
		return PendingAction{}, errors.New("approval queue unavailable")
	}
	params, err := json.Marshal(r)
	if err != nil {
		return PendingAction{}, err
	}
	return pending.Create(ctx, PendingAction{
		ActionType: ActionCodesignTrustRule, Params: params, ProposedBy: pd.ID,
		Rationale: rationale, Status: "pending", Tenant: pd.Tenant,
	})
}

// NewCodesignTrustRuleExecutor applies an approved rule. The queue already
// enforced approver role, no-self-approval and quorum; this adds validation
// and the tenant gate only it can apply (the CA must belong to the tenant the
// proposal was made under).
func NewCodesignTrustRuleExecutor(store CodesignTrustStore, audit AuditProvider) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		if store == nil {
			return nil, errors.New("code-signing trust store unavailable")
		}
		var r CodesignTrustRule
		if err := json.Unmarshal(action.Params, &r); err != nil {
			return nil, fmt.Errorf("invalid trust rule params: %w", err)
		}
		r = normalizeTrustRule(r)
		if err := validateTrustRule(r); err != nil {
			return nil, err
		}
		tenant := action.Tenant
		if tenant == "" {
			tenant = DefaultTenant
		}
		if !caVisibleToTenant(ctx, activeTenantStore, AuthPrincipal{Tenant: tenant}, r.CAID) {
			return nil, errors.New("ca_id is not visible to the proposing tenant")
		}
		r.CreatedBy, r.ApprovedBy, r.Tenant = action.ProposedBy, approver.ID, tenant
		created, err := store.CreateRule(ctx, r)
		if err != nil {
			return nil, err
		}
		if audit != nil {
			if aerr := audit.AppendEntry(ctx, AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "codesign.trust_rule_create",
				ActorType: "user", ActorID: approver.ID, ResourceType: "codesign_trust_rule", ResourceID: created.ID,
				Outcome: AuditOutcomeSuccess, Tenant: tenant,
				ChangeSummary: fmt.Sprintf("issuer=%q audience=%q repo=%q ref=%q ca=%s proposed_by=%s approved_by=%s",
					created.Issuer, created.Audience, created.RepoPattern, created.RefPattern, created.CAID, action.ProposedBy, approver.ID),
			}); aerr != nil {
				logging.Infof("ERROR codesign trust rule %s created but the audit append failed: %v", created.ID, aerr)
			}
		}
		return json.Marshal(map[string]any{"rule_id": created.ID})
	}
}

// CodesignIdentity is the verified caller: the rule that admitted it and the
// signed claims it presented.
type CodesignIdentity struct {
	Rule                            CodesignTrustRule
	Issuer, Subject, Repo, Ref, JTI string
	ExpiresAt                       time.Time
}

// CodesignRefusal is a token refusal. Reason is a closed code that goes only
// to the audit trail; callers get a generic 401.
type CodesignRefusal struct{ Issuer, Reason, Detail string }

func (e *CodesignRefusal) Error() string {
	return "codesign token refused: " + e.Reason
}

func codesignTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// CodesignOIDCVerifier checks a CI OIDC token against the approved trust rules.
type CodesignOIDCVerifier struct {
	store CodesignTrustStore
	now   func() time.Time
	// transport overrides the JWKS HTTP transport (tests point it at a fake IdP).
	transport http.RoundTripper

	mu     sync.Mutex
	caches map[string]*managedOIDCJWKSCache
}

func NewCodesignOIDCVerifier(store CodesignTrustStore) *CodesignOIDCVerifier {
	return &CodesignOIDCVerifier{store: store, now: time.Now, caches: map[string]*managedOIDCJWKSCache{}}
}

func (v *CodesignOIDCVerifier) cacheFor(issuer string) (*managedOIDCJWKSCache, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok := v.caches[issuer]; ok {
		return c, nil
	}
	c, err := newManagedOIDCJWKSCache(issuer+"/.well-known/openid-configuration", 10*time.Second, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	if v.transport != nil {
		c.client.Transport = v.transport
	}
	v.caches[issuer] = c
	return c, nil
}

func decodeJWTPayload(token string) (map[string]any, error) {
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return nil, errors.New("not a jwt")
	}
	raw, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func claimString(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// Verify admits rawToken only when an approved rule matches it and its jti is
// unseen. The returned error is always *CodesignRefusal.
func (v *CodesignOIDCVerifier) Verify(ctx context.Context, rawToken string) (CodesignIdentity, error) {
	refuse := func(issuer, reason, detail string) (CodesignIdentity, error) {
		return CodesignIdentity{}, &CodesignRefusal{Issuer: codesignTruncate(issuer, codesignIssuerMax), Reason: reason, Detail: codesignTruncate(detail, codesignDetailMax)}
	}
	if rawToken == "" || len(rawToken) > codesignMaxToken {
		return refuse("", ReasonMalformed, "empty or oversize token")
	}
	// (a) iss is untrusted until the signature passes; it only selects rules.
	pre, err := decodeJWTPayload(rawToken)
	if err != nil {
		return refuse("", ReasonMalformed, "token is not a decodable jwt")
	}
	iss := claimString(pre, "iss")
	if iss == "" {
		return refuse("", ReasonMalformed, "missing iss")
	}
	if v.store == nil {
		return refuse(iss, ReasonUntrustedIssuer, "trust store unavailable")
	}
	rules, err := v.store.RulesForIssuer(ctx, iss)
	if err != nil {
		return refuse(iss, ReasonUntrustedIssuer, "trust lookup failed")
	}
	if len(rules) == 0 {
		return refuse(iss, ReasonUntrustedIssuer, "no trust rule for issuer")
	}
	// (c) signature/exp/nbf/iss/aud, once per distinct rule audience.
	cache, err := v.cacheFor(iss)
	if err != nil {
		return refuse(iss, ReasonUntrustedIssuer, "issuer not usable")
	}
	now := v.now()
	var verifiedAud, lastErr string
	seen := map[string]bool{}
	for _, rl := range rules {
		if seen[rl.Audience] {
			continue
		}
		seen[rl.Audience] = true
		if _, _, verr := validateOIDCRS256JWTManaged(ctx, rawToken, cache, iss, rl.Audience, "", now); verr == nil {
			verifiedAud = rl.Audience
			break
		} else {
			lastErr = verr.Error()
		}
	}
	if verifiedAud == "" {
		return refuse(iss, ReasonTokenInvalid, lastErr)
	}
	// (d) payload is now signed; read the claims the shared validator skips.
	claims, err := decodeJWTPayload(rawToken)
	if err != nil {
		return refuse(iss, ReasonMalformed, "payload not decodable")
	}
	jti := claimString(claims, "jti")
	if jti == "" {
		return refuse(iss, ReasonMissingJTI, "token has no jti")
	}
	expF, ok1 := claims["exp"].(float64)
	iatF, ok2 := claims["iat"].(float64)
	if !ok1 || !ok2 {
		return refuse(iss, ReasonTokenInvalid, "exp and iat are required")
	}
	exp, iat := time.Unix(int64(expF), 0), time.Unix(int64(iatF), 0)
	if iat.After(now.Add(jwtClockSkew)) {
		return refuse(iss, ReasonTokenInvalid, "iat is in the future")
	}
	if exp.Sub(iat) > codesignMaxTokenAge {
		return refuse(iss, ReasonTokenInvalid, "token lifetime exceeds 1h")
	}
	// (e) a rule for this audience must match repo and ref.
	var matched *CodesignTrustRule
	var repo, ref string
	for i := range rules {
		rl := rules[i]
		if rl.Audience != verifiedAud {
			continue
		}
		set := codesignClaimSets[rl.Provider]
		repo, ref = claimString(claims, set.Repo), claimString(claims, set.Ref)
		rm, _ := path.Match(rl.RepoPattern, repo)
		fm, _ := path.Match(rl.RefPattern, ref)
		if rm && fm {
			matched = &rules[i]
			break
		}
	}
	if matched == nil {
		return refuse(iss, ReasonNoMatchingRule, fmt.Sprintf("repo=%q ref=%q", codesignTruncate(repo, 100), codesignTruncate(ref, 100)))
	}
	// (f) consume the jti only once a rule matched, so junk tokens cannot burn ids.
	fresh, err := v.store.ConsumeJTI(ctx, iss, jti, exp.Add(codesignMaxSkew))
	if err != nil {
		return refuse(iss, ReasonTokenInvalid, "replay ledger unavailable")
	}
	if !fresh {
		return refuse(iss, ReasonReplay, "jti already used")
	}
	set := codesignClaimSets[matched.Provider]
	return CodesignIdentity{
		Rule: *matched, Issuer: iss, Subject: claimString(claims, "sub"),
		Repo: claimString(claims, set.Repo), Ref: claimString(claims, set.Ref), JTI: jti, ExpiresAt: exp,
	}, nil
}

// AuditCodesignRefusal records a refused token with its issuer and reason
// (never the token itself).
func AuditCodesignRefusal(r *http.Request, audit AuditProvider, ref *CodesignRefusal) {
	issuer := ref.Issuer
	actor := "oidc:" + issuer
	if issuer == "" {
		actor = "oidc:unknown"
	}
	detail := fmt.Sprintf("issuer=%q reason=%s", issuer, ref.Reason)
	if ref.Detail != "" {
		detail += fmt.Sprintf(" detail=%q", ref.Detail)
	}
	emitAuditEventDetail(r, audit, actor, "codesign.issue", "codesign", "oidc", AuditOutcomeDenied, detail)
}
