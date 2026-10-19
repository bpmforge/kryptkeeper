// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// codesignIdP is a fake CI OIDC issuer (discovery + JWKS over TLS) plus a
// verifier wired to a real sqlite trust store. W29-12 tests reuse it.
type codesignIdP struct {
	t      *testing.T
	srv    *httptest.Server
	priv   *rsa.PrivateKey
	issuer string
	now    time.Time
	store  CodesignTrustStore
	v      *CodesignOIDCVerifier
	jtiN   int
}

const codesignTestKID = "ci-key-1"

func newCodesignIdP(t *testing.T) *codesignIdP {
	t.Helper()
	f := &codesignIdP{t: t, priv: generateTestRSAKey(t), now: time.Now().UTC().Truncate(time.Second)}
	jwks := buildTestJWKS(t, codesignTestKID, &f.priv.PublicKey)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": f.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(jwks)) })
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	f.issuer = f.srv.URL

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "codesign.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := &dbCodesignTrustStore{db: db, ph: sqlitePlaceholder}
	if err := st.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.store = st
	f.v = NewCodesignOIDCVerifier(st)
	f.v.transport = f.srv.Client().Transport
	f.v.now = func() time.Time { return f.now }
	return f
}

func (f *codesignIdP) addRule(provider, aud, repo, ref string) CodesignTrustRule {
	f.t.Helper()
	r, err := f.store.CreateRule(context.Background(), CodesignTrustRule{
		Provider: provider, Issuer: f.issuer, Audience: aud, RepoPattern: repo, RefPattern: ref,
		CAID: "ca-1", CreatedBy: "alice", ApprovedBy: "bob",
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// claims returns a valid GitHub-shaped claim set; mut adjusts it.
func (f *codesignIdP) claims(mut func(map[string]any)) map[string]any {
	f.jtiN++
	c := map[string]any{
		"iss": f.issuer, "aud": "lab-hub", "sub": "repo:acme/app:ref:refs/heads/main",
		"iat": f.now.Unix(), "nbf": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(),
		"jti": "jti-" + strings.Repeat("x", f.jtiN), "repository": "acme/app", "ref": "refs/heads/main",
	}
	if mut != nil {
		mut(c)
	}
	return c
}

func (f *codesignIdP) token(mut func(map[string]any)) string {
	return signTestRS256JWT(f.t, f.priv, codesignTestKID, f.claims(mut))
}

func (f *codesignIdP) verify(tok string) (CodesignIdentity, *CodesignRefusal) {
	f.t.Helper()
	id, err := f.v.Verify(context.Background(), tok)
	if err == nil {
		return id, nil
	}
	var ref *CodesignRefusal
	if !errors.As(err, &ref) {
		f.t.Fatalf("Verify error is not *CodesignRefusal: %v", err)
	}
	return id, ref
}

func wantReason(t *testing.T, ref *CodesignRefusal, reason string) {
	t.Helper()
	if ref == nil {
		t.Fatalf("expected refusal %q, token was accepted", reason)
	}
	if ref.Reason != reason {
		t.Fatalf("reason = %q (%s), want %q", ref.Reason, ref.Detail, reason)
	}
}

func newCodesignPending(t *testing.T) PendingActionStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	p := &dbPendingActionStore{db: db, ph: sqlitePlaceholder}
	if err := p.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p
}

func goodRule() CodesignTrustRule {
	return CodesignTrustRule{
		Provider: "github", Issuer: "https://token.actions.githubusercontent.com", Audience: "lab-hub",
		RepoPattern: "acme/app", RefPattern: "refs/heads/main", CAID: "ca-1",
	}
}

func TestProposeTrustRule_QueuesOnly(t *testing.T) {
	f := newCodesignIdP(t)
	pending := newCodesignPending(t)
	act, err := ProposeCodesignTrustRule(context.Background(), pending, AuthPrincipal{ID: "alice", Tenant: DefaultTenant}, goodRule(), "ship it")
	if err != nil {
		t.Fatal(err)
	}
	if act.ActionType != ActionCodesignTrustRule || act.ProposedBy != "alice" || act.Status != "pending" {
		t.Fatalf("unexpected pending action: %+v", act)
	}
	var p CodesignTrustRule
	if err := json.Unmarshal(act.Params, &p); err != nil || p.RepoPattern != "acme/app" {
		t.Fatalf("params not carried: %v %s", err, act.Params)
	}
	rules, err := f.store.ListRules(context.Background())
	if err != nil || len(rules) != 0 {
		t.Fatalf("propose must not write a rule: %v %v", rules, err)
	}
}

func TestTrustRuleExecutor_CreatesAndAudits(t *testing.T) {
	f := newCodesignIdP(t)
	aud := &recordingAuditProvider{}
	exec := NewCodesignTrustRuleExecutor(f.store, aud)
	params, _ := json.Marshal(goodRule())
	res, err := exec(context.Background(), PendingAction{ID: "pa-1", Params: params, ProposedBy: "alice"}, AuthPrincipal{ID: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		RuleID string `json:"rule_id"`
	}
	_ = json.Unmarshal(res, &out)
	got, ok, err := f.store.GetRule(context.Background(), out.RuleID)
	if err != nil || !ok {
		t.Fatalf("rule not stored: %v %v", ok, err)
	}
	if got.CreatedBy != "alice" || got.ApprovedBy != "bob" || got.Tenant != DefaultTenant {
		t.Fatalf("provenance wrong: %+v", got)
	}
	if len(aud.entries) != 1 || aud.entries[0].Action != "codesign.trust_rule_create" {
		t.Fatalf("audit entries: %+v", aud.entries)
	}
	cs := aud.entries[0].ChangeSummary
	if !strings.Contains(cs, "proposed_by=alice") || !strings.Contains(cs, "approved_by=bob") {
		t.Fatalf("summary lacks proposer/approver: %s", cs)
	}
}

func TestProposeTrustRule_RejectsBroadPatterns(t *testing.T) {
	cases := map[string]func(*CodesignTrustRule){
		"repo star":      func(r *CodesignTrustRule) { r.RepoPattern = "*" },
		"repo star/x":    func(r *CodesignTrustRule) { r.RepoPattern = "*/x" },
		"repo no slash":  func(r *CodesignTrustRule) { r.RepoPattern = "acme" },
		"repo double":    func(r *CodesignTrustRule) { r.RepoPattern = "acme/**" },
		"ref star":       func(r *CodesignTrustRule) { r.RefPattern = "*" },
		"ref bare main":  func(r *CodesignTrustRule) { r.RefPattern = "main" },
		"bad glob":       func(r *CodesignTrustRule) { r.RepoPattern = "acme/[" },
		"http issuer":    func(r *CodesignTrustRule) { r.Issuer = "http://token.example.com" },
		"unknown prov":   func(r *CodesignTrustRule) { r.Provider = "bitbucket" },
		"empty audience": func(r *CodesignTrustRule) { r.Audience = " " },
		"empty ca":       func(r *CodesignTrustRule) { r.CAID = "" },
	}
	pending := newCodesignPending(t)
	for name, mut := range cases {
		r := goodRule()
		mut(&r)
		if _, err := ProposeCodesignTrustRule(context.Background(), pending, AuthPrincipal{ID: "alice"}, r, ""); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
	// A broad rule smuggled past Propose is still refused by the executor.
	r := goodRule()
	r.RepoPattern = "*"
	params, _ := json.Marshal(r)
	f := newCodesignIdP(t)
	if _, err := NewCodesignTrustRuleExecutor(f.store, nil)(context.Background(), PendingAction{Params: params, ProposedBy: "a"}, AuthPrincipal{ID: "b"}); err == nil {
		t.Error("executor accepted a broad pattern")
	}
}

func TestTrustRule_TenantGate(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	ts := newTestTenantStore(t)
	ctx := context.Background()
	for _, id := range []string{"acme", "globex"} {
		if _, err := ts.CreateTenant(ctx, id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.SetCATenant(ctx, "ca-globex", "globex"); err != nil {
		t.Fatal(err)
	}
	if err := ts.SetCATenant(ctx, "ca-acme", "acme"); err != nil {
		t.Fatal(err)
	}
	prev := activeTenantStore
	setActiveTenantStore(ts)
	t.Cleanup(func() { setActiveTenantStore(prev) })

	pending := newCodesignPending(t)
	r := goodRule()
	r.CAID = "ca-globex"
	if _, err := ProposeCodesignTrustRule(ctx, pending, AuthPrincipal{ID: "alice", Tenant: "acme"}, r, ""); err == nil {
		t.Fatal("propose accepted a CA outside the proposer's tenant")
	}
	r.CAID = "ca-acme"
	if _, err := ProposeCodesignTrustRule(ctx, pending, AuthPrincipal{ID: "alice", Tenant: "acme"}, r, ""); err != nil {
		t.Fatalf("own-tenant CA refused: %v", err)
	}

	f := newCodesignIdP(t)
	bad := goodRule()
	bad.CAID = "ca-globex"
	params, _ := json.Marshal(bad)
	_, err := NewCodesignTrustRuleExecutor(f.store, nil)(ctx, PendingAction{Params: params, ProposedBy: "alice", Tenant: "acme"}, AuthPrincipal{ID: "bob", SuperAdmin: true})
	if err == nil {
		t.Fatal("executor created a rule for a CA outside the proposer's tenant")
	}
	if rules, _ := f.store.ListRules(ctx); len(rules) != 0 {
		t.Fatalf("rule leaked: %v", rules)
	}
}

func TestVerify_Accepts_GitHubAndGitLab(t *testing.T) {
	cases := []struct {
		provider, repoClaim, repoVal, pattern string
	}{
		{"github", "repository", "acme/app", "acme/app"},
		{"gitlab", "project_path", "group/sub/proj", "group/sub/*"},
	}
	for _, c := range cases {
		t.Run(c.provider, func(t *testing.T) {
			f := newCodesignIdP(t)
			f.addRule(c.provider, "lab-hub", c.pattern, "refs/heads/main")
			tok := f.token(func(m map[string]any) {
				delete(m, "repository")
				m[c.repoClaim] = c.repoVal
			})
			id, ref := f.verify(tok)
			if ref != nil {
				t.Fatalf("refused: %+v", ref)
			}
			if id.Repo != c.repoVal || id.Ref != "refs/heads/main" || id.Rule.Provider != c.provider {
				t.Fatalf("identity: %+v", id)
			}
		})
	}
}

func TestVerify_UntrustedIssuer(t *testing.T) {
	f := newCodesignIdP(t)
	_, ref := f.verify(f.token(nil))
	wantReason(t, ref, ReasonUntrustedIssuer)
	if ref.Issuer != f.issuer {
		t.Fatalf("refusal lacks issuer: %+v", ref)
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	_, ref := f.verify(f.token(func(m map[string]any) { m["aud"] = "someone-else" }))
	wantReason(t, ref, ReasonTokenInvalid)
}

func TestVerify_BadSignature(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	tok := signTestRS256JWT(t, generateTestRSAKey(t), codesignTestKID, f.claims(nil))
	_, ref := f.verify(tok)
	wantReason(t, ref, ReasonTokenInvalid)
}

func TestVerify_Expired(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	_, ref := f.verify(f.token(func(m map[string]any) { m["exp"] = f.now.Add(-1 * time.Second).Unix() }))
	wantReason(t, ref, ReasonTokenInvalid)
}

func TestVerify_RepoMismatch(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	_, ref := f.verify(f.token(func(m map[string]any) { m["repository"] = "evil/app" }))
	wantReason(t, ref, ReasonNoMatchingRule)
}

func TestVerify_RefMismatch(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	_, ref := f.verify(f.token(func(m map[string]any) { m["ref"] = "refs/heads/feature" }))
	wantReason(t, ref, ReasonNoMatchingRule)
}

func TestVerify_RefGlobTag(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/tags/v*")
	if _, ref := f.verify(f.token(func(m map[string]any) { m["ref"] = "refs/tags/v1.2.3" })); ref != nil {
		t.Fatalf("tag ref refused: %+v", ref)
	}
	_, ref := f.verify(f.token(func(m map[string]any) { m["ref"] = "refs/heads/main" }))
	wantReason(t, ref, ReasonNoMatchingRule)
}

func TestVerify_ReplayedJTI(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	tok := f.token(nil)
	if _, ref := f.verify(tok); ref != nil {
		t.Fatalf("first use refused: %+v", ref)
	}
	_, ref := f.verify(tok)
	wantReason(t, ref, ReasonReplay)

	// A rule mismatch must not burn the jti: the same jti, presented with
	// a matching claim set afterwards, is still fresh.
	bad := f.token(func(m map[string]any) { m["jti"] = "shared"; m["ref"] = "refs/heads/other" })
	_, ref = f.verify(bad)
	wantReason(t, ref, ReasonNoMatchingRule)
	good := f.token(func(m map[string]any) { m["jti"] = "shared" })
	if _, ref := f.verify(good); ref != nil {
		t.Fatalf("jti was burned by a refused token: %+v", ref)
	}
}

func TestVerify_MissingJTI(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	_, ref := f.verify(f.token(func(m map[string]any) { delete(m, "jti") }))
	wantReason(t, ref, ReasonMissingJTI)
}

func TestVerify_Malformed(t *testing.T) {
	f := newCodesignIdP(t)
	for name, tok := range map[string]string{
		"empty": "", "garbage": "abc", "oversize": strings.Repeat("a", codesignMaxToken+1),
	} {
		_, ref := f.verify(tok)
		if ref == nil || ref.Reason != ReasonMalformed {
			t.Errorf("%s: %+v", name, ref)
		}
	}
}

func TestVerify_SkewBounded(t *testing.T) {
	f := newCodesignIdP(t)
	f.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	if _, ref := f.verify(f.token(func(m map[string]any) { m["nbf"] = f.now.Add(30 * time.Second).Unix() })); ref != nil {
		t.Fatalf("nbf +30s must be inside the skew: %+v", ref)
	}
	_, ref := f.verify(f.token(func(m map[string]any) { m["nbf"] = f.now.Add(5 * time.Minute).Unix() }))
	wantReason(t, ref, ReasonTokenInvalid)
	_, ref = f.verify(f.token(func(m map[string]any) { m["iat"] = f.now.Add(5 * time.Minute).Unix() }))
	wantReason(t, ref, ReasonTokenInvalid)
	_, ref = f.verify(f.token(func(m map[string]any) { m["exp"] = f.now.Add(-1 * time.Second).Unix() }))
	wantReason(t, ref, ReasonTokenInvalid)
	// A long-lived token is not a CI token.
	_, ref = f.verify(f.token(func(m map[string]any) { m["exp"] = f.now.Add(3 * time.Hour).Unix() }))
	wantReason(t, ref, ReasonTokenInvalid)
}

func TestAuditCodesignRefusal_HasIssuerAndReason(t *testing.T) {
	aud := &recordingAuditProvider{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codesign/issue", nil)
	AuditCodesignRefusal(req, aud, &CodesignRefusal{Issuer: "https://idp.example", Reason: ReasonReplay, Detail: "jti already used"})
	if len(aud.entries) != 1 {
		t.Fatalf("entries: %+v", aud.entries)
	}
	e := aud.entries[0]
	if e.Action != "codesign.issue" || e.Outcome != AuditOutcomeDenied {
		t.Fatalf("entry: %+v", e)
	}
	if !strings.Contains(e.ChangeSummary, "https://idp.example") || !strings.Contains(e.ChangeSummary, "reason=replay") {
		t.Fatalf("summary: %s", e.ChangeSummary)
	}
}

func TestConsumeJTI_PrunesExpired(t *testing.T) {
	f := newCodesignIdP(t)
	ctx := context.Background()
	fresh, err := f.store.ConsumeJTI(ctx, "iss", "j1", time.Now().Add(-time.Hour))
	if err != nil || !fresh {
		t.Fatalf("first: %v %v", fresh, err)
	}
	fresh, err = f.store.ConsumeJTI(ctx, "iss", "j1", time.Now().Add(time.Hour))
	if err != nil || !fresh {
		t.Fatalf("expired row must not block reuse: %v %v", fresh, err)
	}
	fresh, _ = f.store.ConsumeJTI(ctx, "iss", "j1", time.Now().Add(time.Hour))
	if fresh {
		t.Fatal("live row must block reuse")
	}
}
