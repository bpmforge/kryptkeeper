// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package spiffe_test

// Live NHI lifecycle (W29-05): propose -> approve -> redeem -> revoke against
// the real hub brought up by run.sh, with the same KK_LIVE_SPIFFE gate and
// KK_SPIFFE_* env as spiffe_live_test.go. Every test creates its own NHI
// (unique name) and its own API keys, and shares nothing with the others.

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func nhiHub(t *testing.T) (base, bootstrapToken string) {
	t.Helper()
	if os.Getenv("KK_LIVE_SPIFFE") != "1" {
		t.Skip("set KK_LIVE_SPIFFE=1 (and the KK_SPIFFE_* vars) to run against a live hub; see tests/live/spiffe/run.sh")
	}
	base, bootstrapToken = os.Getenv("KK_SPIFFE_HUB_BASE"), os.Getenv("KK_SPIFFE_TOKEN")
	if base == "" || bootstrapToken == "" {
		t.Fatal("KK_LIVE_SPIFFE=1 but KK_SPIFFE_HUB_BASE / KK_SPIFFE_TOKEN is unset")
	}
	return base, bootstrapToken
}

func nhiDo(t *testing.T, token, method, path string, body any) (int, []byte) {
	t.Helper()
	base, _ := nhiHub(t)
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // test-controlled local URL
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// nhiNamedKey returns a named-administrator key provisioned by run.sh. Keys
// minted with the bootstrap token are setup credentials and can never
// approve (RC1-B-01), so the proposer and approver cannot be minted here.
func nhiNamedKey(t *testing.T, env string) string {
	t.Helper()
	nhiHub(t)
	v := os.Getenv(env)
	if v == "" {
		t.Fatalf("KK_LIVE_SPIFFE=1 but %s is unset (run.sh provisions it)", env)
	}
	return v
}

// nhiMintKey creates an API key with a unique principal (never logged).
func nhiMintKey(t *testing.T, name, role string) string {
	t.Helper()
	_, boot := nhiHub(t)
	name = fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	code, body := nhiDo(t, boot, http.MethodPost, "/api/v1/api-keys",
		map[string]any{"name": name, "principal_id": name, "role": role, "scopes": []string{"*"}})
	if code != http.StatusCreated {
		t.Fatalf("mint %s key: %d %s", role, code, body)
	}
	var r struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Data.Token == "" {
		t.Fatalf("mint %s key: bad response", role)
	}
	return r.Data.Token
}

type nhiRecord struct {
	ID       string `json:"id"`
	SPIFFEID string `json:"spiffe_id"`
	Status   string `json:"status"`
}

func nhiPropose(t *testing.T, token, label string) nhiRecord {
	t.Helper()
	name := fmt.Sprintf("live-%s-%d", label, time.Now().UnixNano())
	code, body := nhiDo(t, token, http.MethodPost, "/api/v1/nhi/identities",
		map[string]any{"name": name, "kind": "ai_agent", "scopes": []string{"certificate.read"}})
	if code != http.StatusCreated {
		t.Fatalf("propose: %d %s", code, body)
	}
	var r struct {
		Data nhiRecord `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Data.Status != "pending" {
		t.Fatalf("propose: want pending record, got %s", body)
	}
	return r.Data
}

// nhiApprove approves and returns the join token (shown once; never logged).
func nhiApprove(t *testing.T, approver string, n nhiRecord) string {
	t.Helper()
	code, body := nhiDo(t, approver, http.MethodPost, "/api/v1/nhi/identities/"+n.ID+"/approve", nil)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	var r struct {
		Data struct {
			JoinToken string `json:"join_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Data.JoinToken == "" {
		t.Fatal("approve: no join token in response")
	}
	return r.Data.JoinToken
}

type nhiSVID struct {
	SVIDPEM, BundlePEM string
	Code               int
}

func nhiRedeem(t *testing.T, joinToken string) nhiSVID {
	t.Helper()
	code, body := nhiDo(t, "", http.MethodPost, "/api/v1/spiffe/workload-svid", map[string]string{"join_token": joinToken})
	out := nhiSVID{Code: code}
	if code == http.StatusCreated {
		var r struct {
			Data struct {
				SVIDPEM   string `json:"svid_pem"`
				KeyPEM    string `json:"key_pem"`
				BundlePEM string `json:"bundle_pem"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil || r.Data.SVIDPEM == "" || r.Data.KeyPEM == "" || r.Data.BundlePEM == "" {
			t.Fatal("redeem: incomplete SVID response")
		}
		out.SVIDPEM, out.BundlePEM = r.Data.SVIDPEM, r.Data.BundlePEM
	}
	return out
}

func nhiStatus(t *testing.T, token, id string) string {
	t.Helper()
	code, body := nhiDo(t, token, http.MethodGet, "/api/v1/nhi/identities", nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	var r struct {
		Data []nhiRecord `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	for _, n := range r.Data {
		if n.ID == id {
			return n.Status
		}
	}
	t.Fatalf("nhi %s not in list", id)
	return ""
}

func TestNHILiveSelfApprovalRefused(t *testing.T) {
	proposer := nhiNamedKey(t, "KK_SPIFFE_PROPOSER_TOKEN")
	n := nhiPropose(t, proposer, "selfapprove")
	code, body := nhiDo(t, proposer, http.MethodPost, "/api/v1/nhi/identities/"+n.ID+"/approve", nil)
	if code != http.StatusForbidden || !strings.Contains(string(body), "self-approval is not permitted") {
		t.Fatalf("self-approval: want 403 + refusal text, got %d %s", code, body)
	}
	if st := nhiStatus(t, proposer, n.ID); st != "pending" {
		t.Fatalf("status %q after refused self-approval", st)
	}
}

func TestNHILiveMCPAgentCannotApprove(t *testing.T) {
	proposer := nhiNamedKey(t, "KK_SPIFFE_PROPOSER_TOKEN")
	// The bootstrap token is pki-admin, so it may mint the mcp-agent key.
	mcp := nhiMintKey(t, "nhi-mcp", "mcp-agent")
	n := nhiPropose(t, proposer, "mcpdeny")
	code, body := nhiDo(t, mcp, http.MethodPost, "/api/v1/nhi/identities/"+n.ID+"/approve", nil)
	if code != http.StatusForbidden {
		t.Fatalf("mcp-agent approve: want 403, got %d %s", code, body)
	}
	if st := nhiStatus(t, proposer, n.ID); st != "pending" {
		t.Fatalf("status %q after refused mcp-agent approval", st)
	}
}

func TestNHILiveRedeemOnce(t *testing.T) {
	proposer := nhiNamedKey(t, "KK_SPIFFE_PROPOSER_TOKEN")
	approver := nhiNamedKey(t, "KK_SPIFFE_APPROVER_TOKEN")
	n := nhiPropose(t, proposer, "redeem")
	tok := nhiApprove(t, approver, n)
	if first := nhiRedeem(t, tok); first.Code != http.StatusCreated {
		t.Fatalf("first redeem: %d", first.Code)
	}
	if second := nhiRedeem(t, tok); second.Code != http.StatusUnauthorized {
		t.Fatalf("second redeem: want 401, got %d", second.Code)
	}
}

// The join token's own TTL (24h minimum) cannot expire inside a live run;
// that path is covered by the unit tests. What a live run CAN prove is that
// an SVID stops validating once its NotAfter passes.
func TestNHILiveExpiredSVIDRejected(t *testing.T) {
	proposer := nhiNamedKey(t, "KK_SPIFFE_PROPOSER_TOKEN")
	approver := nhiNamedKey(t, "KK_SPIFFE_APPROVER_TOKEN")
	n := nhiPropose(t, proposer, "expiry")
	svid := nhiRedeem(t, nhiApprove(t, approver, n))
	if svid.Code != http.StatusCreated {
		t.Fatalf("redeem: %d", svid.Code)
	}
	block, _ := pem.Decode([]byte(svid.SVIDPEM))
	if block == nil {
		t.Fatal("svid not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(svid.BundlePEM)) {
		t.Fatal("bundle has no certificates")
	}
	opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: time.Now()}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("fresh SVID must verify: %v", err)
	}
	opts.CurrentTime = leaf.NotAfter.Add(time.Second)
	_, err = leaf.Verify(opts)
	var inv x509.CertificateInvalidError
	if !errors.As(err, &inv) || inv.Reason != x509.Expired {
		t.Fatalf("expired SVID must fail with Expired, got %v", err)
	}
}

func TestNHILiveRevokedCannotMint(t *testing.T) {
	proposer := nhiNamedKey(t, "KK_SPIFFE_PROPOSER_TOKEN")
	approver := nhiNamedKey(t, "KK_SPIFFE_APPROVER_TOKEN")

	// Revoked before redemption: the unredeemed join token must be dead.
	n := nhiPropose(t, proposer, "revoke-unredeemed")
	tok := nhiApprove(t, approver, n)
	if code, body := nhiDo(t, approver, http.MethodPost, "/api/v1/nhi/identities/"+n.ID+"/revoke", nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if r := nhiRedeem(t, tok); r.Code != http.StatusUnauthorized {
		t.Fatalf("revoked NHI minted an SVID: %d", r.Code)
	}

	// Revoked after redemption: status flips and a repeat revoke is idempotent.
	m := nhiPropose(t, proposer, "revoke-redeemed")
	if r := nhiRedeem(t, nhiApprove(t, approver, m)); r.Code != http.StatusCreated {
		t.Fatalf("redeem: %d", r.Code)
	}
	for i := 0; i < 2; i++ {
		if code, body := nhiDo(t, approver, http.MethodPost, "/api/v1/nhi/identities/"+m.ID+"/revoke", nil); code != http.StatusNoContent {
			t.Fatalf("revoke #%d: %d %s", i+1, code, body)
		}
	}
	if st := nhiStatus(t, approver, m.ID); st != "revoked" {
		t.Fatalf("status %q, want revoked", st)
	}
}

func TestNHILiveAuditTrail(t *testing.T) {
	proposer := nhiNamedKey(t, "KK_SPIFFE_PROPOSER_TOKEN")
	approver := nhiNamedKey(t, "KK_SPIFFE_APPROVER_TOKEN")
	n := nhiPropose(t, proposer, "audit")
	// self-approval attempt -> an nhi.approve failure row
	if code, _ := nhiDo(t, proposer, http.MethodPost, "/api/v1/nhi/identities/"+n.ID+"/approve", nil); code != http.StatusForbidden {
		t.Fatalf("self-approval: %d", code)
	}
	nhiApprove(t, approver, n)
	if code, _ := nhiDo(t, approver, http.MethodPost, "/api/v1/nhi/identities/"+n.ID+"/revoke", nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}

	outcomes := func(action string) map[string]bool {
		q := url.Values{"action": {action}, "resource_id": {n.ID}, "limit": {"100"}}
		code, body := nhiDo(t, approver, http.MethodGet, "/api/v1/audit?"+q.Encode(), nil)
		if code != http.StatusOK {
			t.Fatalf("audit %s: %d %s", action, code, body)
		}
		var r struct {
			Data []struct {
				Action     string `json:"action"`
				ResourceID string `json:"resource_id"`
				Outcome    string `json:"outcome"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, e := range r.Data {
			if e.Action == action && e.ResourceID == n.ID {
				got[e.Outcome] = true
			}
		}
		return got
	}
	for _, action := range []string{"nhi.propose", "nhi.approve", "nhi.revoke"} {
		if !outcomes(action)["success"] {
			t.Errorf("no success audit row for %s on %s", action, n.ID)
		}
	}
	if !outcomes("nhi.approve")["failure"] {
		t.Error("self-approval left no nhi.approve failure row")
	}
}
