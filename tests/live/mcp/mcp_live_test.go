// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package mcp_test is the W29-08 live acceptance for the MCP server: the REAL
// kryptkeeper-mcp binary, driven by the official mark3labs/mcp-go client over
// stdio and over StreamableHTTP, against a REAL hub process. For each of the
// five propose_* tools it proves propose -> (nothing mutated) -> human
// approve -> executed, and that the mcp-agent role can never approve.
//
// Skipped unless KK_LIVE_MCP=1. tests/live/mcp/run.sh owns the lifecycle
// (builds both binaries, starts the hub) and sets:
//
//	KK_MCP_HUB_BASE          e.g. http://127.0.0.1:8098
//	KK_MCP_ADMIN_TOKEN       the hub's bootstrap token (pki-admin; setup only)
//	KK_MCP_BIN               path to the kryptkeeper-mcp binary
//	KK_MCP_APPROVER_EMAIL    named administrator the hub was configured with
//	KK_MCP_APPROVER_PASSWORD (login password for that administrator)
//
// The human approver is a named login, not an API key: the bootstrap token and
// every key minted with it are setup credentials that the hub refuses as
// approvers (separation_of_duties.go), which is itself part of what is proved.
package mcp_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

const agentPrincipal = "live-mcp-agent"

type liveEnv struct {
	hub, adminTok, bin, email, password string
}

func requireLive(t *testing.T) liveEnv {
	t.Helper()
	if os.Getenv("KK_LIVE_MCP") != "1" {
		t.Skip("set KK_LIVE_MCP=1 (via tests/live/mcp/run.sh) to run the live MCP E2E")
	}
	e := liveEnv{
		hub:      strings.TrimRight(os.Getenv("KK_MCP_HUB_BASE"), "/"),
		adminTok: os.Getenv("KK_MCP_ADMIN_TOKEN"),
		bin:      os.Getenv("KK_MCP_BIN"),
		email:    os.Getenv("KK_MCP_APPROVER_EMAIL"),
		password: os.Getenv("KK_MCP_APPROVER_PASSWORD"),
	}
	if e.hub == "" || e.adminTok == "" || e.bin == "" || e.email == "" || e.password == "" {
		t.Fatal("KK_MCP_HUB_BASE, KK_MCP_ADMIN_TOKEN, KK_MCP_BIN, KK_MCP_APPROVER_EMAIL and KK_MCP_APPROVER_PASSWORD must be set")
	}
	return e
}

// ---- hub REST helpers ----

func (e liveEnv) do(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.hub+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// dataField decodes {"data": {...}} and returns one string field of data.
func dataField(raw []byte, field string) string {
	var env struct {
		Data map[string]any `json:"data"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return ""
	}
	s, _ := env.Data[field].(string)
	return s
}

func (e liveEnv) mustDo(t *testing.T, want int, method, path, token string, body any) []byte {
	t.Helper()
	code, out := e.do(t, method, path, token, body)
	if code != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, code, want, out)
	}
	return out
}

var (
	loginMu  sync.Mutex
	loginTok string
)

// login signs the human approver in once per process: the hub rate-limits
// /auth/login, and one access token serves every approval.
func (e liveEnv) login(t *testing.T) string {
	t.Helper()
	loginMu.Lock()
	defer loginMu.Unlock()
	if loginTok != "" {
		return loginTok
	}
	out := e.mustDo(t, http.StatusOK, http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"email": e.email, "password": e.password})
	tok := dataField(out, "access_token")
	if tok == "" {
		t.Fatalf("login returned no access_token: %s", out)
	}
	loginTok = tok
	return tok
}

func (e liveEnv) mintKey(t *testing.T, name, principal, role string) string {
	t.Helper()
	out := e.mustDo(t, http.StatusCreated, http.MethodPost, "/api/v1/api-keys", e.adminTok,
		map[string]any{"name": name, "principal_id": principal, "role": role})
	tok := dataField(out, "token")
	if tok == "" {
		t.Fatalf("mint %s key returned no token: %s", role, out)
	}
	return tok
}

func newCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// ---- seeded fixture (built once, shared by every test) ----

type targets struct {
	caID                        string
	revokeFP, renewFP, rotateFP string
	bulkCA                      string
	bulkFPs                     []string
}

type fixture struct {
	agentTok    string // mcp-agent API key
	approverKey string // pki-admin API key minted with the bootstrap token
	tpl         string
	byTransport map[string]*targets
}

var (
	fix    *fixture
	fixErr string

	proposalsMu sync.Mutex
	proposals   = map[string]string{} // pending-action id -> rationale sent
)

func getFixture(t *testing.T, e liveEnv) *fixture {
	t.Helper()
	if fix != nil {
		return fix
	}
	if fixErr != "" {
		t.Fatal(fixErr)
	}
	f, err := buildFixture(t, e)
	if err != nil {
		fixErr = err.Error()
		t.Fatal(err)
	}
	fix = f
	return f
}

func buildFixture(t *testing.T, e liveEnv) (f *fixture, err error) {
	t.Helper()
	f = &fixture{byTransport: map[string]*targets{}}
	// Minting an mcp-agent key and a pki-admin key with the bootstrap token.
	f.agentTok = e.mintKey(t, "live-mcp-agent", agentPrincipal, "mcp-agent")
	f.approverKey = e.mintKey(t, "live-approver-key", "live-approver-key", "pki-admin")

	f.tpl = dataField(e.mustDo(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", e.adminTok, map[string]any{
		"name": "live-mcp-leaf", "display_name": "Live MCP leaf", "validity_period": "P90D",
		"key_usage": []string{"digitalSignature", "keyEncipherment"}, "extended_key_usage": []string{"clientAuth"},
		"allowed_algorithms": []string{"ECDSA", "RSA"}, "active": true,
	}), "id")
	if f.tpl == "" {
		return nil, fmt.Errorf("template create returned no id")
	}

	alg := firstSupportedAlgorithm(t, e)
	newCA := func(name string) string {
		out := e.mustDo(t, http.StatusCreated, http.MethodPost, "/api/v1/cas", e.adminTok, map[string]any{
			"name": name, "type": "root", "algorithm": alg, "subject_cn": name,
		})
		id := dataField(out, "id")
		if id == "" {
			t.Fatalf("CA %s: no id in %s", name, out)
		}
		return id
	}
	issue := func(caID, cn string) string {
		out := e.mustDo(t, http.StatusCreated, http.MethodPost, "/api/v1/certificates", e.adminTok, map[string]any{
			"ca_id": caID, "template_id": f.tpl, "csr_pem": newCSR(t, cn),
		})
		fp := dataField(out, "fingerprint_sha256")
		if fp == "" {
			t.Fatalf("issue %s: no fingerprint in %s", cn, out)
		}
		return fp
	}
	for _, tr := range []string{"stdio", "http"} {
		tg := &targets{caID: newCA("live-mcp-" + tr + "-ca"), bulkCA: newCA("live-mcp-" + tr + "-bulk-ca")}
		tg.revokeFP = issue(tg.caID, tr+"-revoke.live.test")
		tg.renewFP = issue(tg.caID, tr+"-renew.live.test")
		tg.rotateFP = issue(tg.caID, tr+"-rotate.live.test")
		tg.bulkFPs = []string{issue(tg.bulkCA, tr+"-bulk1.live.test"), issue(tg.bulkCA, tr+"-bulk2.live.test")}
		f.byTransport[tr] = tg
	}
	return f, nil
}

func firstSupportedAlgorithm(t *testing.T, e liveEnv) string {
	t.Helper()
	// An unsupported algorithm is answered 400 with the supported list.
	_, out := e.do(t, http.MethodPost, "/api/v1/cas", e.adminTok, map[string]any{
		"name": "alg-probe", "type": "root", "algorithm": "DSA", "subject_cn": "alg-probe",
	})
	var resp struct {
		Supported []string `json:"supported_algorithms"`
	}
	if json.Unmarshal(out, &resp) != nil || len(resp.Supported) == 0 {
		t.Fatalf("cannot discover supported CA algorithms from: %s", out)
	}
	for _, a := range resp.Supported {
		if strings.HasPrefix(a, "ECDSA") {
			return a
		}
	}
	return resp.Supported[0]
}

// ---- cert / queue observation ----

type certView struct {
	exists  bool
	revoked bool
}

func (e liveEnv) cert(t *testing.T, fp string) certView {
	t.Helper()
	code, out := e.do(t, http.MethodGet, "/api/v1/certificates/"+url.PathEscape(fp), e.adminTok, nil)
	if code == http.StatusNotFound {
		return certView{}
	}
	if code != http.StatusOK {
		t.Fatalf("GET certificate %s: %d %s", fp, code, out)
	}
	var env struct {
		Data struct {
			RevokedAt *string `json:"revoked_at"`
		} `json:"data"`
	}
	_ = json.Unmarshal(out, &env)
	return certView{exists: true, revoked: env.Data.RevokedAt != nil && *env.Data.RevokedAt != ""}
}

// snapshot counts the certificates (and revoked ones) the hub holds for the
// given CAs; equal before/after a proposal proves nothing was mutated.
func (e liveEnv) snapshot(t *testing.T, caIDs ...string) (total, revoked int) {
	t.Helper()
	for _, id := range caIDs {
		out := e.mustDo(t, http.StatusOK, http.MethodGet, "/api/v1/certificates?limit=500&ca_id="+url.QueryEscape(id), e.adminTok, nil)
		var env struct {
			Data []struct {
				RevokedAt *string `json:"revoked_at"`
			} `json:"data"`
		}
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatalf("decode certificate list: %v: %s", err, out)
		}
		for _, c := range env.Data {
			total++
			if c.RevokedAt != nil && *c.RevokedAt != "" {
				revoked++
			}
		}
	}
	return total, revoked
}

type pendingAction struct {
	ID         string          `json:"id"`
	ActionType string          `json:"action_type"`
	Params     json.RawMessage `json:"params"`
	ProposedBy string          `json:"proposed_by"`
	Rationale  string          `json:"rationale"`
	Status     string          `json:"status"`
	ApprovedBy string          `json:"approved_by"`
	Result     json.RawMessage `json:"result"`
}

func (e liveEnv) action(t *testing.T, id string) pendingAction {
	t.Helper()
	out := e.mustDo(t, http.StatusOK, http.MethodGet, "/api/v1/pending-actions", e.adminTok, nil)
	var env struct {
		Data []pendingAction `json:"data"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("decode pending actions: %v: %s", err, out)
	}
	for _, a := range env.Data {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("pending action %s not found in queue", id)
	return pendingAction{}
}

// ---- MCP client plumbing ----

func baseEnv(e liveEnv, token string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"KRYPTKEEPER_HUB_URL=" + e.hub,
		"KRYPTKEEPER_MCP_TOKEN=" + token,
	}
}

func initialize(t *testing.T, c *client.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.Initialize(ctx, mcp.InitializeRequest{Params: mcp.InitializeParams{
		ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		ClientInfo:      mcp.Implementation{Name: "kk-live", Version: "0"},
	}})
	if err != nil {
		t.Fatalf("MCP initialize: %v", err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// connect returns a real MCP client for the transport, authenticated to the
// hub as the mcp-agent key.
func connect(t *testing.T, e liveEnv, transportName, agentTok string) *client.Client {
	t.Helper()
	switch transportName {
	case "stdio":
		c, err := client.NewStdioMCPClient(e.bin, baseEnv(e, agentTok))
		if err != nil {
			t.Fatalf("start stdio MCP server: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		initialize(t, c)
		return c
	case "http":
		port := freePort(t)
		httpTok := strings.Repeat("h", 8) + fmt.Sprintf("-live-%d-", time.Now().UnixNano()) + strings.Repeat("t", 16)
		cmd := exec.Command(e.bin)
		cmd.Env = append(baseEnv(e, agentTok),
			"KRYPTKEEPER_MCP_TRANSPORT=http",
			fmt.Sprintf("KRYPTKEEPER_MCP_HTTP_ADDR=127.0.0.1:%d", port),
			"KRYPTKEEPER_MCP_HTTP_TOKEN="+httpTok)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start http MCP server: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		healthz := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
		deadline := time.Now().Add(20 * time.Second)
		for {
			resp, err := http.Get(healthz) //nolint:gosec,noctx // loopback readiness probe in a live test
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("http MCP server never became healthy; stderr: %s", stderr.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
		c, err := client.NewStreamableHttpClient(fmt.Sprintf("http://127.0.0.1:%d/mcp", port),
			transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + httpTok}))
		if err != nil {
			t.Fatalf("http MCP client: %v", err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatalf("http MCP client start: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		initialize(t, c)
		return c
	}
	t.Fatalf("unknown transport %q", transportName)
	return nil
}

// callTool invokes a tool and returns the hub JSON inside the untrusted
// envelope (preamble + fenced json block).
func callTool(t *testing.T, c *client.Client, name string, args map[string]any) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: args}})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	var sb strings.Builder
	for _, content := range res.Content {
		sb.WriteString(mcp.GetTextFromContent(content))
	}
	text := sb.String()
	if res.IsError {
		t.Fatalf("tool %s returned an error: %s", name, text)
	}
	const fence = "```json\n"
	i := strings.Index(text, fence)
	if i < 0 {
		t.Fatalf("tool %s output lacks the untrusted-data envelope: %s", name, text)
	}
	return []byte(strings.TrimSuffix(strings.TrimSpace(text[i+len(fence):]), "```"))
}

// ---- tests ----

func TestMCPLive(t *testing.T) {
	e := requireLive(t)
	f := getFixture(t, e)
	for _, tr := range []string{"stdio", "http"} {
		tr := tr
		t.Run(tr, func(t *testing.T) {
			c := connect(t, e, tr, f.agentTok)
			tg := f.byTransport[tr]

			t.Run("ToolsHaveNoApproveOrExecute", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				list, err := c.ListTools(ctx, mcp.ListToolsRequest{})
				if err != nil {
					t.Fatalf("ListTools: %v", err)
				}
				seen := map[string]bool{}
				for _, tl := range list.Tools {
					seen[tl.Name] = true
					if n := strings.ToLower(tl.Name); strings.Contains(n, "approve") || strings.Contains(n, "execute") {
						t.Errorf("MCP server exposes %q: it must never approve or execute", tl.Name)
					}
				}
				for _, want := range []string{"propose_revoke", "propose_bulk_revoke", "propose_issue", "propose_renew", "propose_rotate", "blast_radius"} {
					if !seen[want] {
						t.Errorf("tool %s missing from the live tool list", want)
					}
				}
			})

			t.Run("BlastRadiusRead", func(t *testing.T) {
				out := callTool(t, c, "blast_radius", map[string]any{"action": "revoke", "target": tg.revokeFP})
				if !strings.Contains(string(out), "total_affected") {
					t.Fatalf("blast_radius result lacks total_affected: %s", out)
				}
			})

			cases := []struct {
				tool   string
				args   func() map[string]any
				cas    []string // CAs whose certificate counts must not move on propose
				effect func(t *testing.T, a pendingAction)
			}{
				{"propose_revoke", func() map[string]any {
					return map[string]any{"fingerprint": tg.revokeFP, "reason_code": 1}
				}, []string{tg.caID}, func(t *testing.T, a pendingAction) {
					if !e.cert(t, tg.revokeFP).revoked {
						t.Errorf("approved revoke did not revoke %s", tg.revokeFP)
					}
					if !strings.Contains(string(a.Params), `"impact"`) {
						t.Errorf("revoke proposal lacks the blast-radius impact: %s", a.Params)
					}
				}},
				{"propose_bulk_revoke", func() map[string]any {
					return map[string]any{"ca_id": tg.bulkCA, "reason_code": 1}
				}, []string{tg.bulkCA}, func(t *testing.T, a pendingAction) {
					for _, fp := range tg.bulkFPs {
						if !e.cert(t, fp).revoked {
							t.Errorf("approved bulk revoke left %s active", fp)
						}
					}
					if !strings.Contains(string(a.Params), `"impact"`) {
						t.Errorf("bulk revoke proposal lacks the blast-radius impact: %s", a.Params)
					}
				}},
				{"propose_issue", func() map[string]any {
					return map[string]any{"ca_id": tg.caID, "template_id": f.tpl, "csr_pem": newCSR(t, tr+"-issued.live.test")}
				}, []string{tg.caID}, func(t *testing.T, a pendingAction) {
					fp := resultField(a.Result, "issued")
					if fp == "" || !e.cert(t, fp).exists {
						t.Errorf("approved issue produced no certificate (result %s)", a.Result)
					}
				}},
				{"propose_renew", func() map[string]any {
					return map[string]any{"fingerprint": tg.renewFP, "csr_pem": newCSR(t, tr+"-renew.live.test")}
				}, []string{tg.caID}, func(t *testing.T, a pendingAction) {
					fp := resultField(a.Result, "successor")
					if fp == "" || !e.cert(t, fp).exists {
						t.Errorf("approved renew produced no successor (result %s)", a.Result)
					}
				}},
				{"propose_rotate", func() map[string]any {
					return map[string]any{"fingerprint": tg.rotateFP, "csr_pem": newCSR(t, tr+"-rotate.live.test")}
				}, []string{tg.caID}, func(t *testing.T, a pendingAction) {
					fp := resultField(a.Result, "successor")
					if fp == "" || !e.cert(t, fp).exists {
						t.Errorf("approved rotate produced no successor (result %s)", a.Result)
					}
				}},
			}
			for _, tc := range cases {
				tc := tc
				t.Run(tc.tool+"/ProposeApproveExecute", func(t *testing.T) {
					rationale := "live-" + tr + "-" + tc.tool
					args := tc.args()
					args["rationale"] = rationale
					totalBefore, revokedBefore := e.snapshot(t, tc.cas...)

					out := callTool(t, c, tc.tool, args)
					id := dataField(out, "id")
					if id == "" || dataField(out, "status") != "pending" {
						t.Fatalf("proposal not pending: %s", out)
					}
					proposalsMu.Lock()
					proposals[id] = rationale
					proposalsMu.Unlock()

					// 0 direct mutations: proposing changed nothing on the hub.
					totalAfter, revokedAfter := e.snapshot(t, tc.cas...)
					if totalAfter != totalBefore || revokedAfter != revokedBefore {
						t.Fatalf("propose mutated the hub: certs %d->%d, revoked %d->%d", totalBefore, totalAfter, revokedBefore, revokedAfter)
					}
					if st := e.action(t, id).Status; st != "pending" {
						t.Fatalf("proposal status %q before approval, want pending", st)
					}

					// The human approves (named administrator session).
					code, body := e.do(t, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", e.login(t), nil)
					if code != http.StatusOK {
						t.Fatalf("human approve: %d %s (quorum or approver refusal?)", code, body)
					}
					a := e.action(t, id)
					if a.Status != "approved" || len(a.Result) == 0 {
						t.Fatalf("action not executed: status=%q result=%s", a.Status, a.Result)
					}
					tc.effect(t, a)
				})
			}
		})
	}
}

func resultField(raw json.RawMessage, field string) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	s, _ := m[field].(string)
	return s
}

func TestMCPLiveMCPAgentCannotApprove(t *testing.T) {
	e := requireLive(t)
	f := getFixture(t, e)

	// A pending proposal made by the mcp-agent identity itself.
	tg := f.byTransport["stdio"]
	spare := e.mustDo(t, http.StatusCreated, http.MethodPost, "/api/v1/pending-actions", f.agentTok, map[string]any{
		"action_type": "revoke",
		"params":      map[string]any{"fingerprint": tg.rotateFP, "reason_code": 0},
		"rationale":   "live-mcp-agent-cannot-approve",
	})
	id := dataField(spare, "id")
	if id == "" {
		t.Fatalf("no proposal id: %s", spare)
	}
	for _, verb := range []string{"approve", "reject"} {
		code, body := e.do(t, http.MethodPost, "/api/v1/pending-actions/"+id+"/"+verb, f.agentTok, map[string]any{})
		if code != http.StatusForbidden {
			t.Errorf("mcp-agent %s: status %d, want 403: %s", verb, code, body)
		}
	}
	if st := e.action(t, id).Status; st != "pending" {
		t.Errorf("proposal moved to %q after the mcp-agent's attempts, want pending", st)
	}
	// The bootstrap-minted pki-admin key is also a setup credential.
	if code, body := e.do(t, http.MethodPost, "/api/v1/pending-actions/"+id+"/approve", f.approverKey, nil); code != http.StatusForbidden {
		t.Errorf("a key minted with the bootstrap token approved (status %d): %s", code, body)
	}
	// Clean up: a human rejects the spare so it never lingers.
	if code, body := e.do(t, http.MethodPost, "/api/v1/pending-actions/"+id+"/reject", e.login(t), map[string]any{}); code != http.StatusOK {
		t.Errorf("human reject of the spare proposal: %d %s", code, body)
	}
}

func TestMCPLiveBootRefusedWithApproverToken(t *testing.T) {
	e := requireLive(t)
	f := getFixture(t, e)
	for name, tok := range map[string]string{"pki-admin key": f.approverKey, "bootstrap token": e.adminTok} {
		name, tok := name, tok
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, e.bin)
			cmd.Env = baseEnv(e, tok)
			cmd.Stdin = strings.NewReader("")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("server did not exit within 15s with an approver-capable token; stderr: %s", stderr.String())
			}
			var ee *exec.ExitError
			if err == nil || !errorsAs(err, &ee) || ee.ExitCode() == 0 {
				t.Fatalf("server must exit non-zero, got err=%v", err)
			}
			if !strings.Contains(stderr.String(), "refusing to start") {
				t.Fatalf("stderr lacks 'refusing to start': %s", stderr.String())
			}
		})
	}
}

func errorsAs(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

func TestMCPLiveAuditShowsRationaleAndAgent(t *testing.T) {
	e := requireLive(t)
	proposalsMu.Lock()
	snap := map[string]string{}
	for k, v := range proposals {
		snap[k] = v
	}
	proposalsMu.Unlock()
	if len(snap) == 0 {
		t.Fatal("no proposals were recorded; TestMCPLive must run first in the same process")
	}
	for id, rationale := range snap {
		// The audit row carries the agent identity and the resource; the
		// rationale lives on the pending-action row (the audit event does not
		// embed it; follow-up filed in the W29-08 report).
		out := e.mustDo(t, http.StatusOK, http.MethodGet,
			"/api/v1/audit?action=action.propose&resource_id="+url.QueryEscape(id)+"&limit=50", e.adminTok, nil)
		var env struct {
			Data []struct {
				Action     string `json:"action"`
				ActorID    string `json:"actor_id"`
				ResourceID string `json:"resource_id"`
				Outcome    string `json:"outcome"`
			} `json:"data"`
		}
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatalf("decode audit: %v: %s", err, out)
		}
		found := false
		for _, a := range env.Data {
			if a.Action == "action.propose" && a.ResourceID == id && a.Outcome == "success" && strings.Contains(a.ActorID, agentPrincipal) {
				found = true
			}
		}
		if !found {
			t.Errorf("proposal %s: no action.propose/success audit row attributed to %s: %s", id, agentPrincipal, out)
		}
		a := e.action(t, id)
		if a.ProposedBy != agentPrincipal || a.Rationale != rationale {
			t.Errorf("proposal %s: proposed_by=%q rationale=%q, want %q / %q", id, a.ProposedBy, a.Rationale, agentPrincipal, rationale)
		}
	}
}
