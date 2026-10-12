// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
)

// proposeBody is the payload posted to the Hub's pending-actions queue.
type proposeBody struct {
	ActionType string          `json:"action_type"`
	Params     json.RawMessage `json:"params"`
	Rationale  string          `json:"rationale"`
}

// propose enqueues an action on the Hub and returns the created proposal. The
// MCP server NEVER mutates directly — it can only enqueue a proposal that a
// human approves in the dashboard. This is the structural guardrail.
func propose(ctx context.Context, hub *HubClient, actionType string, params any, rationale string) (*mcp.CallToolResult, error) {
	p, err := json.Marshal(params)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("bad params", err), nil
	}
	body, err := json.Marshal(proposeBody{ActionType: actionType, Params: p, Rationale: rationale})
	if err != nil {
		return mcp.NewToolResultErrorFromErr("bad request", err), nil
	}
	return jsonResult(hub.post(ctx, "/pending-actions", body))
}

// writeTools returns the proposal-only write tools. Each creates a pending
// action; none performs a mutation. A human approves in the dashboard.
func writeTools(hub *HubClient) []readTool {
	return []readTool{
		{
			mcp.NewTool("propose_revoke",
				mcp.WithDescription("Propose revoking a single certificate. Creates a pending action for human approval — it does NOT revoke directly. Returns the proposal (with id)."),
				mcp.WithString("fingerprint", mcp.Required(), mcp.Description("SHA-256 fingerprint to revoke")),
				mcp.WithString("rationale", mcp.Required(), mcp.Description("why this should be revoked (recorded for the approver and audit log)")),
				mcp.WithString("reason_text", mcp.Description("human-readable revocation reason")),
				mcp.WithNumber("reason_code", mcp.Description("RFC 5280 revocation reason code (default 0)")),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				fp, err := req.RequireString("fingerprint")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("fingerprint required", err), nil
				}
				rationale, err := req.RequireString("rationale")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("rationale required", err), nil
				}
				return propose(ctx, hub, "revoke", map[string]any{
					"fingerprint": fp,
					"reason_code": req.GetInt("reason_code", 0),
					"reason_text": req.GetString("reason_text", ""),
				}, rationale)
			},
		},
		{
			mcp.NewTool("propose_bulk_revoke",
				mcp.WithDescription("Propose revoking every certificate issued by a CA (e.g. a compromised CA). Creates a pending action for human approval — it does NOT revoke directly. Returns the proposal (with id)."),
				mcp.WithString("ca_id", mcp.Required(), mcp.Description("the CA whose certificates should be revoked")),
				mcp.WithString("rationale", mcp.Required(), mcp.Description("why (e.g. 'CA-7 private key suspected compromised')")),
				mcp.WithString("reason_text", mcp.Description("human-readable revocation reason")),
				mcp.WithNumber("reason_code", mcp.Description("RFC 5280 revocation reason code (default 0)")),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				caID, err := req.RequireString("ca_id")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("ca_id required", err), nil
				}
				rationale, err := req.RequireString("rationale")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("rationale required", err), nil
				}
				return propose(ctx, hub, "bulk_revoke", map[string]any{
					"ca_id":       caID,
					"reason_code": req.GetInt("reason_code", 0),
					"reason_text": req.GetString("reason_text", ""),
				}, rationale)
			},
		},
		{
			mcp.NewTool("propose_issue",
				mcp.WithDescription("Propose issuing a certificate from a CSR. Creates a pending action for human approval — it does NOT issue directly. Returns the proposal (with id)."),
				mcp.WithString("ca_id", mcp.Required(), mcp.Description("the issuing CA")),
				mcp.WithString("csr_pem", mcp.Required(), mcp.Description("PEM CSR carrying the subject's key — the hub never mints subject keys")),
				mcp.WithString("rationale", mcp.Required(), mcp.Description("why this certificate should exist (recorded for the approver)")),
				mcp.WithString("template_id", mcp.Description("issuance template")),
				mcp.WithString("team_id", mcp.Description("owning team")),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				caID, err := req.RequireString("ca_id")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("ca_id required", err), nil
				}
				csr, err := req.RequireString("csr_pem")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("csr_pem required", err), nil
				}
				rationale, err := req.RequireString("rationale")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("rationale required", err), nil
				}
				return propose(ctx, hub, "issue", map[string]any{
					"ca_id":       caID,
					"csr_pem":     csr,
					"template_id": req.GetString("template_id", ""),
					"team_id":     req.GetString("team_id", ""),
				}, rationale)
			},
		},
		{
			mcp.NewTool("propose_renew",
				mcp.WithDescription("Propose renewing a certificate (key reuse permitted). Creates a pending action for human approval — it does NOT renew directly. Returns the proposal (with id)."),
				mcp.WithString("fingerprint", mcp.Required(), mcp.Description("SHA-256 fingerprint of the certificate to renew")),
				mcp.WithString("csr_pem", mcp.Required(), mcp.Description("PEM CSR for the renewal")),
				mcp.WithString("rationale", mcp.Required(), mcp.Description("why (recorded for the approver)")),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				fp, err := req.RequireString("fingerprint")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("fingerprint required", err), nil
				}
				csr, err := req.RequireString("csr_pem")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("csr_pem required", err), nil
				}
				rationale, err := req.RequireString("rationale")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("rationale required", err), nil
				}
				return propose(ctx, hub, "renew", map[string]any{
					"fingerprint": fp, "csr_pem": csr,
				}, rationale)
			},
		},
		{
			mcp.NewTool("propose_rotate",
				mcp.WithDescription("Propose rotating a certificate to a NEW key (the executor refuses a CSR reusing the old key). Creates a pending action for human approval — it does NOT rotate directly. Returns the proposal (with id)."),
				mcp.WithString("fingerprint", mcp.Required(), mcp.Description("SHA-256 fingerprint of the certificate to rotate")),
				mcp.WithString("csr_pem", mcp.Required(), mcp.Description("PEM CSR carrying the NEW key")),
				mcp.WithString("rationale", mcp.Required(), mcp.Description("why (recorded for the approver)")),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				fp, err := req.RequireString("fingerprint")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("fingerprint required", err), nil
				}
				csr, err := req.RequireString("csr_pem")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("csr_pem required", err), nil
				}
				rationale, err := req.RequireString("rationale")
				if err != nil {
					return mcp.NewToolResultErrorFromErr("rationale required", err), nil
				}
				return propose(ctx, hub, "rotate", map[string]any{
					"fingerprint": fp, "csr_pem": csr,
				}, rationale)
			},
		},
		{
			mcp.NewTool("list_pending_actions",
				mcp.WithDescription("List proposed actions and their status (pending/approved/rejected/failed), so you can report what's awaiting approval. Returns JSON."),
				mcp.WithString("status", mcp.Description("filter by status (pending, approved, rejected, failed)")),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return jsonResult(hub.get(ctx, "/pending-actions", addQuery(req, "status")))
			},
		},
	}
}
