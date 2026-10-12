// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// RoleMCPAgent is the canonical role to assign an API key provisioned for
// MCP server integration (D-017: the MCP write surface is propose-only — an
// AI tool proposes an action, a human approves it). D-029/R-C1 closes the
// one soft spot in that design: today nothing stops an operator handing the
// MCP server a `pki-admin` token, at which point the only backstop against
// it approving its own or others' proposals is discipline, not code.
//
// canApproveActions (handlers_pending_actions.go) rejects RoleMCPAgent
// unconditionally, before its normal allowlist check — so a key correctly
// provisioned with this role can never approve a pending action, structurally,
// independent of whatever the allowlist grows to include later. This does
// not stop an operator from instead assigning the MCP integration's key a
// different, approver-capable role (e.g. `pki-admin`) by mistake — that
// residual is closed by D-029's OTHER adopted option, the boot-time check in
// cmd/kryptkeeper-mcp/main.go: it asks the hub for the token's own role and
// refuses to start if that role can approve pending actions (fail-closed when
// the hub is unreachable).
const RoleMCPAgent = "mcp-agent"
