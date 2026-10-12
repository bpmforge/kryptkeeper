// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "strings"

func canReadOperationalSummaries(principal AuthPrincipal) bool {
	role := strings.TrimSpace(principal.Role)
	switch role {
	case "pki-admin", "pki-operator", "pki-auditor", "discovery-operator", "service-account":
		return true
	}
	return hasScope(principal.Scopes, "*") || hasScope(principal.Scopes, "ops:read")
}

func hasScope(scopes []string, expected string) bool {
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == expected {
			return true
		}
	}
	return false
}

func canManageDiscovery(principal AuthPrincipal) bool {
	role := strings.TrimSpace(principal.Role)
	switch role {
	case "pki-admin", "discovery-operator":
		return true
	}
	return hasScope(principal.Scopes, "*") || hasScope(principal.Scopes, "ops:write") || hasScope(principal.Scopes, "discovery:write")
}

func canManageNotifications(principal AuthPrincipal) bool {
	role := strings.TrimSpace(principal.Role)
	switch role {
	case "pki-admin", "pki-operator", "notification-operator":
		return true
	}
	return hasScope(principal.Scopes, "*") || hasScope(principal.Scopes, "ops:write") || hasScope(principal.Scopes, "notifications:write")
}

func canManageDashboardActions(principal AuthPrincipal) bool {
	role := strings.TrimSpace(principal.Role)
	switch role {
	case "pki-admin", "pki-operator", "discovery-operator", "notification-operator":
		return true
	}
	return hasScope(principal.Scopes, "*") || hasScope(principal.Scopes, "ops:write") || hasScope(principal.Scopes, "dashboard:write")
}

func canManageProtocols(principal AuthPrincipal) bool {
	role := strings.TrimSpace(principal.Role)
	switch role {
	case "pki-admin", "pki-operator", "protocol-operator":
		return true
	}
	return hasScope(principal.Scopes, "*") || hasScope(principal.Scopes, "ops:write") || hasScope(principal.Scopes, "protocol:write")
}
