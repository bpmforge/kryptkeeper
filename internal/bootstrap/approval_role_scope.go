// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"strings"

	"kryptkeeper/internal/logging"
)

// approvalRoleScope answers "may this role decide certificate approvals filed
// against template X" from the template's approval_roles, caching per request
// so a long list does one lookup per template. It scopes what a non-admin sees
// in the approval list and inbox to what the decide handlers (handleApprove,
// handleReject) will actually let them do; those handlers remain the authority
// (proposer != approver, tenant, role capability). A template that cannot be
// read grants nothing: fail closed.
type approvalRoleScope struct {
	templates TemplateProvider
	cache     map[string][]string
}

func newApprovalRoleScope(tp TemplateProvider) *approvalRoleScope {
	return &approvalRoleScope{templates: tp, cache: map[string][]string{}}
}

func (s *approvalRoleScope) mayDecide(ctx context.Context, role, templateID string) bool {
	if isAdminRole(role) {
		return true
	}
	if s == nil || s.templates == nil || strings.TrimSpace(role) == "" || role == RoleMCPAgent {
		return false
	}
	roles, ok := s.cache[templateID]
	if !ok {
		tpl, found, err := s.templates.GetTemplate(ctx, templateID)
		if err == nil && found {
			roles = tpl.ApprovalRoles
		} else if err != nil {
			// Fail closed (no roles), but say why approvals are hidden.
			logging.Warnf("approval role scope: template %q unavailable, hiding its approvals from approvers: %v", templateID, err)
		}
		s.cache[templateID] = roles
	}
	return isApproverForTemplate(role, roles)
}

// visibleTo keeps the requests pd raised plus those pd's role may decide.
func (s *approvalRoleScope) visibleTo(ctx context.Context, pd AuthPrincipal, items []ApprovalRequest) []ApprovalRequest {
	if isAdminRole(pd.Role) {
		return items
	}
	out := make([]ApprovalRequest, 0, len(items))
	for _, it := range items {
		if it.Requester == pd.ID || s.mayDecide(ctx, pd.Role, it.TemplateID) {
			out = append(out, it)
		}
	}
	return out
}
