// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

type fileTemplateProvider struct {
	filePath string
}

func NewFileTemplateProviderFromEnv() TemplateProvider {
	path := resolveStateFilePath(os.Getenv, "APP_TEMPLATE_FILE", "bootstrap-templates.json")
	initStateDir(path)
	return &fileTemplateProvider{filePath: path}
}

func (p *fileTemplateProvider) ListTemplates(_ context.Context, query TemplateListQuery) (TemplateListResult, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	items, ok := p.loadItems()
	if !ok {
		return TemplateListResult{Items: []TemplateItem{}, Total: 0, Limit: limit}, nil
	}

	q := strings.ToLower(strings.TrimSpace(query.Q))
	filtered := make([]TemplateItem, 0, len(items))
	for _, item := range items {
		if query.Active != nil && item.Active != *query.Active {
			continue
		}
		if q != "" {
			if !strings.Contains(strings.ToLower(item.Name), q) && !strings.Contains(strings.ToLower(item.OID), q) {
				continue
			}
		}
		filtered = append(filtered, item)
	}

	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return TemplateListResult{Items: filtered[offset:end], Total: total, Limit: limit}, nil
}

func (p *fileTemplateProvider) GetTemplate(_ context.Context, id string) (TemplateItem, bool, error) {
	items, ok := p.loadItems()
	if !ok {
		return TemplateItem{}, false, nil
	}
	for _, item := range items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return TemplateItem{}, false, nil
}

func (p *fileTemplateProvider) CreateTemplate(_ context.Context, req TemplateUpsertRequest) (TemplateItem, error) {
	if err := validateTemplateUpsertRequest(req); err != nil {
		return TemplateItem{}, err
	}
	enrollPerms, err := normalizeEnrollmentPermissions(req.EnrollmentPermissions)
	if err != nil {
		return TemplateItem{}, fmt.Errorf("%w: %v", errTemplateInvalidCreate, err)
	}

	items, ok := p.loadItems()
	if !ok {
		items = []TemplateItem{}
	}

	if hasTemplateConflict(items, "", req.Name, req.OID) {
		return TemplateItem{}, errTemplateConflict
	}

	now := time.Now().UTC().Format(time.RFC3339)
	item := TemplateItem{
		ID:                nextTemplateID(req.Name),
		Name:              strings.TrimSpace(req.Name),
		DisplayName:       strings.TrimSpace(req.DisplayName),
		OID:               strings.TrimSpace(req.OID),
		KeyUsage:          req.KeyUsage,
		ExtendedKeyUsage:  req.ExtendedKeyUsage,
		AllowedAlgorithms: req.AllowedAlgorithms,
		MinKeySize:        req.MinKeySize,
		ValidityPeriod:    strings.TrimSpace(req.ValidityPeriod),
		RenewalOverlap:    strings.TrimSpace(req.RenewalOverlap),
		AutoEnroll:        req.AutoEnroll,
		Active:            req.Active,
		// W-review: these two were silently dropped here — an admin could
		// configure require_approval and issuance would never gate on it.
		RequireApproval:       req.RequireApproval,
		ApprovalRoles:         req.ApprovalRoles,
		EnrolleeType:          normalizeEnrolleeType(req.EnrolleeType),
		SSHPolicy:             req.SSHPolicy,
		NamePolicy:            req.NamePolicy,
		EnrollmentPermissions: enrollPerms,
		DeviceAttestation:     req.DeviceAttestation,
		Revision:              1,
		SchemaVersion:         1,
		IssuedCount:           0,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	items = append(items, item)
	if err := p.saveItems(items); err != nil {
		return TemplateItem{}, err
	}
	p.startHistory(item)
	return item, nil
}

func (p *fileTemplateProvider) ReplaceTemplate(_ context.Context, id string, req TemplateUpsertRequest, expectedRevision int) (TemplateItem, error) {
	if err := validateTemplateUpsertRequest(req); err != nil {
		return TemplateItem{}, err
	}
	enrollPerms, err := normalizeEnrollmentPermissions(req.EnrollmentPermissions)
	if err != nil {
		return TemplateItem{}, fmt.Errorf("%w: %v", errTemplateInvalidCreate, err)
	}

	items, ok := p.loadItems()
	if !ok {
		return TemplateItem{}, errTemplateNotFound
	}

	for i := range items {
		if items[i].ID != id {
			continue
		}
		if expectedRevision > 0 && items[i].Revision != expectedRevision {
			return TemplateItem{}, errTemplatePrecondition
		}
		if hasTemplateConflict(items, id, req.Name, req.OID) {
			return TemplateItem{}, errTemplateConflict
		}

		before := items[i]
		now := time.Now().UTC().Format(time.RFC3339)
		items[i].Name = strings.TrimSpace(req.Name)
		items[i].DisplayName = strings.TrimSpace(req.DisplayName)
		items[i].OID = strings.TrimSpace(req.OID)
		items[i].KeyUsage = req.KeyUsage
		items[i].ExtendedKeyUsage = req.ExtendedKeyUsage
		items[i].AllowedAlgorithms = req.AllowedAlgorithms
		items[i].MinKeySize = req.MinKeySize
		items[i].ValidityPeriod = strings.TrimSpace(req.ValidityPeriod)
		items[i].RenewalOverlap = strings.TrimSpace(req.RenewalOverlap)
		items[i].AutoEnroll = req.AutoEnroll
		items[i].Active = req.Active
		items[i].RequireApproval = req.RequireApproval
		items[i].ApprovalRoles = req.ApprovalRoles
		items[i].EnrolleeType = normalizeEnrolleeType(req.EnrolleeType)
		items[i].SSHPolicy = req.SSHPolicy
		items[i].NamePolicy = req.NamePolicy
		items[i].EnrollmentPermissions = enrollPerms
		items[i].DeviceAttestation = req.DeviceAttestation
		items[i].Revision++
		items[i].UpdatedAt = now

		if err := p.saveItems(items); err != nil {
			return TemplateItem{}, err
		}
		p.appendHistory(before, items[i])
		return items[i], nil
	}

	return TemplateItem{}, errTemplateNotFound
}

func (p *fileTemplateProvider) CloneTemplate(_ context.Context, id string, req TemplateCloneRequest) (TemplateItem, error) {
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.DisplayName) == "" {
		return TemplateItem{}, errTemplateInvalidCreate
	}

	items, ok := p.loadItems()
	if !ok {
		return TemplateItem{}, errTemplateNotFound
	}

	idx := -1
	for i := range items {
		if items[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return TemplateItem{}, errTemplateNotFound
	}
	if hasTemplateConflict(items, "", req.Name, "") {
		return TemplateItem{}, errTemplateConflict
	}

	now := time.Now().UTC().Format(time.RFC3339)
	clone := items[idx]
	clone.ID = nextTemplateID(req.Name)
	clone.Name = strings.TrimSpace(req.Name)
	clone.DisplayName = strings.TrimSpace(req.DisplayName)
	clone.OID = ""
	clone.Active = false
	clone.AutoEnroll = false
	// Device attestation is an explicit grant per template; a clone starts without it.
	clone.DeviceAttestation = false
	clone.Revision = 1
	clone.IssuedCount = 0
	clone.CreatedAt = now
	clone.UpdatedAt = now

	items = append(items, clone)
	if err := p.saveItems(items); err != nil {
		return TemplateItem{}, err
	}
	// The clone is a new template: its history restarts at revision 1.
	p.startHistory(clone)
	return clone, nil
}

func (p *fileTemplateProvider) PatchTemplate(_ context.Context, id string, req TemplatePatchRequest) (TemplateItem, error) {
	var patchPerms *EnrollmentPermissions
	if req.EnrollmentPermissions != nil {
		var err error
		if patchPerms, err = normalizeEnrollmentPermissions(req.EnrollmentPermissions); err != nil {
			return TemplateItem{}, fmt.Errorf("%w: %v", errTemplateInvalidPatch, err)
		}
	}
	items, ok := p.loadItems()
	if !ok {
		return TemplateItem{}, errTemplateNotFound
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range items {
		if items[i].ID != id {
			continue
		}

		before := items[i]
		if req.DisplayName != nil {
			items[i].DisplayName = *req.DisplayName
		}
		if req.AutoEnroll != nil {
			items[i].AutoEnroll = *req.AutoEnroll
		}
		if req.Active != nil {
			items[i].Active = *req.Active
		}
		if req.AllowedAlgorithms != nil {
			items[i].AllowedAlgorithms = *req.AllowedAlgorithms
		}
		if req.EnrollmentPermissions != nil {
			items[i].EnrollmentPermissions = patchPerms
		}

		items[i].Revision++
		items[i].UpdatedAt = now
		if err := p.saveItems(items); err != nil {
			return TemplateItem{}, err
		}
		p.appendHistory(before, items[i])
		return items[i], nil
	}

	return TemplateItem{}, errTemplateNotFound
}

func (p *fileTemplateProvider) DeleteTemplate(_ context.Context, id string) error {
	items, ok := p.loadItems()
	if !ok {
		return errTemplateNotFound
	}

	idx := -1
	for i := range items {
		if items[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return errTemplateNotFound
	}
	if items[idx].IssuedCount > 0 {
		return errTemplateConflict
	}

	items = append(items[:idx], items[idx+1:]...)
	if err := p.saveItems(items); err != nil {
		return err
	}
	p.dropHistory(id)
	return nil
}

func (p *fileTemplateProvider) loadItems() ([]TemplateItem, bool) {
	body, err := os.ReadFile(p.filePath)
	if err != nil {
		logging.Infof("template file fallback: unreadable %q: %v", p.filePath, err)
		return nil, false
	}
	var items []TemplateItem
	if err := json.Unmarshal(body, &items); err != nil {
		logging.Infof("template file fallback: invalid JSON")
		return nil, false
	}
	return items, true
}

func (p *fileTemplateProvider) saveItems(items []TemplateItem) error {
	body, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return writeStateFile(p.filePath, body)
}

func nextTemplateID(name string) string {
	base := strings.ToLower(strings.TrimSpace(name))
	if base == "" {
		base = "template"
	}
	base = strings.ReplaceAll(base, " ", "-")
	return fmt.Sprintf("tpl-%s-%d", base, time.Now().UTC().UnixNano())
}

func hasTemplateConflict(items []TemplateItem, currentID, name, oid string) bool {
	name = strings.TrimSpace(name)
	oid = strings.TrimSpace(oid)
	for _, item := range items {
		if currentID != "" && item.ID == currentID {
			continue
		}
		if name != "" && strings.EqualFold(item.Name, name) {
			return true
		}
		if oid != "" && strings.EqualFold(strings.TrimSpace(item.OID), oid) {
			return true
		}
	}
	return false
}

func validateTemplateUpsertRequest(req TemplateUpsertRequest) error {
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.DisplayName) == "" || strings.TrimSpace(req.ValidityPeriod) == "" {
		return errTemplateInvalidCreate
	}
	if _, err := ParseValidityPeriod(req.ValidityPeriod); err != nil {
		return errTemplateInvalidCreate
	}
	if len(req.KeyUsage) == 0 || len(req.ExtendedKeyUsage) == 0 || len(req.AllowedAlgorithms) == 0 {
		return errTemplateInvalidCreate
	}
	switch strings.TrimSpace(req.EnrolleeType) {
	case "", templateEnrolleeMachine, templateEnrolleeUser:
	default:
		return errTemplateInvalidCreate
	}
	if req.SSHPolicy != nil {
		if err := req.SSHPolicy.Validate(); err != nil {
			return fmt.Errorf("%w: %v", errTemplateInvalidCreate, err)
		}
	}
	if err := req.NamePolicy.Validate(); err != nil {
		return fmt.Errorf("%w: %v", errTemplateInvalidCreate, err)
	}
	return nil
}

// normalizeEnrolleeType stores the default explicitly, so a template file
// says what every template is offered to.
func normalizeEnrolleeType(v string) string {
	if strings.TrimSpace(v) == templateEnrolleeUser {
		return templateEnrolleeUser
	}
	return templateEnrolleeMachine
}

var (
	enrollRolePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)
	maxEnrollRoles    = 32
)

// normalizeEnrollmentPermissions trims, lowercases and dedupes the role list
// and rejects malformed names. Roles are format-checked only: custom roles are
// created at runtime so the known-role set is not a stable reference. An empty
// list normalizes to nil (unrestricted) so the stored shape has one spelling.
func normalizeEnrollmentPermissions(in *EnrollmentPermissions) (*EnrollmentPermissions, error) {
	if in == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in.Enroll))
	for _, raw := range in.Enroll {
		role := strings.ToLower(strings.TrimSpace(raw))
		if role == "" || seen[role] {
			continue
		}
		if !enrollRolePattern.MatchString(role) {
			return nil, fmt.Errorf("enrollment_permissions: invalid role %q", raw)
		}
		seen[role] = true
		out = append(out, role)
	}
	if len(out) > maxEnrollRoles {
		return nil, fmt.Errorf("enrollment_permissions: at most %d roles", maxEnrollRoles)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &EnrollmentPermissions{Enroll: out}, nil
}
