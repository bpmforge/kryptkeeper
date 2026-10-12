// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/sshkeys"
)

const templateProviderEnv = "APP_TEMPLATE_PROVIDER"

const (
	templateProviderFile = "file"
)

var templateProviderWarnf = log.Printf

type TemplateItem struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	DisplayName       string   `json:"display_name"`
	OID               string   `json:"oid,omitempty"`
	KeyUsage          []string `json:"key_usage"`
	ExtendedKeyUsage  []string `json:"extended_key_usage"`
	AllowedAlgorithms []string `json:"allowed_algorithms"`
	MinKeySize        int      `json:"min_key_size,omitempty"`
	ValidityPeriod    string   `json:"validity_period"`
	RenewalOverlap    string   `json:"renewal_overlap,omitempty"`
	AutoEnroll        bool     `json:"auto_enroll"`
	Active            bool     `json:"active"`
	Revision          int      `json:"revision"`
	SchemaVersion     int      `json:"schema_version"`
	IssuedCount       int      `json:"issued_count"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`

	// EnrolleeType is "machine" or "user" (W20-17): who XCEP offers the
	// template to and WSTEP issues it to. Empty, in files written before
	// W20-17, means machine. Use Enrollee() to read it.
	EnrolleeType string `json:"enrollee_type,omitempty"`

	// MsPKIMinimalKeySize is a legacy input from hand-written template files:
	// nothing sets it, but a larger value still raises the policy minimum
	// (templateItemToPolicy), so dropping it could weaken a deployed policy.
	// The other msPKI-* and adcs_enabled fields were never read and are gone
	// (W20-17).
	MsPKIMinimalKeySize int `json:"ms_pki_minimal_key_size,omitempty"`

	// Short-lived: caps validity at 7 days; OCSP/CRL are not required (CA/B Forum).
	ShortLived bool `json:"short_lived,omitempty"`

	// Approval workflow: issuance creates a pending request instead of issuing immediately.
	RequireApproval bool     `json:"require_approval,omitempty"`
	ApprovalRoles   []string `json:"approval_roles,omitempty"` // roles allowed to approve; defaults to pki-admin

	// SSHPolicy (A01S-4 / FR-P70) makes the template usable for SSH
	// certificate issuance; a template without one cannot sign SSH certs.
	SSHPolicy *sshkeys.Policy `json:"ssh_policy,omitempty"`

	// NamePolicy (SUP-A04-3) restricts the names certificates under this
	// template may carry; absent = unrestricted.
	NamePolicy *ca.NamePolicy `json:"name_policy,omitempty"`
}

// Enrollee returns the template's enrollee type, machine unless it says user.
func (t TemplateItem) Enrollee() string {
	if t.EnrolleeType == templateEnrolleeUser {
		return templateEnrolleeUser
	}
	return templateEnrolleeMachine
}

const (
	templateEnrolleeMachine = "machine"
	templateEnrolleeUser    = "user"
)

type TemplateListQuery struct {
	Limit  int
	Offset int
	Q      string
	Active *bool
}

type TemplateListResult struct {
	Items []TemplateItem
	Total int
	Limit int
}

type TemplatePatchRequest struct {
	DisplayName *string `json:"display_name"`
	AutoEnroll  *bool   `json:"auto_enroll"`
	Active      *bool   `json:"active"`
	// AllowedAlgorithms is a policy knob, not identity — editable via PATCH
	// with a revision bump like the other mutable fields (W18-15).
	AllowedAlgorithms *[]string `json:"allowed_algorithms"`
}

type TemplateUpsertRequest struct {
	Name              string   `json:"name"`
	DisplayName       string   `json:"display_name"`
	OID               string   `json:"oid,omitempty"`
	KeyUsage          []string `json:"key_usage"`
	ExtendedKeyUsage  []string `json:"extended_key_usage"`
	AllowedAlgorithms []string `json:"allowed_algorithms"`
	MinKeySize        int      `json:"min_key_size,omitempty"`
	ValidityPeriod    string   `json:"validity_period"`
	RenewalOverlap    string   `json:"renewal_overlap,omitempty"`
	AutoEnroll        bool     `json:"auto_enroll"`
	Active            bool     `json:"active"`
	ShortLived        bool     `json:"short_lived,omitempty"`
	RequireApproval   bool     `json:"require_approval,omitempty"`
	ApprovalRoles     []string `json:"approval_roles,omitempty"`
	// EnrolleeType is "machine" (the default) or "user" (W20-17).
	EnrolleeType string `json:"enrollee_type,omitempty"`
	// SSHPolicy replaces the stored policy (absent clears it, like every PUT field).
	SSHPolicy *sshkeys.Policy `json:"ssh_policy,omitempty"`
	// NamePolicy replaces the stored name policy (absent clears it).
	NamePolicy *ca.NamePolicy `json:"name_policy,omitempty"`
}

type TemplateCloneRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

var (
	errTemplateNotFound       = errors.New("template not found")
	errTemplateConflict       = errors.New("template conflict")
	errTemplateImmutableField = errors.New("template immutable field")
	errTemplateInvalidPatch   = errors.New("template invalid patch")
	errTemplateInvalidCreate  = errors.New("template invalid create")
	errTemplatePrecondition   = errors.New("template precondition failed")
)

type TemplateProvider interface {
	ListTemplates(context.Context, TemplateListQuery) (TemplateListResult, error)
	GetTemplate(context.Context, string) (TemplateItem, bool, error)
	CreateTemplate(context.Context, TemplateUpsertRequest) (TemplateItem, error)
	ReplaceTemplate(context.Context, string, TemplateUpsertRequest, int) (TemplateItem, error)
	PatchTemplate(context.Context, string, TemplatePatchRequest) (TemplateItem, error)
	CloneTemplate(context.Context, string, TemplateCloneRequest) (TemplateItem, error)
	DeleteTemplate(context.Context, string) error
}

func NewTemplateProviderFromEnv() TemplateProvider {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(templateProviderEnv)))
	switch mode {
	case "", templateProviderFile:
		return NewFileTemplateProviderFromEnv()
	default:
		templateProviderWarnf("warning: unknown APP_TEMPLATE_PROVIDER=%q; falling back to file", mode)
		return NewFileTemplateProviderFromEnv()
	}
}

func parseTemplateLimit(raw string, defaultLimit int) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultLimit
	}
	limit, err := strconv.Atoi(trimmed)
	if err != nil || limit <= 0 {
		return defaultLimit
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func parseTemplateOffset(raw string) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}
	offset, err := strconv.Atoi(trimmed)
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}

func parseTemplateActive(raw string) *bool {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return nil
	}
	if trimmed == "true" {
		v := true
		return &v
	}
	if trimmed == "false" {
		v := false
		return &v
	}
	return nil
}
