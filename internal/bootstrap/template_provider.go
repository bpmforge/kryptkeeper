// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"kryptkeeper/internal/logging"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/sshkeys"
)

const templateProviderEnv = "APP_TEMPLATE_PROVIDER"

const (
	templateProviderFile = "file"
)

var templateProviderWarnf = logging.Warnf

// EnrollmentPermissions lists the roles that may enroll from a template
// (W23-42). A nil value or an empty Enroll list means unrestricted.
type EnrollmentPermissions struct {
	Enroll []string `json:"enroll"`
}

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

	// EnrollmentPermissions restricts which roles may issue from this
	// template (W23-42); absent = unrestricted.
	EnrollmentPermissions *EnrollmentPermissions `json:"enrollment_permissions,omitempty"`
}

// EnrollRoles returns the template's enroll list (nil = unrestricted).
func (t TemplateItem) EnrollRoles() []string {
	if t.EnrollmentPermissions == nil {
		return nil
	}
	return t.EnrollmentPermissions.Enroll
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
	// EnrollmentPermissions replaces the enroll list (W23-42); an empty list
	// clears the restriction.
	EnrollmentPermissions *EnrollmentPermissions `json:"enrollment_permissions"`
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
	// EnrollmentPermissions replaces the stored enroll list (absent clears it).
	EnrollmentPermissions *EnrollmentPermissions `json:"enrollment_permissions,omitempty"`
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

// TemplateFieldChange is one field that differs between two revisions.
type TemplateFieldChange struct {
	Field string `json:"field"`
	Old   any    `json:"old"`
	New   any    `json:"new"`
}

// TemplateRevision is one entry of a template's history (W23-44). Changes is
// the diff against the previous revision, empty for the first one on record.
type TemplateRevision struct {
	Revision  int                   `json:"revision"`
	ChangedAt string                `json:"changed_at"`
	Snapshot  TemplateItem          `json:"snapshot"`
	Changes   []TemplateFieldChange `json:"changes"`
}

// TemplateRevisionLister is an optional TemplateProvider capability, kept off
// TemplateProvider so the many test doubles of it stay valid. The bool is
// false when the template id is unknown.
type TemplateRevisionLister interface {
	ListTemplateRevisions(ctx context.Context, id string) ([]TemplateRevision, bool, error)
}

// diffIgnoredFields change on every save (or are counters), so listing them as
// edits would bury the real change.
var diffIgnoredFields = map[string]bool{
	"revision": true, "updated_at": true, "created_at": true, "issued_count": true, "schema_version": true,
}

// diffTemplates lists the fields that differ, sorted by field name so the
// output is deterministic.
func diffTemplates(oldItem, newItem TemplateItem) []TemplateFieldChange {
	oldMap, newMap := templateAsMap(oldItem), templateAsMap(newItem)
	keys := map[string]bool{}
	for k := range oldMap {
		keys[k] = true
	}
	for k := range newMap {
		keys[k] = true
	}
	fields := make([]string, 0, len(keys))
	for k := range keys {
		if !diffIgnoredFields[k] {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields)
	changes := []TemplateFieldChange{}
	for _, f := range fields {
		if !reflect.DeepEqual(oldMap[f], newMap[f]) {
			changes = append(changes, TemplateFieldChange{Field: f, Old: oldMap[f], New: newMap[f]})
		}
	}
	return changes
}

func templateAsMap(t TemplateItem) map[string]any {
	raw, err := json.Marshal(t)
	if err != nil {
		return map[string]any{}
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]any{}
	}
	return m
}

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
