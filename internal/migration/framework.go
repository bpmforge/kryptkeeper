// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package migration is the source-agnostic framework for importing another
// PKI's certificate templates (ADCS, Vault, Venafi, Keyfactor, CertCentral).
// An Importer parses and maps a source export; the Service diffs it against
// what Kryptkeeper already holds and, on apply, creates the missing templates
// under a batch id so the whole import can be reported and undone.
//
// It must not import internal/bootstrap (that package imports this one); the
// template store and approval lookups arrive through TemplateSink.
package migration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

// MaxInputBytes caps one export.
const MaxInputBytes = 1 << 20

var (
	ErrUnknownSource = errors.New("unknown migration source")
	ErrNoObjects     = errors.New("the export contains no objects")
	ErrInputTooLarge = errors.New("export exceeds the 1 MiB limit")
)

// Input is one import request. Objects, when set, replaces Parse (the live
// ADCS reader hands over already-decoded objects).
type Input struct {
	Source  string
	Content []byte
	Options map[string]string
	Objects []SourceObject
}

// SourceObject is one parsed item of a source export.
type SourceObject struct {
	Kind      string
	SourceKey string
	Name      string
	Raw       map[string]any // JSON-decoded source attributes
}

// FieldStatus says how faithfully a source field landed in Kryptkeeper.
type FieldStatus string

const (
	FieldMapped   FieldStatus = "mapped"
	FieldPartial  FieldStatus = "partial"
	FieldUnmapped FieldStatus = "unmapped"
)

// FieldReport is the per-field outcome shown in the report.
type FieldReport struct {
	Field  string      `json:"field"`
	Status FieldStatus `json:"status"`
	Target string      `json:"target,omitempty"`
	Note   string      `json:"note,omitempty"`
}

// Template mirrors bootstrap.TemplateUpsertRequest. Its JSON encoding is what
// content_hash is computed over, so field order here is part of the contract.
type Template struct {
	Name              string         `json:"name"`
	DisplayName       string         `json:"display_name"`
	OID               string         `json:"oid,omitempty"`
	KeyUsage          []string       `json:"key_usage"`
	ExtendedKeyUsage  []string       `json:"extended_key_usage"`
	AllowedAlgorithms []string       `json:"allowed_algorithms"`
	MinKeySize        int            `json:"min_key_size,omitempty"`
	ValidityPeriod    string         `json:"validity_period"`
	RenewalOverlap    string         `json:"renewal_overlap,omitempty"`
	AutoEnroll        bool           `json:"auto_enroll"`
	RequireApproval   bool           `json:"require_approval,omitempty"`
	ApprovalRoles     []string       `json:"approval_roles,omitempty"`
	EnrolleeType      string         `json:"enrollee_type,omitempty"`
	NamePolicy        *ca.NamePolicy `json:"name_policy,omitempty"`
	// EnrollRoles restricts who may enroll (the template's
	// enrollment_permissions.enroll); empty is unrestricted.
	EnrollRoles []string `json:"enroll_roles,omitempty"`
	// OwnerHint has no template home yet: carried on the batch item and
	// reported "partial".
	OwnerHint string `json:"owner_hint,omitempty"`
}

// Mapped is the result of mapping one source object.
type Mapped struct {
	Template Template
	Fields   []FieldReport
	// Unsupported, when non-empty, is the reason this object cannot become a
	// template. It is reported and never created.
	Unsupported string
	// Notes are deliberate changes the mapping made; they become the diff
	// entry's notes.
	Notes []string
}

// Importer is what one source (ADCS, Vault, Venafi, Keyfactor, CertCentral)
// implements. Map must be pure and deterministic: dry-run output is compared
// byte for byte across runs.
type Importer interface {
	Source() string
	Parse(ctx context.Context, in Input) ([]SourceObject, error)
	Map(obj SourceObject) (Mapped, error)
}

// ReadOptions configures a live read.
type ReadOptions struct {
	URL, BindDN, Secret, BaseDN string
	AllowCleartext              bool
}

// LiveReader is optionally implemented by an Importer that can read its
// objects from the running source (ADCS over LDAP) instead of an export.
type LiveReader interface {
	Read(ctx context.Context, o ReadOptions) ([]SourceObject, error)
}

// TemplateSink is the Kryptkeeper side: where templates are looked up,
// created and disabled. Disable must be idempotent. A sink that also
// implements TemplateUpdater lets a re-applied import update the templates it
// already made instead of reporting a conflict.
type TemplateSink interface {
	FindByName(ctx context.Context, name string) (id string, ok bool, err error)
	Create(ctx context.Context, t Template) (id string, err error)
	Disable(ctx context.Context, id string) error
	HasPendingApprovals(ctx context.Context, id string) (bool, error)
}

// TemplateState is what planning needs to know about an existing template.
type TemplateState struct {
	OID    string
	Active bool
}

// TemplateUpdater is optionally implemented by a TemplateSink (B2 of the ADCS
// cutover rehearsal). Update replaces a template's mapped fields in place,
// keeping its id, and leaves it active. Inspect reports a template's OID and
// whether it is active (ok is false when it no longer exists). Snapshot
// captures everything Update overwrites as an opaque string; Restore puts it
// back exactly, active flag included, so rolling back an update undoes it
// instead of disabling the template.
type TemplateUpdater interface {
	Update(ctx context.Context, id string, t Template) error
	Inspect(ctx context.Context, id string) (st TemplateState, ok bool, err error)
	Snapshot(ctx context.Context, id string) (string, error)
	Restore(ctx context.Context, id, snapshot string) error
}

// OriginStore is optionally implemented by a Store so planning can tell a
// template a migration made (it has a batch item, active or retired) from a
// hub-native one. A Store without it never proves origin, so a name match
// stays a conflict.
type OriginStore interface {
	FindItemByTemplate(ctx context.Context, templateID string) (BatchItem, bool, error)
}

// KeyFloor is the smallest RSA modulus the active issuance policies accept,
// and the policy that sets it. A zero RSABits means no floor.
type KeyFloor struct {
	RSABits int
	Policy  string
}

// Store persists batches. Rollback methods are in RollbackStore (rollback.go).
type Store interface {
	EnsureSchema(ctx context.Context) error
	// SaveBatch writes the batch and its items in one transaction. An item
	// with SupersedesBatchID set also retires the same source key's item in
	// that batch inside the transaction, so a failure leaves the old state.
	SaveBatch(ctx context.Context, b Batch, items []BatchItem) error
	FindActiveItem(ctx context.Context, source, sourceKey string) (BatchItem, bool, error)
	GetBatch(ctx context.Context, id string) (Batch, []BatchItem, bool, error)
	ListBatches(ctx context.Context, limit int) ([]Batch, error)
}

// Action is what apply would do with one source object.
type Action string

const (
	ActionCreate   Action = "create"
	ActionSkip     Action = "skip"
	ActionConflict Action = "conflict"
	// ActionUpdate replaces a template a migration made, and only one: a
	// hub-native template or one an admin disabled is a conflict instead.
	ActionUpdate Action = "update"
)

// DiffEntry is one source object's planned outcome.
type DiffEntry struct {
	SourceKey string `json:"source_key"`
	Name      string `json:"name"`
	Action    Action `json:"action"`
	Reason    string `json:"reason,omitempty"`
	// Notes are changes the import makes on purpose, such as a key size
	// raised to the issuance-policy floor.
	Notes  []string      `json:"notes,omitempty"`
	Fields []FieldReport `json:"fields"`
}

// Diff is the dry-run result. It carries no timestamps, ids or randomness, so
// two runs over the same input and state are byte-identical.
type Diff struct {
	Source      string         `json:"source"`
	Entries     []DiffEntry    `json:"entries"`
	Counts      map[Action]int `json:"counts"`
	Unmapped    int            `json:"unmapped"`
	Unsupported int            `json:"unsupported"`
}

// Batch is one applied import. ReportJSON is storage only and never leaves the
// API raw.
type Batch struct {
	ID           string `json:"id"`
	Source       string `json:"source"`
	Status       string `json:"status"` // applied | rolled_back
	CreatedBy    string `json:"created_by"`
	CreatedAt    string `json:"created_at"`
	RolledBackAt string `json:"rolled_back_at,omitempty"`
	RolledBackBy string `json:"-"`
	ReportJSON   string `json:"-"`
	// Items is the item count, filled by the store on reads.
	Items int `json:"items,omitempty"`
}

// BatchItem is one template a batch created.
type BatchItem struct {
	BatchID, SourceKey, TemplateID, Name, ContentHash, OwnerHint string
	CreatedAt, DisabledAt, KeepReason                            string
	// PriorJSON is the template's state before an update (TemplateUpdater
	// Snapshot); empty for a created template. Rollback restores it.
	PriorJSON string
	// SupersedesBatchID, set on a new item, names the batch whose item for
	// the same source key this one replaces; the store retires it atomically
	// with saving the batch. Stored, so rolling this batch back can
	// reactivate the retired item.
	SupersedesBatchID string
}

// ReportEntry is a DiffEntry plus the template it produced.
type ReportEntry struct {
	DiffEntry
	TemplateID string `json:"template_id"`
}

// Report is the outcome of Apply.
type Report struct {
	BatchID string        `json:"batch_id"`
	Created int           `json:"created"`
	Updated int           `json:"updated"`
	Entries []ReportEntry `json:"entries"`
}

// Service diffs and applies imports.
type Service struct {
	importers map[string]Importer
	sink      TemplateSink
	store     Store
	now       func() time.Time
	newID     func() string
	keyFloor  func(context.Context) (KeyFloor, error)
}

// NewService wires importers to a sink and store.
func NewService(sink TemplateSink, store Store, importers ...Importer) *Service {
	m := make(map[string]Importer, len(importers))
	for _, im := range importers {
		m[im.Source()] = im
	}
	return &Service{importers: m, sink: sink, store: store, now: time.Now, newID: newBatchID}
}

// WithKeyFloor makes every plan raise a mapped RSA template's min_key_size to
// the floor the active issuance policies enforce, so a migrated template
// cannot advertise (over XCEP) a key the CA will refuse. The raise is
// reported as a note on the entry. The policies themselves are never changed.
func (s *Service) WithKeyFloor(f func(context.Context) (KeyFloor, error)) *Service {
	s.keyFloor = f
	return s
}

func newBatchID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("migration: crypto/rand unavailable: " + err.Error())
	}
	return "mb_" + hex.EncodeToString(b[:])
}

// Sources lists the registered importers, sorted.
func (s *Service) Sources() []string {
	out := make([]string, 0, len(s.importers))
	for k := range s.importers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Importer returns the registered importer for source.
func (s *Service) Importer(source string) (Importer, bool) {
	im, ok := s.importers[source]
	return im, ok
}

// Store exposes the batch store (reports, listing).
func (s *Service) Store() Store { return s.store }

type planned struct {
	entry DiffEntry
	tmpl  Template
	hash  string
	// target is the template an ActionUpdate replaces; prev, when set, is
	// the batch item it supersedes.
	target string
	prev   *BatchItem
}

func (s *Service) plan(ctx context.Context, in Input) (Diff, []planned, error) {
	im, ok := s.importers[in.Source]
	if !ok {
		return Diff{}, nil, fmt.Errorf("%w: %q", ErrUnknownSource, in.Source)
	}
	if len(in.Content) > MaxInputBytes {
		return Diff{}, nil, ErrInputTooLarge
	}
	objs, err := sourceObjects(ctx, im, in)
	if err != nil {
		return Diff{}, nil, err
	}
	var floor KeyFloor
	if s.keyFloor != nil {
		if floor, err = s.keyFloor(ctx); err != nil {
			return Diff{}, nil, fmt.Errorf("read issuance policy floor: %w", err)
		}
	}
	items := make([]planned, 0, len(objs))
	for _, obj := range objs {
		items = append(items, mapObject(im, obj, floor))
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i].entry, items[j].entry
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.SourceKey < b.SourceKey
	})
	return s.diffOf(ctx, in.Source, items)
}

// sourceObjects is the export's objects: the ones the caller already decoded,
// or the importer's parse of the content.
func sourceObjects(ctx context.Context, im Importer, in Input) ([]SourceObject, error) {
	objs := in.Objects
	if objs == nil {
		var err error
		if objs, err = im.Parse(ctx, in); err != nil {
			return nil, fmt.Errorf("parse %s export: %w", in.Source, err)
		}
	}
	if len(objs) == 0 {
		return nil, ErrNoObjects
	}
	return objs, nil
}

// mapObject maps one source object into a planned entry: skipped when
// unsupported, otherwise hashed and ready to classify.
func mapObject(im Importer, obj SourceObject, floor KeyFloor) planned {
	m, err := im.Map(obj)
	if err != nil {
		m = Mapped{Unsupported: "map error: " + err.Error()}
	}
	name := m.Template.Name
	if name == "" {
		name = obj.Name
	}
	if m.Unsupported == "" {
		if missing := missingField(m.Template); missing != "" {
			m.Unsupported = "incomplete mapping: missing " + missing
		}
	}
	fields := append([]FieldReport{}, m.Fields...)
	sort.SliceStable(fields, func(i, j int) bool { return fields[i].Field < fields[j].Field })
	p := planned{entry: DiffEntry{SourceKey: obj.SourceKey, Name: name, Fields: fields}, tmpl: m.Template}
	if m.Unsupported != "" {
		p.entry.Action = ActionSkip
		p.entry.Reason = "unsupported: " + m.Unsupported
		return p
	}
	p.entry.Notes = append(p.entry.Notes, m.Notes...)
	if note := raiseToFloor(&p.tmpl, floor); note != "" {
		p.entry.Notes = append(p.entry.Notes, note)
	}
	raw, _ := json.Marshal(p.tmpl) // plain struct: cannot fail
	sum := sha256.Sum256(raw)
	p.hash = hex.EncodeToString(sum[:])
	return p
}

// diffOf classifies the sorted, mapped items and totals the diff.
func (s *Service) diffOf(ctx context.Context, source string, items []planned) (Diff, []planned, error) {
	diff := Diff{Source: source, Entries: make([]DiffEntry, 0, len(items)),
		Counts: map[Action]int{ActionCreate: 0, ActionSkip: 0, ActionConflict: 0, ActionUpdate: 0}}
	names := map[string]bool{}
	keys := map[string]bool{}
	for i := range items {
		p := &items[i]
		if p.hash != "" { // supported
			if err := s.classify(ctx, source, p, names, keys); err != nil {
				return Diff{}, nil, err
			}
		}
		diff.Counts[p.entry.Action]++
		if strings.HasPrefix(p.entry.Reason, "unsupported: ") {
			diff.Unsupported++
		}
		diff.Unmapped += countUnmapped(p.entry.Fields)
		diff.Entries = append(diff.Entries, p.entry)
	}
	return diff, items, nil
}

func countUnmapped(fields []FieldReport) int {
	n := 0
	for _, f := range fields {
		if f.Status == FieldUnmapped {
			n++
		}
	}
	return n
}

func (s *Service) classify(ctx context.Context, source string, p *planned, names, keys map[string]bool) error {
	e := &p.entry
	dupName, dupKey := names[e.Name], keys[e.SourceKey]
	names[e.Name], keys[e.SourceKey] = true, true
	switch {
	case dupName:
		e.Action, e.Reason = ActionConflict, "duplicate name in export"
		return nil
	case dupKey:
		e.Action, e.Reason = ActionConflict, "duplicate source key in export"
		return nil
	}
	it, found, err := s.store.FindActiveItem(ctx, source, e.SourceKey)
	if err != nil {
		return fmt.Errorf("look up %q: %w", e.SourceKey, err)
	}
	updater, canUpdate := s.sink.(TemplateUpdater)
	if found {
		return s.classifyImported(ctx, p, it, updater, canUpdate)
	}
	id, exists, err := s.sink.FindByName(ctx, e.Name)
	if err != nil {
		return fmt.Errorf("look up template %q: %w", e.Name, err)
	}
	if !exists {
		e.Action = ActionCreate
		return nil
	}
	return s.classifyNameMatch(ctx, p, id, updater, canUpdate)
}

// classifyImported handles a source key a migration already imported.
func (s *Service) classifyImported(ctx context.Context, p *planned, it BatchItem, updater TemplateUpdater, canUpdate bool) error {
	e := &p.entry
	if it.ContentHash == p.hash {
		e.Action, e.Reason = ActionSkip, "already imported in batch "+it.BatchID
		return nil
	}
	if !canUpdate {
		e.Action, e.Reason = ActionConflict, "source changed since batch "+it.BatchID
		return nil
	}
	st, ok, err := updater.Inspect(ctx, it.TemplateID)
	if err != nil {
		return fmt.Errorf("look up template %q: %w", e.Name, err)
	}
	switch {
	case !ok:
		e.Action, e.Reason = ActionConflict, "the template batch "+it.BatchID+" made no longer exists"
	case !st.Active:
		// A rollback retires the item, so an active item on an inactive
		// template means someone disabled it on purpose.
		e.Action, e.Reason = ActionConflict, "the template was disabled by an administrator after batch "+it.BatchID+"; re-enable it to import the change"
	default:
		e.Action, e.Reason = ActionUpdate, "source or policy floor changed since batch "+it.BatchID+"; the template is updated in place"
		p.target, p.prev = it.TemplateID, &it
	}
	return nil
}

// classifyNameMatch handles an existing template whose name the export uses
// but which no active batch item tracks. Only a template some migration made
// (e.g. one a rolled-back import left disabled) with the same OID is the same
// template and is updated; a hub-native template is never overwritten.
func (s *Service) classifyNameMatch(ctx context.Context, p *planned, id string, updater TemplateUpdater, canUpdate bool) error {
	e := &p.entry
	origins, hasOrigin := s.store.(OriginStore)
	if !canUpdate || !hasOrigin {
		e.Action, e.Reason = ActionConflict, "template name already exists"
		return nil
	}
	owner, made, err := origins.FindItemByTemplate(ctx, id)
	if err != nil {
		return fmt.Errorf("look up origin of template %q: %w", e.Name, err)
	}
	switch {
	case !made:
		e.Action, e.Reason = ActionConflict, "a template with this name already exists and was not created by a migration; rename or remove it to import this one"
		return nil
	case owner.DisabledAt == "":
		// Another source key's item still owns it: updating here would give
		// one template two active items and would bypass classifyImported's
		// admin-disabled check.
		e.Action, e.Reason = ActionConflict, "the template is tracked by batch "+owner.BatchID+" under another source key"
		return nil
	case p.tmpl.OID == "":
		// Only a (globally unique) OID proves the same template; a name alone
		// does not, and most sources carry no OID.
		e.Action, e.Reason = ActionConflict, "template name already exists"
		return nil
	}
	st, ok, err := updater.Inspect(ctx, id)
	if err != nil {
		return fmt.Errorf("look up template %q: %w", e.Name, err)
	}
	if !ok || st.OID != p.tmpl.OID {
		e.Action, e.Reason = ActionConflict, "template name already exists with a different OID"
		return nil
	}
	e.Action, e.Reason = ActionUpdate, "a template this migration framework made has this name and OID; it is updated in place and reactivated"
	p.target = id
	return nil
}

// raiseToFloor lifts an RSA template's min_key_size to the policy floor and
// returns the note that reports it, or "" when nothing changed.
func raiseToFloor(t *Template, floor KeyFloor) string {
	if floor.RSABits <= 0 || t.MinKeySize >= floor.RSABits {
		return ""
	}
	if !slices.ContainsFunc(t.AllowedAlgorithms, ca.IsRSAAlgorithm) {
		return ""
	}
	from := t.MinKeySize
	t.MinKeySize = floor.RSABits
	if from <= 0 { // the source named no key size
		return fmt.Sprintf("key size set to %d to meet policy %q", floor.RSABits, floor.Policy)
	}
	return fmt.Sprintf("key size raised from %d to %d to meet policy %q", from, floor.RSABits, floor.Policy)
}

func missingField(t Template) string {
	switch {
	case strings.TrimSpace(t.Name) == "":
		return "name"
	case strings.TrimSpace(t.DisplayName) == "":
		return "display_name"
	case strings.TrimSpace(t.ValidityPeriod) == "":
		return "validity_period"
	case len(t.KeyUsage) == 0:
		return "key_usage"
	case len(t.ExtendedKeyUsage) == 0:
		return "extended_key_usage"
	case len(t.AllowedAlgorithms) == 0:
		return "allowed_algorithms"
	}
	return ""
}

// DryRun classifies every object and writes nothing.
func (s *Service) DryRun(ctx context.Context, in Input) (Diff, error) {
	d, _, err := s.plan(ctx, in)
	return d, err
}

// Apply re-plans (state may have moved since a proposal) and carries out the
// "create" and "update" entries. Rerunning over the same input changes nothing
// and saves no batch. An updated template is recorded in the new batch with a
// snapshot of its prior state, so rolling that batch back restores it.
func (s *Service) Apply(ctx context.Context, in Input, actor string) (Report, error) {
	_, items, err := s.plan(ctx, in)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Entries: make([]ReportEntry, 0, len(items))}
	now := s.now().UTC().Format(time.RFC3339)
	var batchItems []BatchItem
	var createErr error
	batchID := s.newID()
	for _, p := range items {
		re := ReportEntry{DiffEntry: p.entry}
		if createErr == nil && (p.entry.Action == ActionCreate || p.entry.Action == ActionUpdate) {
			id, prior, err := s.write(ctx, p)
			if err != nil {
				createErr = fmt.Errorf("%s template %q: %w", p.entry.Action, p.entry.Name, err)
			} else {
				re.TemplateID = id
				if p.entry.Action == ActionCreate {
					rep.Created++
				} else {
					rep.Updated++
				}
				item := BatchItem{BatchID: batchID, SourceKey: p.entry.SourceKey,
					TemplateID: id, Name: p.entry.Name, ContentHash: p.hash, OwnerHint: p.tmpl.OwnerHint, CreatedAt: now, PriorJSON: prior}
				if p.prev != nil {
					item.SupersedesBatchID = p.prev.BatchID
				}
				batchItems = append(batchItems, item)
			}
		}
		rep.Entries = append(rep.Entries, re)
	}
	if rep.Created+rep.Updated == 0 {
		return rep, createErr
	}
	rep.BatchID = batchID
	raw, _ := json.Marshal(rep) // plain structs: cannot fail
	b := Batch{ID: batchID, Source: in.Source, Status: "applied", CreatedBy: actor, CreatedAt: now, ReportJSON: string(raw)}
	if err := s.store.SaveBatch(ctx, b, batchItems); err != nil {
		return rep, fmt.Errorf("record batch %s: %w", batchID, err)
	}
	return rep, createErr
}

// write carries out one planned create or update and returns the template id
// and, for an update, the snapshot taken before it.
func (s *Service) write(ctx context.Context, p planned) (id, prior string, err error) {
	if p.entry.Action == ActionCreate {
		id, err = s.sink.Create(ctx, p.tmpl)
		return id, "", err
	}
	u, ok := s.sink.(TemplateUpdater)
	if !ok {
		return "", "", errors.New("template sink cannot update")
	}
	if prior, err = u.Snapshot(ctx, p.target); err != nil {
		return "", "", fmt.Errorf("snapshot before update: %w", err)
	}
	return p.target, prior, u.Update(ctx, p.target, p.tmpl)
}

// Report decodes the stored report of a batch.
func (s *Service) Report(ctx context.Context, batchID string) (Batch, Report, bool, error) {
	b, _, ok, err := s.store.GetBatch(ctx, batchID)
	if err != nil || !ok {
		return Batch{}, Report{}, false, err
	}
	var rep Report
	if err := json.Unmarshal([]byte(b.ReportJSON), &rep); err != nil {
		return b, Report{}, true, fmt.Errorf("decode report: %w", err)
	}
	if rep.Entries == nil {
		rep.Entries = []ReportEntry{}
	}
	return b, rep, true, nil
}

// ---- shared helpers for importers ----

var ekuByOID = map[string]string{
	"1.3.6.1.5.5.7.3.1": "serverAuth",
	"1.3.6.1.5.5.7.3.2": "clientAuth",
	"1.3.6.1.5.5.7.3.3": "codeSigning",
	"1.3.6.1.5.5.7.3.4": "emailProtection",
	"1.3.6.1.5.5.7.3.8": "timeStamping",
	"1.3.6.1.5.5.7.3.9": "OCSPSigning",
}

// EKUFromOID names a known extended key usage OID.
func EKUFromOID(oid string) (string, bool) {
	n, ok := ekuByOID[strings.TrimSpace(oid)]
	return n, ok
}

// EKUFromName canonicalises "ServerAuth", "server_auth" and "serverAuth".
func EKUFromName(s string) (string, bool) {
	norm := strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(s))
	for _, n := range ekuByOID {
		if strings.ToLower(n) == norm {
			return n, true
		}
	}
	return "", false
}

// ValidityFromDuration renders d as "P<N>D", rounding up, minimum one day.
func ValidityFromDuration(d time.Duration) string {
	days := int64((d + 24*time.Hour - 1) / (24 * time.Hour))
	if days < 1 {
		days = 1
	}
	return fmt.Sprintf("P%dD", days)
}

// PercentMapped is (mapped+partial)*100/len, ignoring synthesized defaults
// (fields whose name starts with "("); 100 when nothing is left to count.
func PercentMapped(f []FieldReport) int {
	total, ok := 0, 0
	for _, r := range f {
		if strings.HasPrefix(r.Field, "(") {
			continue
		}
		total++
		if r.Status == FieldMapped || r.Status == FieldPartial {
			ok++
		}
	}
	if total == 0 {
		return 100
	}
	return ok * 100 / total
}
