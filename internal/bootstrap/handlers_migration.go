// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/migration"
)

// W24-38: import another PKI's templates. A dry run writes nothing; an apply
// is only proposed here and runs when a second person approves it in the
// pending-action queue, so one operator cannot bulk-create issuance policy.

// ActionMigrationApply is the pending-action type for an approved import.
const ActionMigrationApply = "migration.apply"

// maxMigrationApplyContent keeps a proposal inside the queue's 64 KiB cap
// (params are stored verbatim, base64 inflates by a third).
const maxMigrationApplyContent = 48 << 10

const migrationBodyLimit = 1 << 20

type migrationRequest struct {
	Source        string            `json:"source"`
	Content       string            `json:"content"`
	CredentialRef string            `json:"credential_ref"`
	Options       map[string]string `json:"options"`
}

// migrationApplyParams is what the queue stores. Only credential_ref is
// persisted, never the secret it resolves to.
type migrationApplyParams struct {
	Source        string            `json:"source"`
	ContentB64    string            `json:"content_b64"`
	Options       map[string]string `json:"options,omitempty"`
	CredentialRef string            `json:"credential_ref,omitempty"`
	DiffSHA256    string            `json:"diff_sha256"`
}

type migrationTenantKey struct{}

// templateSink adapts the template provider and approval store to the
// framework. It lives here because internal/migration cannot import bootstrap.
type templateSink struct {
	templates TemplateProvider
	approvals func() (ApprovalStore, error)
}

func (s templateSink) FindByName(ctx context.Context, name string) (string, bool, error) {
	for offset := 0; ; {
		res, err := s.templates.ListTemplates(ctx, TemplateListQuery{Q: name, Limit: 200, Offset: offset})
		if err != nil {
			return "", false, err
		}
		for _, it := range res.Items {
			if it.Name == name {
				return it.ID, true, nil
			}
		}
		offset += len(res.Items)
		if len(res.Items) == 0 || offset >= res.Total {
			return "", false, nil
		}
	}
}

func (s templateSink) Create(ctx context.Context, t migration.Template) (string, error) {
	created, err := s.templates.CreateTemplate(ctx, TemplateUpsertRequest{
		Name: t.Name, DisplayName: t.DisplayName, OID: t.OID,
		KeyUsage: t.KeyUsage, ExtendedKeyUsage: t.ExtendedKeyUsage, AllowedAlgorithms: t.AllowedAlgorithms,
		MinKeySize: t.MinKeySize, ValidityPeriod: t.ValidityPeriod, RenewalOverlap: t.RenewalOverlap,
		AutoEnroll: t.AutoEnroll, Active: true, RequireApproval: t.RequireApproval,
		ApprovalRoles: t.ApprovalRoles, EnrolleeType: t.EnrolleeType, NamePolicy: t.NamePolicy,
		EnrollmentPermissions: migratedEnrollPermissions(t),
	})
	if err != nil {
		return "", err
	}
	// Same tenant mapping the template create handler applies.
	if tenant, _ := ctx.Value(migrationTenantKey{}).(string); tenant != "" && tenant != DefaultTenant && activeTenantStore != nil {
		if merr := activeTenantStore.SetTemplateTenant(ctx, created.ID, tenant); merr != nil {
			logging.Warnf("auto-map migrated template %s to tenant %s failed: %v", created.ID, tenant, merr)
		}
	}
	return created.ID, nil
}

// Update replaces a migrated template's mapped fields in place (B2): the
// template keeps its id and OID, is (re)activated, and keeps what the import
// does not model (SSH policy, short-lived flag, an enroll list an admin set).
func (s templateSink) Update(ctx context.Context, id string, t migration.Template) error {
	it, ok, err := s.templates.GetTemplate(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("template %s: %w", id, errTemplateNotFound)
	}
	// An enroll list an admin set (e.g. granting a DC) survives a re-apply.
	perms := it.EnrollmentPermissions
	if perms == nil {
		perms = migratedEnrollPermissions(t)
	}
	_, err = s.templates.ReplaceTemplate(ctx, id, TemplateUpsertRequest{
		Name: t.Name, DisplayName: t.DisplayName, OID: t.OID,
		KeyUsage: t.KeyUsage, ExtendedKeyUsage: t.ExtendedKeyUsage, AllowedAlgorithms: t.AllowedAlgorithms,
		MinKeySize: t.MinKeySize, ValidityPeriod: t.ValidityPeriod, RenewalOverlap: t.RenewalOverlap,
		AutoEnroll: t.AutoEnroll, Active: true, RequireApproval: t.RequireApproval,
		ApprovalRoles: t.ApprovalRoles, EnrolleeType: t.EnrolleeType, NamePolicy: t.NamePolicy,
		ShortLived: it.ShortLived, SSHPolicy: it.SSHPolicy, EnrollmentPermissions: perms,
	}, it.Revision)
	return err
}

// migratedEnrollPermissions is the enroll list an import sets (B5: DC,
// Kerberos and RAS templates are restricted); nil is unrestricted.
func migratedEnrollPermissions(t migration.Template) *EnrollmentPermissions {
	if len(t.EnrollRoles) == 0 {
		return nil
	}
	return &EnrollmentPermissions{Enroll: append([]string(nil), t.EnrollRoles...)}
}

// Inspect reports a template's OID and whether it is active.
func (s templateSink) Inspect(ctx context.Context, id string) (migration.TemplateState, bool, error) {
	it, ok, err := s.templates.GetTemplate(ctx, id)
	if err != nil || !ok {
		return migration.TemplateState{}, false, err
	}
	return migration.TemplateState{OID: it.OID, Active: it.Active}, true, nil
}

// Snapshot captures every field Update overwrites, as the request that would
// put the template back, so a rolled-back update restores it exactly.
func (s templateSink) Snapshot(ctx context.Context, id string) (string, error) {
	it, ok, err := s.templates.GetTemplate(ctx, id)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("template %s: %w", id, errTemplateNotFound)
	}
	raw, err := json.Marshal(templateRequestOf(it))
	return string(raw), err
}

// Restore replaces the template with a Snapshot, active flag included.
func (s templateSink) Restore(ctx context.Context, id, snapshot string) error {
	var req TemplateUpsertRequest
	if err := json.Unmarshal([]byte(snapshot), &req); err != nil {
		return fmt.Errorf("decode template snapshot: %w", err)
	}
	it, ok, err := s.templates.GetTemplate(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("template %s: %w", id, errTemplateNotFound)
	}
	_, err = s.templates.ReplaceTemplate(ctx, id, req, it.Revision)
	return err
}

// templateRequestOf is the PUT body that reproduces it.
func templateRequestOf(it TemplateItem) TemplateUpsertRequest {
	return TemplateUpsertRequest{
		Name: it.Name, DisplayName: it.DisplayName, OID: it.OID,
		KeyUsage: it.KeyUsage, ExtendedKeyUsage: it.ExtendedKeyUsage, AllowedAlgorithms: it.AllowedAlgorithms,
		MinKeySize: it.MinKeySize, ValidityPeriod: it.ValidityPeriod, RenewalOverlap: it.RenewalOverlap,
		AutoEnroll: it.AutoEnroll, Active: it.Active, ShortLived: it.ShortLived,
		RequireApproval: it.RequireApproval, ApprovalRoles: it.ApprovalRoles, EnrolleeType: it.EnrolleeType,
		SSHPolicy: it.SSHPolicy, NamePolicy: it.NamePolicy, EnrollmentPermissions: it.EnrollmentPermissions,
	}
}

func (s templateSink) Disable(ctx context.Context, id string) error {
	it, ok, err := s.templates.GetTemplate(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("template %s: %w", id, errTemplateNotFound)
	}
	if !it.Active {
		return nil
	}
	inactive := false
	_, err = s.templates.PatchTemplate(ctx, id, TemplatePatchRequest{Active: &inactive})
	return err
}

func (s templateSink) HasPendingApprovals(ctx context.Context, id string) (bool, error) {
	store, err := s.approvals()
	if err != nil || store == nil {
		return false, fmt.Errorf("approval store unavailable: %v", err)
	}
	for offset := 0; ; {
		reqs, total, err := store.List(ctx, "pending", 200, offset)
		if err != nil {
			return false, err
		}
		for _, r := range reqs {
			if r.TemplateID == id {
				return true, nil
			}
		}
		offset += len(reqs)
		if len(reqs) == 0 || offset >= total {
			return false, nil
		}
	}
}

func newMigrationStoreFromEnv() migration.Store {
	state := newDBProviderState[migration.Store](
		"migration",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_MIGRATION_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_MIGRATION_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_MIGRATION_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) migration.Store { return migration.NewSQLStore(db, false) },
		func(db *sql.DB) migration.Store { return migration.NewSQLStore(db, true) },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("migration", state.openErr) // logs the outage itself; the sentinel return is unused
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("migration", err) // logs the outage itself; the sentinel return is unused
		return nil
	}
	return state.store
}

// registerMigrationHandlers builds the service from the environment and
// mounts the API. It must run before registerPendingActionHandlers: it
// registers the executor that handler reads.
func registerMigrationHandlers(cfg *ServerConfig, mux *http.ServeMux, auth *Authenticator, templates TemplateProvider, creds OutboundCredentialStore, actions PendingActionStore, auditProvider AuditProvider) {
	var svc *migration.Service
	if store := newMigrationStoreFromEnv(); store != nil {
		sink := templateSink{templates: templates, approvals: newApprovalStoreFromEnv}
		svc = migration.NewService(sink, store, migrationImporters()...).
			WithKeyFloor(policyKeyFloor(func() *ca.PolicyEngine { return cfg.policyEngine }))
	}
	h := mountMigrationHandlers(mux, auth, svc, creds, actions, auditProvider)
	if cfg.actionExecutors == nil {
		cfg.actionExecutors = map[string]ActionExecutor{}
	}
	cfg.actionExecutors[ActionMigrationApply] = h.ExecuteApply
}

// policyKeyFloor reads the RSA floor of the active issuance policies, which a
// migrated template's min_key_size is raised to (B2). A nil engine is no floor.
func policyKeyFloor(engine func() *ca.PolicyEngine) func(context.Context) (migration.KeyFloor, error) {
	return func(context.Context) (migration.KeyFloor, error) {
		pe := engine()
		if pe == nil {
			return migration.KeyFloor{}, nil
		}
		bits, name, err := pe.RSAFloor()
		return migration.KeyFloor{RSABits: bits, Policy: name}, err
	}
}

type migrationHandlers struct {
	svc     *migration.Service
	creds   OutboundCredentialStore
	actions PendingActionStore
	audit   AuditProvider
}

func migrationDiffSHA256(d migration.Diff) string {
	raw, _ := json.Marshal(d) // plain structs: cannot fail
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// input builds the framework input. With no pasted content, an importer that
// can read its source live (ADCS) does so with the referenced credential; the
// secret is resolved here and never stored.
func (h *migrationHandlers) input(ctx context.Context, source, content, credentialRef string, options map[string]string) (migration.Input, error) {
	in := migration.Input{Source: source, Content: []byte(content), Options: options}
	if content != "" {
		return in, nil
	}
	im, ok := h.svc.Importer(source)
	if !ok {
		return in, fmt.Errorf("%w: %q", migration.ErrUnknownSource, source)
	}
	lr, live := im.(migration.LiveReader)
	if !live || credentialRef == "" {
		return in, errors.New("content is required")
	}
	if h.creds == nil {
		return in, errMigrationCredsUnavailable
	}
	secret, err := h.creds.Resolve(ctx, credentialRef)
	if err != nil {
		return in, fmt.Errorf("credential %q: %w", credentialRef, err)
	}
	objs, err := lr.Read(ctx, migration.ReadOptions{
		URL: options["ldap_url"], BindDN: options["bind_dn"], BaseDN: options["base_dn"],
		// The same unwrap adcs_live binds with: a stored {"password":...} or
		// JSON-string payload sent as-is is an LDAP 52e (B1).
		Secret: adcsBindPassword(secret), AllowCleartext: options["allow_cleartext"] == "true",
	})
	if err != nil {
		return in, fmt.Errorf("read %s source: %w", source, err)
	}
	if objs == nil {
		objs = []migration.SourceObject{}
	}
	in.Objects = objs
	return in, nil
}

var errMigrationCredsUnavailable = errors.New("outbound credential store not configured")

// failRequest maps a framework or input error to a response. Anything that
// is not the caller's mistake stays server-side.
func (h *migrationHandlers) failRequest(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case errors.Is(err, errMigrationCredsUnavailable):
		writeServiceUnavailable(w, msg)
	case errors.Is(err, migration.ErrUnknownSource), errors.Is(err, migration.ErrNoObjects), errors.Is(err, migration.ErrInputTooLarge),
		strings.HasPrefix(msg, "parse "), strings.HasPrefix(msg, "credential "), msg == "content is required":
		writeBadRequest(w, msg)
	default:
		logging.Infof("migration: %v", err)
		writeServiceUnavailable(w, "migration unavailable")
	}
}

func mountMigrationHandlers(mux *http.ServeMux, auth *Authenticator, svc *migration.Service, creds OutboundCredentialStore, actions PendingActionStore, auditProvider AuditProvider) *migrationHandlers {
	h := &migrationHandlers{svc: svc, creds: creds, actions: actions, audit: auditProvider}
	mux.HandleFunc("/api/v1/migration/", func(w http.ResponseWriter, r *http.Request) {
		sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/migration/"), "/")
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "migration.access", "migration", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if svc == nil {
			writeServiceUnavailable(w, "migration store unavailable")
			return
		}
		parts := strings.Split(sub, "/")
		switch {
		case sub == "sources":
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			writeJSONData(w, svc.Sources())
		case sub == "dryrun":
			h.dryRun(w, r, pd)
		case sub == "apply":
			h.propose(w, r, pd)
		case sub == "batches":
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			list, err := svc.Store().ListBatches(r.Context(), 100)
			if err != nil {
				logging.Infof("migration: list batches: %v", err)
				writeServiceUnavailable(w, "migration unavailable")
				return
			}
			writeJSONData(w, list)
		case len(parts) == 2 && parts[0] != "" && parts[1] == "report":
			h.report(w, r, parts[0])
		case len(parts) == 2 && parts[0] != "" && parts[1] == "rollback":
			h.rollback(w, r, pd, parts[0])
		default:
			writeNotFound(w, "no such migration route")
		}
	})
	return h
}

func (h *migrationHandlers) decode(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, action string) (migrationRequest, bool) {
	var req migrationRequest
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return req, false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, migrationBodyLimit)).Decode(&req); err != nil {
		emitAuditEvent(r, h.audit, pd.ID, action, "migration", "", AuditOutcomeFailure)
		writeBadRequest(w, "invalid request body")
		return req, false
	}
	req.Source = strings.TrimSpace(req.Source)
	if req.Source == "" {
		emitAuditEvent(r, h.audit, pd.ID, action, "migration", "", AuditOutcomeFailure)
		writeBadRequest(w, "source is required")
		return req, false
	}
	return req, true
}

func (h *migrationHandlers) dryRun(w http.ResponseWriter, r *http.Request, pd AuthPrincipal) {
	req, ok := h.decode(w, r, pd, "migration.dryrun")
	if !ok {
		return
	}
	in, err := h.input(r.Context(), req.Source, req.Content, req.CredentialRef, req.Options)
	var diff migration.Diff
	if err == nil {
		diff, err = h.svc.DryRun(r.Context(), in)
	}
	if err != nil {
		emitAuditEvent(r, h.audit, pd.ID, "migration.dryrun", "migration", req.Source, AuditOutcomeFailure)
		h.failRequest(w, err)
		return
	}
	emitAuditEventDetail(r, h.audit, pd.ID, "migration.dryrun", "migration", req.Source, AuditOutcomeSuccess, diffSummary(diff))
	writeJSONData(w, diff)
}

func diffSummary(d migration.Diff) string {
	return fmt.Sprintf("create=%d update=%d skip=%d conflict=%d", d.Counts[migration.ActionCreate], d.Counts[migration.ActionUpdate],
		d.Counts[migration.ActionSkip], d.Counts[migration.ActionConflict])
}

// propose runs a dry run and, when something would be created or updated,
// queues the apply for a second person. Nothing is written here.
func (h *migrationHandlers) propose(w http.ResponseWriter, r *http.Request, pd AuthPrincipal) {
	req, ok := h.decode(w, r, pd, "migration.apply_requested")
	if !ok {
		return
	}
	if len(req.Content) > maxMigrationApplyContent {
		emitAuditEvent(r, h.audit, pd.ID, "migration.apply_requested", "migration", req.Source, AuditOutcomeFailure)
		writeBadRequest(w, "export too large to approve; split it")
		return
	}
	if h.actions == nil {
		emitAuditEvent(r, h.audit, pd.ID, "migration.apply_requested", "migration", req.Source, AuditOutcomeFailure)
		writeServiceUnavailable(w, "the approval queue is unavailable, so a migration cannot be applied")
		return
	}
	in, err := h.input(r.Context(), req.Source, req.Content, req.CredentialRef, req.Options)
	var diff migration.Diff
	if err == nil {
		diff, err = h.svc.DryRun(r.Context(), in)
	}
	if err != nil {
		emitAuditEvent(r, h.audit, pd.ID, "migration.apply_requested", "migration", req.Source, AuditOutcomeFailure)
		h.failRequest(w, err)
		return
	}
	n := diff.Counts[migration.ActionCreate] + diff.Counts[migration.ActionUpdate]
	if n == 0 {
		writeJSONData(w, map[string]any{"status": "nothing_to_apply", "diff": diff})
		return
	}
	params, _ := json.Marshal(migrationApplyParams{
		Source: req.Source, ContentB64: base64.StdEncoding.EncodeToString([]byte(req.Content)),
		Options: req.Options, CredentialRef: req.CredentialRef, DiffSHA256: migrationDiffSHA256(diff),
	})
	act, err := h.actions.Create(r.Context(), PendingAction{
		ActionType: ActionMigrationApply, Params: params, ProposedBy: pd.ID, Tenant: pd.Tenant,
		Rationale: fmt.Sprintf("migrate %d templates from %s", n, req.Source),
	})
	if err != nil {
		emitAuditEvent(r, h.audit, pd.ID, "migration.apply_requested", "migration", req.Source, AuditOutcomeFailure)
		logging.Infof("migration: propose: %v", err)
		writeServiceUnavailable(w, "could not queue the migration for approval")
		return
	}
	emitAuditEventDetail(r, h.audit, pd.ID, "migration.apply_requested", "migration", req.Source, AuditOutcomeSuccess,
		fmt.Sprintf("%s pending_action=%s", diffSummary(diff), act.ID))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(struct {
		Data any `json:"data"`
	}{Data: map[string]any{"status": "pending_approval", "pending_action_id": act.ID, "diff": diff}})
}

// ExecuteApply carries out an approved migration.apply. The queue has already
// refused self-approval and non-approver roles.
func (h *migrationHandlers) ExecuteApply(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
	if h.svc == nil {
		return nil, errors.New("migration store unavailable")
	}
	var p migrationApplyParams
	if err := json.Unmarshal(action.Params, &p); err != nil {
		return nil, errors.New("malformed migration proposal")
	}
	content, err := base64.StdEncoding.DecodeString(p.ContentB64)
	if err != nil {
		return nil, errors.New("malformed migration proposal content")
	}
	tenant := action.Tenant
	if tenant == "" {
		tenant = DefaultTenant
	}
	ctx = context.WithValue(ctx, migrationTenantKey{}, tenant)
	in, err := h.input(ctx, p.Source, string(content), p.CredentialRef, p.Options)
	if err != nil {
		h.auditApply(ctx, approver, tenant, p.Source, AuditOutcomeFailure, err.Error())
		return nil, err
	}
	diff, err := h.svc.DryRun(ctx, in)
	if err != nil {
		h.auditApply(ctx, approver, tenant, p.Source, AuditOutcomeFailure, err.Error())
		return nil, err
	}
	if migrationDiffSHA256(diff) != p.DiffSHA256 {
		err := errors.New("the export or the template set changed since this was proposed; propose again")
		h.auditApply(ctx, approver, tenant, p.Source, AuditOutcomeFailure, err.Error())
		return nil, err
	}
	rep, err := h.svc.Apply(ctx, in, approver.ID)
	if err != nil {
		resource := rep.BatchID
		if resource == "" {
			resource = p.Source
		}
		h.auditApply(ctx, approver, tenant, resource, AuditOutcomeFailure, fmt.Sprintf("batch=%s created=%d updated=%d: %v", rep.BatchID, rep.Created, rep.Updated, err))
		return nil, err
	}
	h.auditApply(ctx, approver, tenant, rep.BatchID, AuditOutcomeSuccess, fmt.Sprintf("batch=%s created=%d updated=%d", rep.BatchID, rep.Created, rep.Updated))
	out, _ := json.Marshal(rep)
	return out, nil
}

// auditApply appends directly: an executor has no *http.Request.
func (h *migrationHandlers) auditApply(ctx context.Context, approver AuthPrincipal, tenant, resourceID string, outcome AuditOutcome, summary string) {
	if h.audit == nil {
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditAppendTimeout)
	defer cancel()
	if err := h.audit.AppendEntry(actx, AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "migration.apply",
		ActorType: "user", ActorID: approver.ID, ResourceType: "migration", ResourceID: resourceID,
		Outcome: outcome, ChangeSummary: summary, Tenant: tenant,
	}); err != nil {
		logging.Errorf("audit append failed action=migration.apply resource_id=%s actor_id=%s: %v", resourceID, approver.ID, err)
	}
}

func (h *migrationHandlers) report(w http.ResponseWriter, r *http.Request, batchID string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	b, rep, ok, err := h.svc.Report(r.Context(), batchID)
	if err != nil {
		logging.Infof("migration: report %s: %v", batchID, err)
		writeServiceUnavailable(w, "migration unavailable")
		return
	}
	if !ok {
		writeNotFound(w, "migration batch not found")
		return
	}
	writeJSONData(w, map[string]any{"batch": b, "report": rep})
}

// rollback disables the templates a batch created (W24-39). An already
// rolled-back batch answers 200 and writes no audit row: twice is a no-op.
func (h *migrationHandlers) rollback(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, batchID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	res, err := h.svc.Rollback(r.Context(), batchID, pd.ID)
	if err != nil {
		emitAuditEvent(r, h.audit, pd.ID, "migration.rollback", "migration", batchID, AuditOutcomeFailure)
		if errors.Is(err, migration.ErrBatchNotFound) {
			writeNotFound(w, "migration batch not found")
			return
		}
		logging.Infof("migration: rollback %s: %v", batchID, err)
		writeServiceUnavailable(w, "rollback failed; retry to resume")
		return
	}
	if !res.AlreadyRolledBack {
		emitAuditEventDetail(r, h.audit, pd.ID, "migration.rollback", "migration", batchID, AuditOutcomeSuccess,
			fmt.Sprintf("disabled=%d kept=%d", res.Disabled, res.Kept))
	}
	writeJSONData(w, res)
}
