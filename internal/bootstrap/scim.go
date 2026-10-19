// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
)

// scimUserResource is the subset of the SCIM core User schema this endpoint
// reads/writes. KryptkeeperRole is a non-standard extension attribute
// letting a SCIM client set the initial role directly, in addition to the
// Groups-based mapping below.
type scimUserResource struct {
	Schemas         []string    `json:"schemas,omitempty"`
	ID              string      `json:"id,omitempty"`
	UserName        string      `json:"userName"`
	Emails          []scimEmail `json:"emails,omitempty"`
	Active          bool        `json:"active"`
	KryptkeeperRole string      `json:"kryptkeeperRole,omitempty"`
	Meta            scimMeta    `json:"meta,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
}

type scimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// scimPatchRequest is the SCIM PATCH op format (RFC 7644 3.5.2). value is
// decoded on demand since it can be either a bare scalar (path set) or an
// object keyed by attribute name (path omitted) depending on IdP.
type scimPatchRequest struct {
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

func scimEmailFromUser(u UserRecord) []scimEmail {
	if strings.TrimSpace(u.Email) == "" {
		return nil
	}
	return []scimEmail{{Value: u.Email, Primary: true}}
}

func scimUserFromRecord(u UserRecord) scimUserResource {
	return scimUserResource{
		Schemas:         []string{scimUserSchema},
		ID:              u.ID,
		UserName:        u.Email,
		Emails:          scimEmailFromUser(u),
		Active:          !isDeprovisionedStatus(u.Status),
		KryptkeeperRole: u.Role,
		Meta:            scimMeta{ResourceType: "User", Location: "/scim/v2/Users/" + u.ID},
	}
}

func scimEmailFromRequest(req scimUserResource) string {
	if email := strings.TrimSpace(req.UserName); email != "" && strings.Contains(email, "@") {
		return email
	}
	for _, e := range req.Emails {
		if strings.TrimSpace(e.Value) != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	return strings.TrimSpace(req.UserName)
}

func writeSCIMJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logging.Warnf("failed to encode scim response: %v", err)
	}
}

// writeSCIMBodyError answers a body-read failure: 413 when the cap was hit,
// otherwise 400 with badDetail.
func writeSCIMBodyError(w http.ResponseWriter, err error, badDetail string) {
	if isBodyTooLarge(err) {
		writeSCIMError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeSCIMError(w, http.StatusBadRequest, badDetail)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	payload := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  fmt.Sprintf("%d", status),
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logging.Warnf("failed to encode scim error response: %v", err)
	}
}

// scimAllowAdminRolesEnv opts a deployment in to SCIM assigning pki-admin or
// super-admin. Default off (D-204): the SCIM bearer is a long-lived
// provisioning secret held by the IdP, and without a ceiling a leak of it is
// a leak of every admin role. break-glass and bootstrap are never assignable
// through SCIM, flag or not, because break-glass holders can override dual
// control and bootstrap is the reserved root identity.
const scimAllowAdminRolesEnv = "SCIM_ALLOW_ADMIN_ROLES"

// scimRoleRefusal returns "" when SCIM may assign role, else the reason. The
// ceiling covers every SCIM path that sets a role: user create, user PATCH, the
// default role and the group role map (a SCIM client creates the group, so the
// map is reachable by whoever holds the bearer).
func scimRoleRefusal(role string) string {
	r := strings.ToLower(strings.TrimSpace(role))
	switch {
	case r == "":
		return ""
	case !roleGrantableByMap(r), r == breakGlassRole:
		return "role is not assignable through SCIM"
	case (r == "pki-admin" || r == "super-admin") && !envBool(scimAllowAdminRolesEnv):
		return "administrator roles are not assignable through SCIM; set " + scimAllowAdminRolesEnv + " to allow"
	}
	return ""
}

// scimUserInScope keeps the single, tenant-less SCIM bearer inside the default
// tenant when multi-tenancy is on: it must not read, deprovision or re-role
// another tenant's users.
func scimUserInScope(u UserRecord) bool {
	return !multiTenancyEnabled() || u.Tenant == "" || u.Tenant == DefaultTenant
}

// scimCancelApprovals cancels the pending issuance approvals a deprovisioned
// or removed user filed (W33-23). teamID "" cancels across teams. Failures are
// logged, never surfaced: the IdP's deprovision must not fail because the
// approval store is down, and the approvals then expire on their own TTL.
func scimCancelApprovals(ctx context.Context, auditProvider AuditProvider, userID, teamID string) {
	store, _ := newApprovalStoreFromEnv() // nil store = approvals disabled; open errors are logged by the provider
	if store == nil {
		return
	}
	n, err := CancelPendingForRequester(ctx, store, auditProvider, userID, teamID, time.Now())
	if err != nil {
		logging.Warnf("scim: cancelling pending approvals of %q failed after %d: %v", userID, n, err)
		return
	}
	if n > 0 {
		logging.Infof("scim: cancelled %d pending approval(s) of %q", n, userID)
	}
}

// registerSCIMHandlers wires /scim/v2/Users and /scim/v2/Groups. Every
// handler here checks scimAuthorized FIRST, before touching
// Authenticator.AuthenticatePrincipal at all -- SCIM provisioning is a trust
// boundary separate from using the product (acceptance #5): an ordinary
// operator session must be rejected here regardless of its role or scopes.
func registerSCIMHandlers(mux *http.ServeMux, auth *Authenticator, userProvider UserProvider, auditProvider AuditProvider) {
	// Lazy (sync.Once, opened on the first actual Groups request): opening
	// this store eagerly at registration time would create a var/
	// kryptkeeper.db as a side effect of every registerAuthHandlers call
	// with SCIM configured, even ones (like Users-only tests) that never
	// touch Groups.
	var groupStoreOnce sync.Once
	var groupStore scimGroupStore
	getGroupStore := func() scimGroupStore {
		groupStoreOnce.Do(func() {
			if strings.TrimSpace(auth.config.scimBearerToken) == "" {
				return
			}
			groupStore = newSCIMGroupStoreFromEnv()
		})
		return groupStore
	}

	mux.HandleFunc("/scim/v2/Users", func(w http.ResponseWriter, r *http.Request) {
		if !scimAuthorized(auth, r) {
			emitAuditEvent(r, auditProvider, "", "scim.users", "scim-user", "users", AuditOutcomeDenied)
			writeSCIMError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		switch r.Method {
		case http.MethodGet:
			users, err := userProvider.ListUsers(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, "", "scim.users.list", "scim-user", "users", AuditOutcomeFailure)
				writeSCIMError(w, http.StatusServiceUnavailable, "users unavailable")
				return
			}
			filter, ferr := parseSCIMFilter(r.URL.Query().Get("filter"))
			if ferr == nil && filter != nil {
				ferr = filter.validFor(scimUserFilterAttrs)
			}
			if ferr != nil {
				writeSCIMError(w, http.StatusBadRequest, ferr.Error())
				return
			}
			matched := make([]UserRecord, 0, len(users))
			for _, u := range users {
				if !scimUserInScope(u) {
					continue
				}
				if filter == nil || filter.matchUser(u) {
					matched = append(matched, u)
				}
			}
			sort.Slice(matched, func(i, j int) bool {
				a, b := strings.ToLower(matched[i].Email), strings.ToLower(matched[j].Email)
				if a != b {
					return a < b
				}
				return matched[i].ID < matched[j].ID
			})
			resources := make([]any, 0, len(matched))
			for _, u := range matched {
				resources = append(resources, scimUserFromRecord(u))
			}
			emitAuditEvent(r, auditProvider, "", "scim.users.list", "scim-user", "users", AuditOutcomeSuccess)
			writeSCIMJSON(w, http.StatusOK, scimPagedList(r, resources))
		case http.MethodPost:
			var req scimUserResource
			if err := decodeJSONBody(w, r, &req, maxSCIMBodyBytes); err != nil {
				writeSCIMBodyError(w, err, "invalid request body")
				return
			}
			email := scimEmailFromRequest(req)
			if email == "" {
				writeSCIMError(w, http.StatusBadRequest, "userName or emails[0].value is required")
				return
			}
			role := firstNonEmpty(strings.TrimSpace(req.KryptkeeperRole), auth.config.scimDefaultRole)
			if msg := scimRoleRefusal(role); msg != "" {
				emitAuditEvent(r, auditProvider, "", "scim.users.create", "scim-user", email, AuditOutcomeDenied)
				writeSCIMError(w, http.StatusForbidden, msg)
				return
			}
			user, err := userProvider.InviteUser(r.Context(), email, role)
			if err != nil {
				emitAuditEvent(r, auditProvider, "", "scim.users.create", "scim-user", email, AuditOutcomeFailure)
				writeSCIMError(w, http.StatusServiceUnavailable, "user creation unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, "", "scim.users.create", "scim-user", user.ID, AuditOutcomeSuccess)
			writeSCIMJSON(w, http.StatusCreated, scimUserFromRecord(user))
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/scim/v2/Users/", func(w http.ResponseWriter, r *http.Request) {
		if !scimAuthorized(auth, r) {
			emitAuditEvent(r, auditProvider, "", "scim.users", "scim-user", "users", AuditOutcomeDenied)
			writeSCIMError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
		if id == "" {
			writeSCIMError(w, http.StatusNotFound, "user not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			user, found, err := findSCIMUserByID(r.Context(), userProvider, id)
			if err != nil {
				writeSCIMError(w, http.StatusServiceUnavailable, "users unavailable")
				return
			}
			if !found || !scimUserInScope(user) {
				writeSCIMError(w, http.StatusNotFound, "user not found")
				return
			}
			writeSCIMJSON(w, http.StatusOK, scimUserFromRecord(user))
		case http.MethodPatch:
			capBody(w, r, maxSCIMBodyBytes)
			role, activeSet, active, err := decodeSCIMUserMutation(r)
			if err != nil {
				writeSCIMBodyError(w, err, err.Error())
				return
			}
			if !scimTargetInScope(w, r, userProvider, auditProvider, "scim.users.update", id) {
				return
			}
			if msg := scimRoleRefusal(role); msg != "" {
				emitAuditEvent(r, auditProvider, "", "scim.users.update", "scim-user", id, AuditOutcomeDenied)
				writeSCIMError(w, http.StatusForbidden, msg)
				return
			}
			if activeSet && !active {
				// Deprovisioning: acceptance #4's exact revocation path --
				// reuses DeactivateUser, the same method the admin console
				// (handlers_users.go) already calls.
				if err := userProvider.DeactivateUser(r.Context(), id); err != nil {
					emitAuditEvent(r, auditProvider, "", "scim.users.deprovision", "scim-user", id, AuditOutcomeFailure)
					writeSCIMError(w, http.StatusNotFound, "user not found")
					return
				}
				emitAuditEvent(r, auditProvider, "", "scim.users.deprovision", "scim-user", id, AuditOutcomeSuccess)
				scimCancelApprovals(r.Context(), auditProvider, id, "")
			} else {
				status := ""
				if activeSet && active {
					status = "active"
				}
				if role == "" && status == "" {
					// Nothing to change; still return current state.
				} else if _, err := userProvider.UpdateUser(r.Context(), id, role, status); err != nil {
					emitAuditEvent(r, auditProvider, "", "scim.users.update", "scim-user", id, AuditOutcomeFailure)
					writeSCIMError(w, http.StatusNotFound, "user not found")
					return
				}
				emitAuditEvent(r, auditProvider, "", "scim.users.update", "scim-user", id, AuditOutcomeSuccess)
			}
			user, found, err := findSCIMUserByID(r.Context(), userProvider, id)
			if err != nil || !found {
				writeSCIMError(w, http.StatusNotFound, "user not found")
				return
			}
			writeSCIMJSON(w, http.StatusOK, scimUserFromRecord(user))
		case http.MethodDelete:
			// SCIM DELETE maps to a soft deactivate, never a row delete --
			// this codebase treats audit history as append-only (CLAUDE.md),
			// and a hard-deleted account would erase who it ever was.
			if !scimTargetInScope(w, r, userProvider, auditProvider, "scim.users.deprovision", id) {
				return
			}
			if err := userProvider.DeactivateUser(r.Context(), id); err != nil {
				emitAuditEvent(r, auditProvider, "", "scim.users.deprovision", "scim-user", id, AuditOutcomeFailure)
				writeSCIMError(w, http.StatusNotFound, "user not found")
				return
			}
			emitAuditEvent(r, auditProvider, "", "scim.users.deprovision", "scim-user", id, AuditOutcomeSuccess)
			scimCancelApprovals(r.Context(), auditProvider, id, "")
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, "GET, PATCH, DELETE")
		}
	})

	registerSCIMGroupHandlers(mux, auth, userProvider, getGroupStore, auditProvider)
}

// decodeSCIMUserMutation reads a PATCH (Operations, RFC 7644 3.5.2) body and
// returns the requested role change and, separately, whether `active` was
// specified and what value it was set to -- callers need those two facts
// distinguished so "not present" (leave alone) differs from "present and
// false" (deprovision). PUT (whole-resource replace) is deliberately NOT
// supported: scimUserResource.Active is a plain bool, so a PUT body omitting
// `active` would decode to false and silently deprovision the account on
// what looked like an unrelated field update -- exactly the kind of
// accidental revocation this ticket exists to make deliberate and tested.
// Real IdPs (Okta, Azure AD) provision via PATCH, not PUT, so this costs
// nothing in practice.
func decodeSCIMUserMutation(r *http.Request) (role string, activeSet bool, active bool, err error) {
	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		if isBodyTooLarge(readErr) {
			return "", false, false, errBodyTooLarge
		}
		return "", false, false, fmt.Errorf("invalid request body")
	}

	var patch scimPatchRequest
	if err := json.Unmarshal(body, &patch); err != nil {
		return "", false, false, fmt.Errorf("invalid request body")
	}
	// apply folds one attribute assignment into the result. Okta sends
	// {"active": false} with no path; Entra sends path "active" with the
	// STRING "False"; both are handled here.
	apply := func(attr string, raw json.RawMessage) {
		switch scimUserAttr(attr) {
		case "active":
			if v, ok := scimBoolValue(raw); ok {
				activeSet, active = true, v
			}
		case "kryptkeeperrole", "role":
			var v string
			if err := json.Unmarshal(raw, &v); err == nil {
				role = v
			}
		}
	}
	for _, op := range patch.Operations {
		switch strings.ToLower(strings.TrimSpace(op.Op)) {
		case "add", "replace":
			if strings.TrimSpace(op.Path) != "" {
				apply(op.Path, op.Value)
				continue
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &obj); err == nil {
				for k, v := range obj {
					apply(k, v)
				}
			}
		case "remove":
			// An account is ended by deprovisioning, never by stripping
			// "active"; roles and identity attributes are not rewritable
			// through SCIM, so removing them is accepted as a no-op.
			if scimUserAttr(op.Path) == "active" {
				return "", false, false, fmt.Errorf("active cannot be removed")
			}
		default:
			return "", false, false, fmt.Errorf("invalid op")
		}
	}
	return role, activeSet, active, nil
}

// scimUserAttr normalises a PATCH path or object key: case-insensitive, with
// the schema-qualified form ("urn:...:2.0:User:active") reduced to its name.
func scimUserAttr(path string) string {
	p := strings.ToLower(strings.TrimSpace(path))
	return strings.TrimPrefix(p, strings.ToLower(scimUserSchema)+":")
}

// scimBoolValue reads a JSON bool or the strings "True"/"False" (Entra).
func scimBoolValue(raw json.RawMessage) (bool, bool) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// --- SCIM list filtering and pagination (RFC 7644 3.4.2) ---

const (
	scimDefaultCount = 100
	scimMaxCount     = 200
)

var (
	scimUserFilterAttrs  = map[string]bool{"username": true, "emails.value": true, "active": true, "id": true}
	scimGroupFilterAttrs = map[string]bool{"displayname": true, "id": true}
	// Okta and Entra qualify the email filter with a sub-attribute selector.
	scimEmailSelectorRe = regexp.MustCompile(`(?i)^emails\[[^\]]*\]\.value$`)
	scimMemberRemoveRe  = regexp.MustCompile(`(?i)^members\[value eq "([^"]+)"\]$`)
)

// scimFilter is the one-clause subset of the SCIM filter grammar the IdPs
// actually send for existence checks: attr op "value". Attr is lower-cased.
type scimFilter struct{ Attr, Op, Value string }

// parseSCIMFilter parses a single `attr op "value"` clause. and/or/not,
// grouping and every operator other than eq, sw and co are refused rather than
// half-evaluated: a filter that silently matches too much would make an IdP
// believe an account exists (or does not).
func parseSCIMFilter(raw string) (*scimFilter, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	bad := func(reason string) (*scimFilter, error) {
		return nil, fmt.Errorf("invalid filter: %s", reason)
	}
	attr, rest := scimFilterToken(raw)
	op, rest := scimFilterToken(rest)
	if attr == "" || op == "" || rest == "" {
		return bad("expected attr op value")
	}
	attr = strings.ToLower(attr)
	if scimEmailSelectorRe.MatchString(attr) {
		attr = "emails.value"
	}
	op = strings.ToLower(op)
	if op != "eq" && op != "sw" && op != "co" {
		return bad("unsupported operator " + strconv.Quote(op))
	}
	var value string
	if strings.HasPrefix(rest, `"`) {
		end := -1
		for i := 1; i < len(rest); i++ {
			if rest[i] == '\\' {
				i++
				continue
			}
			if rest[i] == '"' {
				end = i
				break
			}
		}
		if end < 0 {
			return bad("unterminated quote")
		}
		if strings.TrimSpace(rest[end+1:]) != "" {
			return bad("only a single attr op value clause is supported")
		}
		value = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(rest[1:end])
	} else {
		if attr != "active" || (rest != "true" && rest != "false") {
			return bad("value must be a quoted string")
		}
		value = rest
	}
	if attr == "active" && op != "eq" {
		return bad("active supports only eq")
	}
	return &scimFilter{Attr: attr, Op: op, Value: value}, nil
}

// scimFilterToken splits off the next whitespace-delimited token, treating a
// [...] selector (which may contain spaces) as part of the token.
func scimFilterToken(s string) (token, rest string) {
	s = strings.TrimLeft(s, " \t")
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ' ', '\t':
			if depth == 0 {
				return s[:i], strings.TrimLeft(s[i:], " \t")
			}
		}
	}
	return s, ""
}

// validFor rejects attributes the target resource does not expose.
func (f *scimFilter) validFor(allowed map[string]bool) error {
	if !allowed[f.Attr] {
		return fmt.Errorf("invalid filter: unsupported attribute %s", strconv.Quote(f.Attr))
	}
	return nil
}

func (f *scimFilter) matchString(have string) bool {
	have, want := strings.ToLower(have), strings.ToLower(f.Value)
	switch f.Op {
	case "eq":
		return have == want
	case "sw":
		return strings.HasPrefix(have, want)
	case "co":
		return strings.Contains(have, want)
	}
	return false
}

func (f *scimFilter) matchUser(u UserRecord) bool {
	switch f.Attr {
	case "username", "emails.value":
		return f.matchString(u.Email)
	case "id":
		return f.matchString(u.ID)
	case "active":
		return f.Value == strconv.FormatBool(!isDeprovisionedStatus(u.Status))
	}
	return false
}

func (f *scimFilter) matchGroup(g scimGroup) bool {
	switch f.Attr {
	case "displayname":
		return f.matchString(g.DisplayName)
	case "id":
		return f.matchString(g.ID)
	}
	return false
}

// scimStartIndex is the 1-based startIndex query value, floored at 1.
func scimStartIndex(r *http.Request) int {
	if n, err := strconv.Atoi(r.URL.Query().Get("startIndex")); err == nil && n > 1 {
		return n
	}
	return 1
}

// scimPage turns startIndex/count into a safe 0-based slice window over total
// matches: start never exceeds total and start+count never overruns it.
func scimPage(r *http.Request, total int) (start, count int) {
	count = scimDefaultCount
	if raw := r.URL.Query().Get("count"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			count = n
		}
	}
	if count < 0 {
		count = 0
	}
	if count > scimMaxCount {
		count = scimMaxCount
	}
	start = scimStartIndex(r) - 1
	if start > total {
		start = total
	}
	if count > total-start {
		count = total - start
	}
	return start, count
}

// scimPagedList wraps one page of already filtered and sorted resources;
// totalResults counts every match, not just this page.
func scimPagedList(r *http.Request, resources []any) scimListResponse {
	start, count := scimPage(r, len(resources))
	page := make([]any, 0, count)
	page = append(page, resources[start:start+count]...)
	return scimListResponse{Schemas: []string{scimListSchema}, TotalResults: len(resources), StartIndex: scimStartIndex(r), ItemsPerPage: len(page), Resources: page}
}

// scimTargetInScope answers 404 (same as an unknown id, so tenants cannot be
// probed) and returns false when id names a user outside the SCIM scope. A
// lookup error also stops the mutation.
func scimTargetInScope(w http.ResponseWriter, r *http.Request, userProvider UserProvider, auditProvider AuditProvider, action, id string) bool {
	user, found, err := findSCIMUserByID(r.Context(), userProvider, id)
	if err != nil {
		emitAuditEvent(r, auditProvider, "", action, "scim-user", id, AuditOutcomeFailure)
		writeSCIMError(w, http.StatusServiceUnavailable, "users unavailable")
		return false
	}
	if !found || !scimUserInScope(user) {
		// The client sees "not found" either way, so the tenant boundary is
		// not probeable, but the attempt on a real out-of-scope user is
		// recorded.
		if found {
			emitAuditEvent(r, auditProvider, "", action, "scim-user", id, AuditOutcomeDenied)
		}
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return false
	}
	return true
}

func findSCIMUserByID(ctx context.Context, userProvider UserProvider, id string) (UserRecord, bool, error) {
	users, err := userProvider.ListUsers(ctx)
	if err != nil {
		return UserRecord{}, false, err
	}
	for _, u := range users {
		if u.ID == id {
			return u, true, nil
		}
	}
	return UserRecord{}, false, nil
}

// --- SCIM Groups: IdP group membership -> Kryptkeeper role mapping ---

type scimGroupResource struct {
	Schemas     []string          `json:"schemas,omitempty"`
	ID          string            `json:"id,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []scimGroupMember `json:"members,omitempty"`
	Meta        scimMeta          `json:"meta,omitempty"`
}

type scimGroupMember struct {
	Value string `json:"value"`
}

// registerSCIMGroupHandlers takes a getGroupStore getter rather than a
// concrete store so construction can be lazy: getGroupStore is called only
// when a Groups request actually arrives, not at registration time (see
// registerSCIMHandlers -- a store built eagerly at registration would open/
// EnsureSchema a DB file as a side effect of every registerAuthHandlers call
// with SCIM configured, even ones that never touch Groups).
func registerSCIMGroupHandlers(mux *http.ServeMux, auth *Authenticator, userProvider UserProvider, getGroupStore func() scimGroupStore, auditProvider AuditProvider) {
	mux.HandleFunc("/scim/v2/Groups", func(w http.ResponseWriter, r *http.Request) {
		if !scimAuthorized(auth, r) {
			emitAuditEvent(r, auditProvider, "", "scim.groups", "scim-group", "groups", AuditOutcomeDenied)
			writeSCIMError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		groupStore := getGroupStore()
		if groupStore == nil {
			writeSCIMError(w, http.StatusServiceUnavailable, "scim groups unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			groups, err := groupStore.List(r.Context())
			if err != nil {
				writeSCIMError(w, http.StatusServiceUnavailable, "groups unavailable")
				return
			}
			filter, ferr := parseSCIMFilter(r.URL.Query().Get("filter"))
			if ferr == nil && filter != nil {
				ferr = filter.validFor(scimGroupFilterAttrs)
			}
			if ferr != nil {
				writeSCIMError(w, http.StatusBadRequest, ferr.Error())
				return
			}
			matched := make([]scimGroup, 0, len(groups))
			for _, g := range groups {
				if filter == nil || filter.matchGroup(g) {
					matched = append(matched, g)
				}
			}
			sort.Slice(matched, func(i, j int) bool {
				a, b := strings.ToLower(matched[i].DisplayName), strings.ToLower(matched[j].DisplayName)
				if a != b {
					return a < b
				}
				return matched[i].ID < matched[j].ID
			})
			// Resolve members only for the page: the store round-trip per
			// group is the expensive part and the rest are never serialised.
			start, count := scimPage(r, len(matched))
			page := make([]any, 0, count)
			for _, g := range matched[start : start+count] {
				resource, err := scimGroupResourceFromStore(r.Context(), groupStore, g)
				if err != nil {
					writeSCIMError(w, http.StatusServiceUnavailable, "groups unavailable")
					return
				}
				page = append(page, resource)
			}
			writeSCIMJSON(w, http.StatusOK, scimListResponse{Schemas: []string{scimListSchema}, TotalResults: len(matched), StartIndex: scimStartIndex(r), ItemsPerPage: len(page), Resources: page})
		case http.MethodPost:
			var req scimGroupResource
			err := decodeJSONBody(w, r, &req, maxSCIMBodyBytes)
			if err != nil && isBodyTooLarge(err) {
				writeSCIMBodyError(w, err, "")
				return
			}
			if err != nil || strings.TrimSpace(req.DisplayName) == "" {
				writeSCIMError(w, http.StatusBadRequest, "displayName is required")
				return
			}
			id, err := generateOpaqueToken("grp")
			if err != nil {
				writeSCIMError(w, http.StatusServiceUnavailable, "group creation unavailable")
				return
			}
			id = strings.ReplaceAll(id, "_", "")
			group, err := groupStore.Create(r.Context(), id, strings.TrimSpace(req.DisplayName), time.Now())
			if err != nil {
				emitAuditEvent(r, auditProvider, "", "scim.groups.create", "scim-group", req.DisplayName, AuditOutcomeFailure)
				writeSCIMError(w, http.StatusServiceUnavailable, "group creation unavailable")
				return
			}
			for _, member := range req.Members {
				if err := addSCIMGroupMember(r.Context(), groupStore, userProvider, auth, auditProvider, group, member.Value); err != nil {
					logging.Warnf("scim: failed to add member %q to group %q: %v", member.Value, group.DisplayName, err)
				}
			}
			emitAuditEvent(r, auditProvider, "", "scim.groups.create", "scim-group", group.ID, AuditOutcomeSuccess)
			resource, err := scimGroupResourceFromStore(r.Context(), groupStore, group)
			if err != nil {
				writeSCIMError(w, http.StatusServiceUnavailable, "groups unavailable")
				return
			}
			writeSCIMJSON(w, http.StatusCreated, resource)
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/scim/v2/Groups/", func(w http.ResponseWriter, r *http.Request) {
		if !scimAuthorized(auth, r) {
			emitAuditEvent(r, auditProvider, "", "scim.groups", "scim-group", "groups", AuditOutcomeDenied)
			writeSCIMError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		groupStore := getGroupStore()
		if groupStore == nil {
			writeSCIMError(w, http.StatusServiceUnavailable, "scim groups unavailable")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Groups/")
		if id == "" {
			writeSCIMError(w, http.StatusNotFound, "group not found")
			return
		}
		group, found, err := groupStore.Get(r.Context(), id)
		if err != nil {
			writeSCIMError(w, http.StatusServiceUnavailable, "groups unavailable")
			return
		}
		if !found {
			writeSCIMError(w, http.StatusNotFound, "group not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			resource, err := scimGroupResourceFromStore(r.Context(), groupStore, group)
			if err != nil {
				writeSCIMError(w, http.StatusServiceUnavailable, "groups unavailable")
				return
			}
			writeSCIMJSON(w, http.StatusOK, resource)
		case http.MethodPatch:
			capBody(w, r, maxSCIMBodyBytes)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				writeSCIMBodyError(w, err, "invalid request body")
				return
			}
			var patch scimPatchRequest
			if err := json.Unmarshal(body, &patch); err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			for _, op := range patch.Operations {
				applySCIMGroupPatchOp(r.Context(), groupStore, userProvider, auth, auditProvider, group, op.Op, op.Path, op.Value)
			}
			emitAuditEvent(r, auditProvider, "", "scim.groups.update", "scim-group", group.ID, AuditOutcomeSuccess)
			resource, err := scimGroupResourceFromStore(r.Context(), groupStore, group)
			if err != nil {
				writeSCIMError(w, http.StatusServiceUnavailable, "groups unavailable")
				return
			}
			writeSCIMJSON(w, http.StatusOK, resource)
		case http.MethodDelete:
			if err := groupStore.Delete(r.Context(), group.ID); err != nil {
				emitAuditEvent(r, auditProvider, "", "scim.groups.delete", "scim-group", group.ID, AuditOutcomeFailure)
				writeSCIMError(w, http.StatusNotFound, "group not found")
				return
			}
			emitAuditEvent(r, auditProvider, "", "scim.groups.delete", "scim-group", group.ID, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, "GET, PATCH, DELETE")
		}
	})
}

// applySCIMGroupPatchOp applies one PATCH operation to a group's membership.
// Op and path match case-insensitively (Entra sends "Add"/"Remove"). remove
// takes either path "members" with a value array (Okta) or the filtered path
// members[value eq "<id>"] with no value (Entra). replace swaps the whole set,
// re-applying the group's role mapping to everyone listed. Unknown paths are
// ignored; per-member failures are logged and skipped so one stale id does not
// abort the rest of an IdP's batch.
func applySCIMGroupPatchOp(ctx context.Context, groupStore scimGroupStore, userProvider UserProvider, auth *Authenticator, auditProvider AuditProvider, group scimGroup, op, path string, value json.RawMessage) {
	path = strings.TrimSpace(path)
	op = strings.ToLower(strings.TrimSpace(op))
	listed := func() []string {
		var members []scimGroupMember
		if err := json.Unmarshal(value, &members); err != nil {
			return nil
		}
		ids := make([]string, 0, len(members))
		for _, m := range members {
			ids = append(ids, m.Value)
		}
		return ids
	}
	add := func(ids []string) {
		for _, id := range ids {
			if err := addSCIMGroupMember(ctx, groupStore, userProvider, auth, auditProvider, group, id); err != nil {
				logging.Warnf("scim: failed to add member %q to group %q: %v", id, group.DisplayName, err)
			}
		}
	}
	remove := func(ids []string) {
		// Only a real departure cancels approvals: RemoveMember succeeds for
		// a non-member, and without this check a bearer holder could cancel
		// anyone's approvals by "removing" them from a group it created.
		before := map[string]bool{}
		if current, err := groupStore.Members(ctx, group.ID); err == nil {
			for _, m := range current {
				before[m] = true
			}
		}
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if err := groupStore.RemoveMember(ctx, group.ID, id); err != nil {
				logging.Warnf("scim: failed to remove member %q from group %q: %v", id, group.DisplayName, err)
				continue
			}
			if !before[id] {
				continue
			}
			if u, found, err := findSCIMUserByID(ctx, userProvider, id); err != nil || !found || !scimUserInScope(u) {
				continue
			}
			// W33-23: a member leaving a group leaves that team. The group's
			// displayName is the team id; an approval filed for another team
			// is untouched.
			scimCancelApprovals(ctx, auditProvider, id, group.DisplayName)
		}
	}
	if m := scimMemberRemoveRe.FindStringSubmatch(path); m != nil {
		if op == "remove" {
			remove([]string{m[1]})
		}
		return
	}
	if !strings.EqualFold(path, "members") {
		return
	}
	switch op {
	case "add":
		add(listed())
	case "remove":
		remove(listed())
	case "replace":
		keep := listed()
		current, err := groupStore.Members(ctx, group.ID)
		if err != nil {
			logging.Warnf("scim: failed to read members of group %q for replace: %v", group.DisplayName, err)
			return
		}
		want := make(map[string]bool, len(keep))
		for _, id := range keep {
			want[strings.TrimSpace(id)] = true
		}
		for _, id := range current {
			if !want[id] {
				remove([]string{id})
			}
		}
		add(keep)
	}
}

// addSCIMGroupMember records membership and, if this group's displayName is
// configured in APP_SCIM_GROUP_ROLE_MAP_JSON, assigns the mapped
// Kryptkeeper role to the member (acceptance #4: "map IdP groups to
// Kryptkeeper roles"). Membership is recorded even when no mapping exists,
// since a group's mapping can be configured after the fact.
func addSCIMGroupMember(ctx context.Context, groupStore scimGroupStore, userProvider UserProvider, auth *Authenticator, auditProvider AuditProvider, group scimGroup, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("empty member value")
	}
	if err := groupStore.AddMember(ctx, group.ID, userID); err != nil {
		return err
	}
	role, mapped := auth.config.scimGroupRoleMap[group.DisplayName]
	if !mapped {
		return nil
	}
	if msg := scimRoleRefusal(role); msg != "" {
		// Membership stays recorded; only the privileged role is withheld.
		logging.Warnf("scim: group %q maps to role %q, not applied to %q: %s", group.DisplayName, role, userID, msg)
		if auditProvider != nil {
			e := AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "scim.groups.role_withheld", ActorType: "scim", ActorID: "scim",
				ResourceType: "scim-user", ResourceID: userID, Outcome: AuditOutcomeDenied,
				ChangeSummary: fmt.Sprintf("group=%s role=%s", group.DisplayName, role),
			}
			if err := auditProvider.AppendEntry(ctx, e); err != nil {
				logging.Errorf("scim: audit append failed for withheld role on %q: %v", userID, err)
			}
		}
		return nil
	}
	if u, found, err := findSCIMUserByID(ctx, userProvider, userID); err == nil && found && !scimUserInScope(u) {
		return fmt.Errorf("user %q is outside the SCIM tenant scope", userID)
	}
	_, err := userProvider.UpdateUser(ctx, userID, role, "")
	return err
}

func scimGroupResourceFromStore(ctx context.Context, groupStore scimGroupStore, g scimGroup) (scimGroupResource, error) {
	memberIDs, err := groupStore.Members(ctx, g.ID)
	if err != nil {
		return scimGroupResource{}, err
	}
	members := make([]scimGroupMember, 0, len(memberIDs))
	for _, id := range memberIDs {
		members = append(members, scimGroupMember{Value: id})
	}
	return scimGroupResource{
		Schemas:     []string{scimGroupSchema},
		ID:          g.ID,
		DisplayName: g.DisplayName,
		Members:     members,
		Meta:        scimMeta{ResourceType: "Group", Location: "/scim/v2/Groups/" + g.ID},
	}, nil
}

// --- scimGroupStore: DB-backed persistence for SCIM Group resources ---
//
// Membership state is durable (survives restarts) unlike the OIDC login
// state store, deliberately: a SCIM Group represents real IdP-managed
// structure an IdP expects to GET/PATCH/DELETE consistently across restarts,
// not short-lived flow state. Mirrors config_store.go's G-33 self-heal
// pattern (EnsureSchema, sqlite/postgres structs, newDBProviderState).

type scimGroup struct {
	ID          string
	DisplayName string
	CreatedAt   string
	UpdatedAt   string
}

type scimGroupStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, id, displayName string, now time.Time) (scimGroup, error)
	Get(ctx context.Context, id string) (scimGroup, bool, error)
	List(ctx context.Context) ([]scimGroup, error)
	Delete(ctx context.Context, id string) error
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
	Members(ctx context.Context, groupID string) ([]string, error)
}

// scimGroupSchemaStatements mirrors migration 000031_oidc_sso_scim -- see
// G-33: every DB-backed store in this codebase self-heals its own schema
// since migrations are never actually run against a live deployment. Kept as
// separate statements (not one multi-statement string) because pgx's
// ExecContext rejects multiple statements in one call.
var scimGroupSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS scim_groups (
    id            TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
)`,
	`CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id      TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL,
    added_at      TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id)
)`,
	`CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members(user_id)`,
}

func execSchemaStatements(ctx context.Context, db *sql.DB, statements []string) error {
	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

type sqliteSCIMGroupStore struct{ db *sql.DB }

func (s *sqliteSCIMGroupStore) EnsureSchema(ctx context.Context) error {
	return execSchemaStatements(ctx, s.db, scimGroupSchemaStatements)
}

func (s *sqliteSCIMGroupStore) Create(ctx context.Context, id, displayName string, now time.Time) (scimGroup, error) {
	ts := now.UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO scim_groups (id, display_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
		id, displayName, ts, ts)
	if err != nil {
		return scimGroup{}, err
	}
	return scimGroup{ID: id, DisplayName: displayName, CreatedAt: ts, UpdatedAt: ts}, nil
}

func (s *sqliteSCIMGroupStore) Get(ctx context.Context, id string) (scimGroup, bool, error) {
	return scanSCIMGroup(s.db.QueryRowContext(ctx, "SELECT id, display_name, created_at, updated_at FROM scim_groups WHERE id = ?", id))
}

func (s *sqliteSCIMGroupStore) List(ctx context.Context) ([]scimGroup, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, display_name, created_at, updated_at FROM scim_groups ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	return scanSCIMGroupRows(rows)
}

func (s *sqliteSCIMGroupStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM scim_groups WHERE id = ?", id)
	return err
}

func (s *sqliteSCIMGroupStore) AddMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO scim_group_members (group_id, user_id, added_at) VALUES (?, ?, ?) ON CONFLICT(group_id, user_id) DO NOTHING",
		groupID, userID, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *sqliteSCIMGroupStore) RemoveMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?", groupID, userID)
	return err
}

func (s *sqliteSCIMGroupStore) Members(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT user_id FROM scim_group_members WHERE group_id = ? ORDER BY added_at ASC", groupID)
	if err != nil {
		return nil, err
	}
	return scanSCIMMemberRows(rows)
}

type postgresSCIMGroupStore struct{ db *sql.DB }

func (s *postgresSCIMGroupStore) EnsureSchema(ctx context.Context) error {
	return execSchemaStatements(ctx, s.db, scimGroupSchemaStatements)
}

func (s *postgresSCIMGroupStore) Create(ctx context.Context, id, displayName string, now time.Time) (scimGroup, error) {
	ts := now.UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO scim_groups (id, display_name, created_at, updated_at) VALUES ($1, $2, $3, $4)",
		id, displayName, ts, ts)
	if err != nil {
		return scimGroup{}, err
	}
	return scimGroup{ID: id, DisplayName: displayName, CreatedAt: ts, UpdatedAt: ts}, nil
}

func (s *postgresSCIMGroupStore) Get(ctx context.Context, id string) (scimGroup, bool, error) {
	return scanSCIMGroup(s.db.QueryRowContext(ctx, "SELECT id, display_name, created_at, updated_at FROM scim_groups WHERE id = $1", id))
}

func (s *postgresSCIMGroupStore) List(ctx context.Context) ([]scimGroup, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, display_name, created_at, updated_at FROM scim_groups ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	return scanSCIMGroupRows(rows)
}

func (s *postgresSCIMGroupStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM scim_groups WHERE id = $1", id)
	return err
}

func (s *postgresSCIMGroupStore) AddMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO scim_group_members (group_id, user_id, added_at) VALUES ($1, $2, $3) ON CONFLICT(group_id, user_id) DO NOTHING",
		groupID, userID, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *postgresSCIMGroupStore) RemoveMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = $2", groupID, userID)
	return err
}

func (s *postgresSCIMGroupStore) Members(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT user_id FROM scim_group_members WHERE group_id = $1 ORDER BY added_at ASC", groupID)
	if err != nil {
		return nil, err
	}
	return scanSCIMMemberRows(rows)
}

func scanSCIMGroup(row *sql.Row) (scimGroup, bool, error) {
	var g scimGroup
	err := row.Scan(&g.ID, &g.DisplayName, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return scimGroup{}, false, nil
	}
	if err != nil {
		return scimGroup{}, false, err
	}
	return g, true, nil
}

func scanSCIMGroupRows(rows *sql.Rows) ([]scimGroup, error) {
	defer rows.Close()
	items := []scimGroup{}
	for rows.Next() {
		var g scimGroup
		if err := rows.Scan(&g.ID, &g.DisplayName, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, g)
	}
	return items, rows.Err()
}

func scanSCIMMemberRows(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	items := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	return items, rows.Err()
}

// newSCIMGroupStoreFromEnv opens the scim_groups/scim_group_members store and
// ensures its schema exists (G-33), matching newConfigStoreFromEnv's
// nil-tolerant shape -- returns nil on any failure, in which case SCIM Group
// endpoints report 503 but SCIM Users keeps working (Groups is the part
// acceptance #4 calls conditional: "Groups if group mapping needs it").
func newSCIMGroupStoreFromEnv() scimGroupStore {
	state := newDBProviderState[scimGroupStore](
		"scim-group",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_SCIM_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_SCIM_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_SCIM_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) scimGroupStore { return &sqliteSCIMGroupStore{db: db} },
		func(db *sql.DB) scimGroupStore { return &postgresSCIMGroupStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("scim-group", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("scim-group", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}
