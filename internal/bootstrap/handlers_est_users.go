// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"kryptkeeper/internal/logging"
	"net/http"
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/est"
)

const (
	estUserMaxSuffixes  = 20
	estUserAuditType    = "est_user"
	estUserBodyMaxBytes = 16 * 1024
)

// estUsernameRE excludes ":" because it would break HTTP Basic parsing
// (RFC 7617: the user-id cannot contain a colon).
var estUsernameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// ESTUserStore is the est.DBUserStore surface the API needs.
type ESTUserStore interface {
	Create(ctx context.Context, u est.StoredUser) (est.StoredUser, error)
	Get(ctx context.Context, username string) (est.StoredUser, error)
	List(ctx context.Context) ([]est.StoredUser, error)
	Update(ctx context.Context, username string, disabled *bool, suffixes []string) (est.StoredUser, error)
	SetPassword(ctx context.Context, username, bcryptHash string) error
	Delete(ctx context.Context, username string) error
}

type estUserView struct {
	Username           string     `json:"username"`
	AllowedDNSSuffixes []string   `json:"allowed_dns_suffixes"`
	Disabled           bool       `json:"disabled"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	PasswordRotatedAt  *time.Time `json:"password_rotated_at"`
	ShadowedByFile     bool       `json:"shadowed_by_file"`
}

// estUserSecret is the one-time response of create and rotate.
type estUserSecret struct {
	Username           string    `json:"username"`
	Password           string    `json:"password"`
	AllowedDNSSuffixes []string  `json:"allowed_dns_suffixes"`
	CreatedAt          time.Time `json:"created_at"`
}

// RegisterESTUserHandlers mounts the EST Basic-user API (W26-07, D-112):
// create (the server generates the password, shown once), list, get, rotate,
// disable/re-suffix and delete. pki-admin only. hasFileUser reports users
// defined in KRYPTKEEPER_EST_USERS_FILE, which win over a stored user of the
// same name.
func RegisterESTUserHandlers(mux *http.ServeMux, auth *Authenticator, store ESTUserStore, hasFileUser func(string) bool, auditProvider AuditProvider) {
	if store == nil {
		return
	}
	if hasFileUser == nil {
		hasFileUser = func(string) bool { return false }
	}
	authorize := func(w http.ResponseWriter, r *http.Request, action, id string) (string, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, estUserAuditType, id, AuditOutcomeDenied)
			writeUnauthorized(w)
			return "", false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, estUserAuditType, id, AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required for EST users")
			return "", false
		}
		// EST users are one instance-wide credential set.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, estUserAuditType, id) {
			return "", false
		}
		return pd.ID, true
	}
	writeData := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(struct {
			Data any `json:"data"`
		}{Data: v}); err != nil {
			logging.Infof("est user response: %v", err)
		}
	}
	view := func(u est.StoredUser) estUserView {
		return estUserView{
			Username: u.Username, AllowedDNSSuffixes: u.AllowedDNSSuffixes, Disabled: u.Disabled,
			CreatedBy: u.CreatedBy, CreatedAt: u.CreatedAt, PasswordRotatedAt: u.PasswordRotatedAt,
			ShadowedByFile: hasFileUser(u.Username),
		}
	}
	// storeFailure answers a store error that is not a plain not-found.
	storeFailure := func(w http.ResponseWriter, r *http.Request, principal, action, id string, err error) {
		logging.Infof("est user %s: %v", action, err)
		emitAuditEvent(r, auditProvider, principal, action, estUserAuditType, id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "est users unavailable")
	}
	notFound := func(w http.ResponseWriter, r *http.Request, principal, action, id string) {
		emitAuditEvent(r, auditProvider, principal, action, estUserAuditType, id, AuditOutcomeFailure)
		writeNotFound(w, "est user not found")
	}
	badRequest := func(w http.ResponseWriter, r *http.Request, principal, action, id, msg string) {
		emitAuditEventDetail(r, auditProvider, principal, action, estUserAuditType, id, AuditOutcomeFailure, msg)
		writeBadRequest(w, msg)
	}
	decode := func(w http.ResponseWriter, r *http.Request, principal, action, id string, into any) bool {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, estUserBodyMaxBytes)).Decode(into); err != nil {
			emitAuditEvent(r, auditProvider, principal, action, estUserAuditType, id, AuditOutcomeFailure)
			if rejectOversizeBody(w, err) {
				return false
			}
			writeBadRequest(w, "invalid request body")
			return false
		}
		return true
	}
	checkSuffixes := func(in []string) ([]string, error) {
		if len(in) > estUserMaxSuffixes {
			return nil, errors.New("at most 20 allowed_dns_suffixes")
		}
		return est.ValidateSuffixes(in)
	}
	suffixDetail := func(s []string) string { return "suffixes=" + strings.Join(s, ",") }

	mux.HandleFunc("/api/v1/est/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "est.user.list", "-"); !ok {
				return
			}
			users, err := store.List(r.Context())
			if err != nil {
				logging.Infof("est user list: %v", err)
				writeServiceUnavailable(w, "est users unavailable")
				return
			}
			views := make([]estUserView, 0, len(users))
			for _, u := range users {
				views = append(views, view(u))
			}
			writeData(w, http.StatusOK, views)
		case http.MethodPost:
			const action = "est.user.create"
			principal, ok := authorize(w, r, action, "-")
			if !ok {
				return
			}
			var req struct {
				Username string   `json:"username"`
				Suffixes []string `json:"allowed_dns_suffixes"`
			}
			if !decode(w, r, principal, action, "-", &req) {
				return
			}
			if !estUsernameRE.MatchString(req.Username) {
				badRequest(w, r, principal, action, "-", "username must be 1-64 characters from A-Z a-z 0-9 . _ @ - (no colon)")
				return
			}
			suffixes, err := checkSuffixes(req.Suffixes)
			if err != nil {
				badRequest(w, r, principal, action, req.Username, err.Error())
				return
			}
			if hasFileUser(req.Username) {
				emitAuditEvent(r, auditProvider, principal, action, estUserAuditType, req.Username, AuditOutcomeFailure)
				writeConflict(w, "est user is already defined in the users file")
				return
			}
			password, hash, err := est.NewUserPassword()
			if err != nil {
				storeFailure(w, r, principal, action, req.Username, err)
				return
			}
			created, err := store.Create(r.Context(), est.StoredUser{
				Username: req.Username, BcryptHash: hash, AllowedDNSSuffixes: suffixes, CreatedBy: principal,
			})
			if errors.Is(err, est.ErrUserExists) {
				emitAuditEvent(r, auditProvider, principal, action, estUserAuditType, req.Username, AuditOutcomeFailure)
				writeConflict(w, "est user already exists")
				return
			}
			if err != nil {
				storeFailure(w, r, principal, action, req.Username, err)
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, action, estUserAuditType, created.Username, AuditOutcomeSuccess, suffixDetail(suffixes))
			// The password is in this response and nowhere else.
			writeData(w, http.StatusCreated, estUserSecret{
				Username: created.Username, Password: password,
				AllowedDNSSuffixes: created.AllowedDNSSuffixes, CreatedAt: created.CreatedAt,
			})
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/est/users/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/est/users/")
		name, sub, _ := strings.Cut(rest, "/")
		if name == "" || (sub != "" && sub != "rotate") {
			writeNotFound(w, "est user not found")
			return
		}
		if sub == "rotate" {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			const action = "est.user.rotate"
			principal, ok := authorize(w, r, action, name)
			if !ok {
				return
			}
			if !estUsernameRE.MatchString(name) {
				badRequest(w, r, principal, action, "-", "invalid username")
				return
			}
			current, err := store.Get(r.Context(), name)
			if errors.Is(err, est.ErrUserNotFound) {
				notFound(w, r, principal, action, name)
				return
			}
			if err != nil {
				storeFailure(w, r, principal, action, name, err)
				return
			}
			password, hash, err := est.NewUserPassword()
			if err != nil {
				storeFailure(w, r, principal, action, name, err)
				return
			}
			if err := store.SetPassword(r.Context(), name, hash); err != nil {
				if errors.Is(err, est.ErrUserNotFound) {
					notFound(w, r, principal, action, name)
					return
				}
				storeFailure(w, r, principal, action, name, err)
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, action, estUserAuditType, name, AuditOutcomeSuccess, suffixDetail(current.AllowedDNSSuffixes))
			writeData(w, http.StatusOK, estUserSecret{
				Username: name, Password: password, AllowedDNSSuffixes: current.AllowedDNSSuffixes, CreatedAt: current.CreatedAt,
			})
			return
		}

		switch r.Method {
		case http.MethodGet:
			const action = "est.user.get"
			_, ok := authorize(w, r, action, name)
			if !ok {
				return
			}
			if !estUsernameRE.MatchString(name) {
				writeNotFound(w, "est user not found")
				return
			}
			u, err := store.Get(r.Context(), name)
			if errors.Is(err, est.ErrUserNotFound) {
				writeNotFound(w, "est user not found")
				return
			}
			if err != nil {
				logging.Infof("est user get: %v", err)
				writeServiceUnavailable(w, "est users unavailable")
				return
			}
			writeData(w, http.StatusOK, view(u))
		case http.MethodPatch:
			const action = "est.user.update"
			principal, ok := authorize(w, r, action, name)
			if !ok {
				return
			}
			var req struct {
				Disabled *bool    `json:"disabled"`
				Suffixes []string `json:"allowed_dns_suffixes"`
			}
			if !decode(w, r, principal, action, name, &req) {
				return
			}
			if !estUsernameRE.MatchString(name) {
				badRequest(w, r, principal, action, "-", "invalid username")
				return
			}
			if req.Disabled == nil && req.Suffixes == nil {
				badRequest(w, r, principal, action, name, "disabled or allowed_dns_suffixes is required")
				return
			}
			var suffixes []string
			if req.Suffixes != nil {
				var err error
				if suffixes, err = checkSuffixes(req.Suffixes); err != nil {
					badRequest(w, r, principal, action, name, err.Error())
					return
				}
			}
			u, err := store.Update(r.Context(), name, req.Disabled, suffixes)
			if errors.Is(err, est.ErrUserNotFound) {
				notFound(w, r, principal, action, name)
				return
			}
			if err != nil {
				storeFailure(w, r, principal, action, name, err)
				return
			}
			detail := suffixDetail(u.AllowedDNSSuffixes)
			if req.Disabled != nil {
				detail += " disabled=" + map[bool]string{true: "true", false: "false"}[u.Disabled]
			}
			emitAuditEventDetail(r, auditProvider, principal, action, estUserAuditType, name, AuditOutcomeSuccess, detail)
			writeData(w, http.StatusOK, view(u))
		case http.MethodDelete:
			const action = "est.user.delete"
			principal, ok := authorize(w, r, action, name)
			if !ok {
				return
			}
			if !estUsernameRE.MatchString(name) {
				badRequest(w, r, principal, action, "-", "invalid username")
				return
			}
			if err := store.Delete(r.Context(), name); err != nil {
				if errors.Is(err, est.ErrUserNotFound) {
					notFound(w, r, principal, action, name)
					return
				}
				storeFailure(w, r, principal, action, name, err)
				return
			}
			emitAuditEvent(r, auditProvider, principal, action, estUserAuditType, name, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, "GET, PATCH, DELETE")
		}
	})
}
