// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/cmp"
)

const (
	cmpCredentialResource   = "cmp_credential"
	cmpCredentialMaxBody    = 32 * 1024
	cmpAnchorMaxPEM         = 8 * 1024
	cmpCredentialMaxSuffix  = 20
	cmpCredentialMaxLabelen = 200
)

type cmpCredentialView struct {
	ID                 string     `json:"id"`
	Kind               string     `json:"kind"`
	Label              string     `json:"label"`
	Reference          string     `json:"reference,omitempty"`
	CertSHA256         string     `json:"cert_sha256,omitempty"`
	Enforced           *bool      `json:"enforced,omitempty"`
	AllowedDNSSuffixes []string   `json:"allowed_dns_suffixes"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	RotatedAt          *time.Time `json:"rotated_at"`
	RevokedAt          *time.Time `json:"revoked_at"`
	LastUsedAt         *time.Time `json:"last_used_at"`
}

// RegisterCMPCredentialHandlers mounts the CMP credential API (W26-09):
// POST /api/v1/cmp/credentials mints a PBM secret (shown only in that 201) or
// registers a trust anchor, GET lists without secret material, POST
// .../{id}/rotate mints a replacement secret, DELETE .../{id} revokes.
// pki-admin only. passphrase supplies the key that seals secrets; empty makes
// minting answer 503.
//
// A revoked or rotated-away secret stops working at once on the node that
// handled the call and within 30 seconds on other nodes (the CMP server
// caches unsealed secrets that long). Trust anchors are stored but not yet
// used to verify messages; every anchor view says enforced:false.
func RegisterCMPCredentialHandlers(mux *http.ServeMux, auth *Authenticator, store cmp.CredentialStore, passphrase func() []byte, auditProvider AuditProvider) {
	if store == nil {
		return
	}
	authorize := func(w http.ResponseWriter, r *http.Request, action, resID string) (string, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, cmpCredentialResource, resID, AuditOutcomeDenied)
			writeUnauthorized(w)
			return "", false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, cmpCredentialResource, resID, AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required for CMP credentials")
			return "", false
		}
		// CMP is one instance-wide endpoint.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, cmpCredentialResource, resID) {
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
			logging.Infof("cmp credential response: %v", err)
		}
	}
	unavailable := func(w http.ResponseWriter, r *http.Request, principal, action, resID string, err error) {
		logging.Infof("%s: %v", action, err)
		emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, resID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "cmp credentials unavailable")
	}
	view := func(c cmp.Credential) cmpCredentialView {
		v := cmpCredentialView{ID: c.ID, Kind: c.Kind, Label: c.Label, Reference: c.SenderKID, CertSHA256: c.CertSHA256,
			AllowedDNSSuffixes: c.AllowedDNSSuffixes, CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt,
			RotatedAt: c.RotatedAt, RevokedAt: c.RevokedAt, LastUsedAt: c.LastUsedAt}
		if v.AllowedDNSSuffixes == nil {
			v.AllowedDNSSuffixes = []string{}
		}
		if c.Kind == cmp.KindTrustAnchor {
			no := false
			v.Enforced = &no
		}
		return v
	}

	mux.HandleFunc("/api/v1/cmp/credentials", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "cmp.credential.list", "-"); !ok {
				return
			}
			list, err := store.List(r.Context())
			if err != nil {
				logging.Infof("cmp credential list: %v", err)
				writeServiceUnavailable(w, "cmp credentials unavailable")
				return
			}
			views := make([]cmpCredentialView, 0, len(list))
			for _, c := range list {
				views = append(views, view(c))
			}
			writeData(w, http.StatusOK, views)
		case http.MethodPost:
			const action = "cmp.credential.create"
			principal, ok := authorize(w, r, action, "-")
			if !ok {
				return
			}
			var req struct {
				Kind        string   `json:"kind"`
				Label       string   `json:"label"`
				Suffixes    []string `json:"allowed_dns_suffixes"`
				Certificate string   `json:"certificate_pem"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, cmpCredentialMaxBody)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, "-", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			req.Label = strings.TrimSpace(req.Label)
			fail := func(msg string) {
				emitAuditEventDetail(r, auditProvider, principal, action, cmpCredentialResource, "-", AuditOutcomeFailure, "kind="+req.Kind+" "+msg)
				writeBadRequest(w, msg)
			}
			if len(req.Label) > cmpCredentialMaxLabelen {
				fail("label must be at most 200 characters")
				return
			}
			switch req.Kind {
			case cmp.KindPBM:
				createCMPPBM(w, r, store, passphrase, principal, req.Label, req.Suffixes, fail, auditProvider, writeData)
			case cmp.KindTrustAnchor:
				createCMPAnchor(w, r, store, principal, req.Label, req.Certificate, fail, auditProvider, writeData)
			default:
				fail(`kind must be "pbm" or "trust_anchor"`)
			}
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/cmp/credentials/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/cmp/credentials/")
		id, sub, _ := strings.Cut(rest, "/")
		switch {
		case id != "" && sub == "" && r.Method == http.MethodDelete:
			const action = "cmp.credential.revoke"
			principal, ok := authorize(w, r, action, id)
			if !ok {
				return
			}
			c, _ := store.Get(r.Context(), id) // detail only; Revoke reports a missing id
			err := store.Revoke(r.Context(), id, time.Now().UTC())
			switch {
			case err == nil:
				emitAuditEventDetail(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeSuccess, cmpCredentialDetail(c))
				w.WriteHeader(http.StatusNoContent)
			case errors.Is(err, cmp.ErrCredentialNotFound):
				emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure)
				writeNotFound(w, "cmp credential not found")
			case errors.Is(err, cmp.ErrAlreadyRevoked):
				emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure)
				writeConflict(w, "cmp credential already revoked")
			default:
				unavailable(w, r, principal, action, id, err)
			}
		case id != "" && sub == "rotate" && r.Method == http.MethodPost:
			const action = "cmp.credential.rotate"
			principal, ok := authorize(w, r, action, id)
			if !ok {
				return
			}
			pass := passphrase()
			if len(pass) == 0 {
				emitAuditEventDetail(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure, "no credential store passphrase")
				writeServiceUnavailable(w, "cmp secret minting needs a credential store passphrase")
				return
			}
			c, err := store.Get(r.Context(), id)
			if err != nil {
				if errors.Is(err, cmp.ErrCredentialNotFound) {
					emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure)
					writeNotFound(w, "cmp credential not found")
					return
				}
				unavailable(w, r, principal, action, id, err)
				return
			}
			secret, sealed, err := mintCMPSecret(pass)
			if err != nil {
				unavailable(w, r, principal, action, id, err)
				return
			}
			now := time.Now().UTC().Truncate(time.Second)
			switch err := store.Rotate(r.Context(), id, sealed, now); {
			case err == nil:
				emitAuditEventDetail(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeSuccess, cmpCredentialDetail(c))
				writeData(w, http.StatusOK, struct {
					ID        string    `json:"id"`
					Reference string    `json:"reference"`
					Secret    string    `json:"secret"`
					RotatedAt time.Time `json:"rotated_at"`
				}{id, c.SenderKID, secret, now})
			case errors.Is(err, cmp.ErrCredentialNotFound):
				emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure)
				writeNotFound(w, "cmp credential not found")
			case errors.Is(err, cmp.ErrNotPBM):
				emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure)
				writeBadRequest(w, "only PBM secrets can be rotated")
			case errors.Is(err, cmp.ErrAlreadyRevoked):
				emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure)
				writeConflict(w, "cmp credential already revoked")
			default:
				unavailable(w, r, principal, action, id, err)
			}
		case id == "" || (sub != "" && sub != "rotate"):
			emitAuditEvent(r, auditProvider, "", "cmp.credential.revoke", cmpCredentialResource, "-", AuditOutcomeFailure)
			writeNotFound(w, "cmp credential not found")
		default:
			if sub == "rotate" {
				writeMethodNotAllowed(w, http.MethodPost)
			} else {
				writeMethodNotAllowed(w, http.MethodDelete)
			}
		}
	})
}

// cmpCredentialDetail is the audit detail: kind, label and reference, never
// a secret.
func cmpCredentialDetail(c cmp.Credential) string {
	d := "kind=" + c.Kind + " label=" + c.Label
	if c.SenderKID != "" {
		d += " reference=" + c.SenderKID
	}
	return d
}

func createCMPPBM(w http.ResponseWriter, r *http.Request, store cmp.CredentialStore, passphrase func() []byte, principal, label string,
	suffixes []string, fail func(string), auditProvider AuditProvider, writeData func(http.ResponseWriter, int, any)) {
	const action = "cmp.credential.create"
	clean := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		if s = strings.TrimSpace(s); s != "" {
			clean = append(clean, s)
		}
	}
	if len(clean) > cmpCredentialMaxSuffix {
		fail("at most 20 allowed_dns_suffixes")
		return
	}
	if err := (&ca.NamePolicy{AllowedDNSSuffixes: clean}).Validate(); err != nil {
		fail("invalid allowed_dns_suffixes: " + err.Error())
		return
	}
	pass := passphrase()
	if len(pass) == 0 {
		emitAuditEventDetail(r, auditProvider, principal, action, cmpCredentialResource, "-", AuditOutcomeFailure, "no credential store passphrase")
		writeServiceUnavailable(w, "cmp secret minting needs a credential store passphrase")
		return
	}
	secret, sealed, err := mintCMPSecret(pass)
	idRaw := make([]byte, 6+12)
	if err == nil {
		_, err = rand.Read(idRaw)
	}
	if err != nil {
		logging.Infof("cmp credential mint: %v", err)
		emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, "-", AuditOutcomeFailure)
		writeServiceUnavailable(w, "cmp credentials unavailable")
		return
	}
	reference := "kk-cmp-" + hex.EncodeToString(idRaw[:6])
	id := "cmpc-" + hex.EncodeToString(idRaw[6:])
	now := time.Now().UTC().Truncate(time.Second)
	c := cmp.Credential{ID: id, Kind: cmp.KindPBM, Label: label, SenderKID: reference, AllowedDNSSuffixes: clean, CreatedBy: principal, CreatedAt: now}
	if err := store.CreatePBM(r.Context(), c, sealed); err != nil {
		logging.Infof("cmp credential create: %v", err)
		emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "cmp credentials unavailable")
		return
	}
	emitAuditEventDetail(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeSuccess, cmpCredentialDetail(c))
	// secret is in this response and nowhere else.
	writeData(w, http.StatusCreated, struct {
		ID                 string    `json:"id"`
		Kind               string    `json:"kind"`
		Label              string    `json:"label"`
		Reference          string    `json:"reference"`
		Secret             string    `json:"secret"`
		AllowedDNSSuffixes []string  `json:"allowed_dns_suffixes"`
		CreatedAt          time.Time `json:"created_at"`
	}{id, cmp.KindPBM, label, reference, secret, clean, now})
}

func createCMPAnchor(w http.ResponseWriter, r *http.Request, store cmp.CredentialStore, principal, label, certPEM string,
	fail func(string), auditProvider AuditProvider, writeData func(http.ResponseWriter, int, any)) {
	const action = "cmp.credential.create"
	if len(certPEM) > cmpAnchorMaxPEM {
		fail("certificate_pem must be at most 8 KiB")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	cert, fingerprint, err := cmp.ParseAnchorPEM(certPEM, now)
	if err != nil {
		fail(err.Error())
		return
	}
	idRaw := make([]byte, 12)
	if _, err := rand.Read(idRaw); err != nil {
		logging.Infof("cmp credential id: %v", err)
		emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, "-", AuditOutcomeFailure)
		writeServiceUnavailable(w, "cmp credentials unavailable")
		return
	}
	id := "cmpc-" + hex.EncodeToString(idRaw)
	c := cmp.Credential{ID: id, Kind: cmp.KindTrustAnchor, Label: label, CertSHA256: fingerprint, CreatedBy: principal, CreatedAt: now}
	switch err := store.RegisterAnchor(r.Context(), c, certPEM); {
	case err == nil:
	case errors.Is(err, cmp.ErrDuplicateAnchor):
		emitAuditEventDetail(r, auditProvider, principal, action, cmpCredentialResource, "-", AuditOutcomeFailure, "kind=trust_anchor duplicate sha256="+fingerprint)
		writeConflict(w, "trust anchor already registered")
		return
	default:
		logging.Infof("cmp anchor register: %v", err)
		emitAuditEvent(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "cmp credentials unavailable")
		return
	}
	emitAuditEventDetail(r, auditProvider, principal, action, cmpCredentialResource, id, AuditOutcomeSuccess, cmpCredentialDetail(c)+" sha256="+fingerprint)
	writeData(w, http.StatusCreated, struct {
		ID         string    `json:"id"`
		Kind       string    `json:"kind"`
		Label      string    `json:"label"`
		Subject    string    `json:"subject"`
		NotAfter   time.Time `json:"not_after"`
		CertSHA256 string    `json:"cert_sha256"`
		Enforced   bool      `json:"enforced"`
		CreatedAt  time.Time `json:"created_at"`
	}{id, cmp.KindTrustAnchor, label, cert.Subject.String(), cert.NotAfter.UTC(), fingerprint, false, now})
}

// mintCMPSecret returns a 24-character base64url secret (what openssl takes as
// -secret pass:) and its sealed form.
func mintCMPSecret(passphrase []byte) (secret, sealed string, err error) {
	raw := make([]byte, 18)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	sealed, err = sealEnvelope(passphrase, []byte(secret))
	if err != nil {
		return "", "", err
	}
	return secret, sealed, nil
}
