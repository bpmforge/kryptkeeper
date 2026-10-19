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
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/acme"
)

// SealSecret and OpenSecret expose the credential-store envelope (Argon2id +
// AES-GCM) to the ACME EAB store, which needs the raw HMAC key back to verify
// bindings and so cannot hash it.
func SealSecret(passphrase, plaintext []byte) (string, error) {
	return sealEnvelope(passphrase, plaintext)
}

// OpenSecret reverses SealSecret.
func OpenSecret(passphrase []byte, sealed string) ([]byte, error) {
	return openEnvelope(passphrase, sealed)
}

// CredentialStorePassphraseFromEnv is the passphrase sealed secrets use
// (APP_CREDENTIAL_STORE_PASSPHRASE, else KRYPTKEEPER_KEYSTORE_PASSPHRASE).
func CredentialStorePassphraseFromEnv() []byte { return outboundCredentialPassphraseFromEnv() }

var (
	eabProvisionerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	eabTemplatePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

const acmeEABResource = "acme_eab"

// ACMEEABOptions configures RegisterACMEEABHandlers.
type ACMEEABOptions struct {
	// Passphrase seals minted MAC keys; empty makes POST answer 503.
	Passphrase []byte
	// ProvisionerExists, when non-nil, must accept a bound provisioner name.
	ProvisionerExists func(name string) bool
}

type acmeEABKeyView struct {
	KID         string     `json:"kid"`
	Label       string     `json:"label"`
	Provisioner string     `json:"provisioner"`
	TemplateID  string     `json:"template_id"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	Uses        int        `json:"uses"`
}

// RegisterACMEEABHandlers mounts the ACME EAB credential API (W26-01):
// POST /api/v1/acme/eab-keys mints a key (hmac_key appears only in that 201),
// GET lists them without key material, DELETE /api/v1/acme/eab-keys/{kid}
// revokes one. pki-admin only.
func RegisterACMEEABHandlers(mux *http.ServeMux, auth *Authenticator, store acme.EABAdmin, opts ACMEEABOptions, auditProvider AuditProvider) {
	if store == nil {
		return
	}
	authorize := func(w http.ResponseWriter, r *http.Request, action, resID string) (string, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, acmeEABResource, resID, AuditOutcomeDenied)
			writeUnauthorized(w)
			return "", false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, acmeEABResource, resID, AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required for ACME EAB credentials")
			return "", false
		}
		// EAB keys gate the one instance-wide ACME endpoint.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, acmeEABResource, resID) {
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
			logging.Infof("acme eab response: %v", err)
		}
	}

	mux.HandleFunc("/api/v1/acme/eab-keys", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "acme.eab.list", "-"); !ok {
				return
			}
			list, err := store.List(r.Context())
			if err != nil {
				logging.Infof("acme eab list: %v", err)
				writeServiceUnavailable(w, "acme eab keys unavailable")
				return
			}
			views := make([]acmeEABKeyView, 0, len(list))
			for _, k := range list {
				views = append(views, acmeEABKeyView{KID: k.KID, Label: k.Label, Provisioner: k.Provisioner, TemplateID: k.TemplateID,
					CreatedBy: k.CreatedBy, CreatedAt: k.CreatedAt, RevokedAt: k.RevokedAt, LastUsedAt: k.LastUsedAt, Uses: k.Uses})
			}
			writeData(w, http.StatusOK, views)
		case http.MethodPost:
			principal, ok := authorize(w, r, "acme.eab.create", "-")
			if !ok {
				return
			}
			var req struct {
				Label       string `json:"label"`
				Provisioner string `json:"provisioner"`
				TemplateID  string `json:"template_id"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal, "acme.eab.create", acmeEABResource, "-", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			req.Label, req.Provisioner, req.TemplateID = strings.TrimSpace(req.Label), strings.TrimSpace(req.Provisioner), strings.TrimSpace(req.TemplateID)
			if msg := validateACMEEABRequest(req.Label, req.Provisioner, req.TemplateID, opts.ProvisionerExists); msg != "" {
				emitAuditEventDetail(r, auditProvider, principal, "acme.eab.create", acmeEABResource, "-", AuditOutcomeFailure, msg)
				writeBadRequest(w, msg)
				return
			}
			if len(opts.Passphrase) == 0 {
				emitAuditEventDetail(r, auditProvider, principal, "acme.eab.create", acmeEABResource, "-", AuditOutcomeFailure, "no credential store passphrase")
				writeServiceUnavailable(w, "acme eab minting needs a credential store passphrase")
				return
			}
			kid, secret, sealed, err := mintACMEEAB(opts.Passphrase)
			if err != nil {
				logging.Infof("acme eab mint: %v", err)
				emitAuditEvent(r, auditProvider, principal, "acme.eab.create", acmeEABResource, "-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "acme eab keys unavailable")
				return
			}
			now := time.Now().UTC().Truncate(time.Second)
			key := acme.EABAdminKey{KID: kid, Label: req.Label, Provisioner: req.Provisioner, TemplateID: req.TemplateID, CreatedBy: principal, CreatedAt: now}
			if err := store.Create(r.Context(), key, sealed); err != nil {
				logging.Infof("acme eab create: %v", err)
				emitAuditEvent(r, auditProvider, principal, "acme.eab.create", acmeEABResource, kid, AuditOutcomeFailure)
				writeServiceUnavailable(w, "acme eab keys unavailable")
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, "acme.eab.create", acmeEABResource, kid, AuditOutcomeSuccess, req.Label)
			// hmac_key is in this response and nowhere else.
			writeData(w, http.StatusCreated, struct {
				KID         string    `json:"kid"`
				HMACKey     string    `json:"hmac_key"`
				Label       string    `json:"label"`
				Provisioner string    `json:"provisioner"`
				TemplateID  string    `json:"template_id"`
				CreatedAt   time.Time `json:"created_at"`
			}{kid, secret, req.Label, req.Provisioner, req.TemplateID, now})
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/acme/eab-keys/", func(w http.ResponseWriter, r *http.Request) {
		kid := strings.TrimPrefix(r.URL.Path, "/api/v1/acme/eab-keys/")
		if kid == "" || strings.Contains(kid, "/") {
			emitAuditEvent(r, auditProvider, "", "acme.eab.revoke", acmeEABResource, "-", AuditOutcomeFailure)
			writeNotFound(w, "acme eab key not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		principal, ok := authorize(w, r, "acme.eab.revoke", kid)
		if !ok {
			return
		}
		err := store.Revoke(r.Context(), kid, time.Now().UTC())
		switch {
		case err == nil:
			emitAuditEvent(r, auditProvider, principal, "acme.eab.revoke", acmeEABResource, kid, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, acme.ErrEABNotFound):
			emitAuditEvent(r, auditProvider, principal, "acme.eab.revoke", acmeEABResource, kid, AuditOutcomeFailure)
			writeNotFound(w, "acme eab key not found")
		case errors.Is(err, acme.ErrEABAlreadyRevoked):
			emitAuditEvent(r, auditProvider, principal, "acme.eab.revoke", acmeEABResource, kid, AuditOutcomeFailure)
			writeConflict(w, "acme eab key already revoked")
		default:
			logging.Infof("acme eab revoke: %v", err)
			emitAuditEvent(r, auditProvider, principal, "acme.eab.revoke", acmeEABResource, kid, AuditOutcomeFailure)
			writeServiceUnavailable(w, "acme eab keys unavailable")
		}
	})
}

// validateACMEEABRequest returns a user-facing message, or "" when valid.
func validateACMEEABRequest(label, provisioner, templateID string, exists func(string) bool) string {
	switch {
	case len(label) > 200:
		return "label must be at most 200 characters"
	case provisioner != "" && !eabProvisionerPattern.MatchString(provisioner):
		return "provisioner must be lowercase letters, digits and hyphens (at most 63 characters)"
	case provisioner != "" && exists != nil && !exists(provisioner):
		return "unknown provisioner"
	case templateID != "" && !eabTemplatePattern.MatchString(templateID):
		return "template_id has an invalid format"
	}
	return ""
}

// mintACMEEAB returns a new kid, its base64url (unpadded) HMAC key as
// certbot --eab-hmac-key and lego --hmac take it, and the sealed key.
func mintACMEEAB(passphrase []byte) (kid, secret, sealed string, err error) {
	raw := make([]byte, 32+10)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", err
	}
	mac, id := raw[:32], raw[32:]
	sealed, err = sealEnvelope(passphrase, mac)
	if err != nil {
		return "", "", "", err
	}
	return "kk-eab-" + hex.EncodeToString(id), base64.RawURLEncoding.EncodeToString(mac), sealed, nil
}
