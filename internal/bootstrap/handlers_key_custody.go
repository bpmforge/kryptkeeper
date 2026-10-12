// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// W15-02: per-key custody evidence — backend, rotation history, and
// access events — from data the platform already holds. The
// regulatory driver is documented key custody; the append-only audit
// trail is the single source of custody truth (nothing reconstructable
// from the audit log is a bug, per the laws).

// KeyCustodyEntry is one key's custody facts.
type KeyCustodyEntry struct {
	KeyID          string `json:"key_id"`
	Algorithm      string `json:"algorithm"`
	CreatedAt      string `json:"created_at,omitempty"`
	RotationCount  int    `json:"rotation_count"`
	LastRotatedAt  string `json:"last_rotated_at,omitempty"`
	AccessCount    int    `json:"access_count"`
	LastAccessedAt string `json:"last_accessed_at,omitempty"`
}

// KeyCustodyReport is the whole-keystore custody evidence.
type KeyCustodyReport struct {
	GeneratedAt       string            `json:"generated_at"`
	Backend           string            `json:"backend"`
	DualControlEscrow bool              `json:"dual_control_escrow"`
	Keys              []KeyCustodyEntry `json:"keys"`
}

// keystoreBackendLabel maps the concrete store type to the custody
// boundary auditors ask about.
func keystoreBackendLabel(store keystore.Store) string {
	// Match by type NAME rather than concrete type: PKCS11Store is
	// build-tag-gated (//go:build pkcs11) and absent from the default
	// build, so a typed case would not compile.
	name := fmt.Sprintf("%T", store)
	switch {
	case strings.Contains(name, "SoftwareStore"):
		return "software"
	case strings.Contains(name, "PKCS11Store"):
		return "pkcs11-hsm"
	case strings.Contains(name, "VaultStore"):
		return "vault-transit"
	case strings.Contains(name, "CloudKMSStore"):
		return "cloud-kms"
	default:
		return name
	}
}

// keyUseActions are the audit actions that count as ACCESS to key
// material (a signing/get/export operation).
var keyUseActions = map[string]bool{"key.op": true, "key.get": true, "key.export": true}

// buildKeyCustodyReport assembles the report from the keystore and the
// append-only audit trail.
func buildKeyCustodyReport(ctx context.Context, store keystore.Store, auditProvider AuditProvider) (KeyCustodyReport, error) {
	metas, err := store.List()
	if err != nil {
		return KeyCustodyReport{}, err
	}
	report := KeyCustodyReport{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		Backend:           keystoreBackendLabel(store),
		DualControlEscrow: strings.TrimSpace(os.Getenv("APP_KEY_ESCROW_CUSTODIANS")) != "",
	}

	// One audit pass over key-resource events, grouped by key id.
	rotations := map[string]int{}
	lastRotation := map[string]string{}
	accesses := map[string]int{}
	lastAccess := map[string]string{}
	if auditProvider != nil {
		res, err := auditProvider.ListEntries(ctx, AuditListQuery{ResourceType: "key", Limit: 10000, Order: "asc"})
		if err == nil {
			for _, e := range res.Entries {
				id := e.ResourceID
				switch {
				case e.Action == "key.rotate":
					rotations[id]++
					lastRotation[id] = e.Timestamp
				case keyUseActions[e.Action]:
					accesses[id]++
					lastAccess[id] = e.Timestamp
				}
			}
		}
	}

	for _, m := range metas {
		report.Keys = append(report.Keys, KeyCustodyEntry{
			KeyID:          m.ID,
			Algorithm:      string(m.Algorithm),
			CreatedAt:      m.CreatedAt,
			RotationCount:  rotations[m.ID],
			LastRotatedAt:  lastRotation[m.ID],
			AccessCount:    accesses[m.ID],
			LastAccessedAt: lastAccess[m.ID],
		})
	}
	return report, nil
}

// registerKeyCustodyHandler mounts the custody evidence endpoint.
func registerKeyCustodyHandler(mux *http.ServeMux, auth *Authenticator, store keystore.Store, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/reports/key-custody", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.key_custody", "report", "key-custody", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "report.key_custody", "report", "key-custody", AuditOutcomeDenied)
			writeForbidden(w, "your role is not authorized to read key-custody evidence")
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "key-custody evidence requires a keystore (none configured)")
			return
		}
		report, err := buildKeyCustodyReport(r.Context(), store, auditProvider)
		if err != nil {
			writeServiceUnavailable(w, "key-custody report failed")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "report.key_custody", "report", "key-custody", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Data KeyCustodyReport `json:"data"`
		}{Data: report})
	})
}
