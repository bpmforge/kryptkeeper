// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"kryptkeeper/internal/logging"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

// caEffectiveStatus derives the status a CA should present from its
// certificate's actual validity rather than trusting the stored "status"
// column verbatim (S-43). A CA stays "active" in storage even after its own
// certificate expires -- nothing recomputes it -- so it keeps advertising
// itself as healthy indefinitely, and CA Health ends up rendering a green
// "active" badge beside a red "Expired" column for the same row. Any other
// stored status (suspended, revoked, ...) already does not present as
// active and is left untouched, as is a CA with no certificate on file
// (nothing to derive from) or an unparsable validity window. This is a
// read-time projection, not a persisted transition: the stored column is
// left alone so the distinction between "was active, expired in place" and
// "was explicitly suspended/revoked" survives in the underlying record.
func caEffectiveStatus(item CAListItem, now time.Time) string {
	if item.Status != "active" || item.Certificate == nil {
		return item.Status
	}
	validUntil, err := time.Parse(time.RFC3339, item.Certificate.ValidUntil)
	if err != nil {
		return item.Status
	}
	if validUntil.Before(now) {
		return "expired"
	}
	return item.Status
}

// withCAEffectiveStatus returns item with Status overwritten per
// caEffectiveStatus.
func withCAEffectiveStatus(item CAListItem, now time.Time) CAListItem {
	item.Status = caEffectiveStatus(item, now)
	return item
}

func registerCAHandlers(mux *http.ServeMux, auth *Authenticator, caProvider CAProvider, tenantStore TenantStore, auditProvider AuditProvider) {
	dualControl := NewKeyDualControlFromEnv(NewPendingActionStoreFromEnv())

	// W23-03: import an external self-signed root as a keyless trust anchor,
	// behind D-122 dual control. Registered with an exact pattern so it wins
	// over the /api/v1/cas/ subtree below.
	mux.HandleFunc("/api/v1/cas/import", func(w http.ResponseWriter, r *http.Request) {
		handleCAImport(w, r, auth, caProvider, tenantStore, auditProvider, dualControl)
	})

	mux.HandleFunc("/api/v1/cas", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "ca.list", "ca", "cas", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		if r.Method == http.MethodPost {
			var req CACreateRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.create", "ca", "cas", AuditOutcomeFailure)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}
			if req.SubjectCN == "" {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.create", "ca", "cas", AuditOutcomeFailure)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"subject_cn is required"}`))
				return
			}
			// L-07: signing under another tenant's (or the default) CA would
			// mint a sub-CA from a key the caller does not own.
			if req.ParentCAID != "" && !caVisibleToTenant(r.Context(), tenantStore, pd, req.ParentCAID) {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.create", "ca", "cas", AuditOutcomeDenied)
				writeForbidden(w, "parent certificate authority is not visible in your tenant")
				return
			}
			if !tenantBypass(pd) && tenantStore != nil {
				exists, terr := tenantStore.TenantExists(r.Context(), pd.Tenant)
				if terr != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.create", "ca", "cas", AuditOutcomeFailure)
					writeServiceUnavailable(w, "tenant lookup failed")
					return
				}
				if !exists {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.create", "ca", "cas", AuditOutcomeDenied)
					writeBadRequest(w, "unknown tenant")
					return
				}
			}
			created, err := caProvider.CreateCA(r.Context(), req)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.create", "ca", "cas", AuditOutcomeFailure)
				logging.Warnf("ca create failed: %v", err)
				w.Header().Set("Content-Type", "application/json")
				if errors.Is(err, errUnsupportedCAAlgorithm) {
					w.WriteHeader(http.StatusBadRequest)
					body, _ := json.Marshal(map[string]any{"error": "bad_request", "message": err.Error(), "supported_algorithms": caSupportedAlgorithms})
					_, _ = w.Write(body)
					return
				}
				w.WriteHeader(http.StatusUnprocessableEntity)
				body, _ := json.Marshal(map[string]string{"error": "unprocessable_entity", "message": err.Error()})
				_, _ = w.Write(body)
				return
			}
			created = withCAEffectiveStatus(created, time.Now().UTC())
			if !tenantBypass(pd) && pd.Tenant != DefaultTenant && tenantStore != nil {
				if merr := tenantStore.SetCATenant(r.Context(), created.ID, pd.Tenant); merr != nil {
					logging.Warnf("auto-map ca %s to tenant %s failed: %v", created.ID, pd.Tenant, merr)
				}
			}
			caSummary := fmt.Sprintf(`{"name":%q,"type":%q,"algorithm":%q,"subject_cn":%q}`,
				req.Name, req.Type, req.Algorithm, req.SubjectCN)
			createAction := "ca.create"
			if created.Status == ca.CAStatusPendingCertificate {
				createAction = "ca.csr_generate" // key generated, CSR issued, awaiting the offline-signed certificate
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, createAction, "ca", created.ID, AuditOutcomeSuccess, caSummary)
			resp := struct {
				Data CAListItem `json:"data"`
			}{Data: created}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode /api/v1/cas POST response: %v", err)
			}
			return
		}

		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}

		query := CAListQuery{
			Limit:  parseCALimit(r.URL.Query().Get("limit"), 25),
			Offset: parseCAOffset(r.URL.Query().Get("cursor")),
			Type:   strings.TrimSpace(r.URL.Query().Get("type")),
			Status: strings.TrimSpace(r.URL.Query().Get("status")),
		}

		// L-20: for a tenant-scoped caller, filter the whole set first so
		// total and next_cursor describe only their rows.
		caScoped := tenantStore != nil && !tenantBypass(pd)
		var result CAListResult
		if caScoped {
			result, err = listCAsTenantFiltered(r.Context(), caProvider, tenantStore, pd, query)
		} else {
			result, err = caProvider.ListCAs(r.Context(), query)
		}
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "ca.list", "ca", "cas", AuditOutcomeFailure)
			logging.Warnf("ca list unavailable: %v", err)
			writeServiceUnavailable(w, "ca list unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "ca.list", "ca", "cas", AuditOutcomeSuccess)

		// v2.2: scope CAs to the caller's tenant (no-op unless MULTI_TENANCY on).
		if !caScoped {
			result.Items = filterCAsByTenant(r.Context(), tenantStore, pd, result.Items)
		}

		// S-43: recompute each item's presented status from certificate
		// validity before it ever reaches a caller. fetchedCount is captured
		// before the re-filter below so cursor math (which mirrors
		// result.Total, itself computed by the provider against the stored
		// "status" column) is unaffected by it -- pagination stays keyed to
		// the provider's stored-status count until that count is itself
		// derivation-aware (out of this ticket's write_scope; see S-51).
		now := time.Now().UTC()
		fetchedCount := len(result.Items)
		for i := range result.Items {
			result.Items[i] = withCAEffectiveStatus(result.Items[i], now)
			// W19-01: CertificatePEM exists on CAListItem so /cas/{id}/chain
			// has real certificate bytes to serve (see ca_engine_provider.go)
			// -- it isn't part of this endpoint's documented response shape
			// in docs/openapi.yaml and has no reason to ride along on every
			// list/get call, so it's stripped here rather than expanding
			// this endpoint's contract for a field only the chain export needs.
			result.Items[i].CertificatePEM = ""
		}
		if query.Status != "" {
			kept := result.Items[:0]
			for _, item := range result.Items {
				if item.Status == query.Status {
					kept = append(kept, item)
				}
			}
			result.Items = kept
		}

		resp := struct {
			Data []CAListItem `json:"data"`
			Meta struct {
				Total      int     `json:"total"`
				Limit      int     `json:"limit"`
				NextCursor *string `json:"next_cursor"`
				PrevCursor *string `json:"prev_cursor"`
			} `json:"meta"`
		}{
			Data: result.Items,
		}
		resp.Meta.Total = result.Total
		resp.Meta.Limit = result.Limit
		nextOffset := query.Offset + fetchedCount
		if nextOffset < result.Total {
			next := strconv.Itoa(nextOffset)
			resp.Meta.NextCursor = &next
		}
		if query.Offset > 0 {
			prevOffset := query.Offset - query.Limit
			if prevOffset < 0 {
				prevOffset = 0
			}
			prev := strconv.Itoa(prevOffset)
			resp.Meta.PrevCursor = &prev
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/cas response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/cas/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "ca.get", "ca", "ca-id", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/cas/")
		if tail == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "ca.get", "ca", "", AuditOutcomeFailure)
			writeNotFound(w, "ca not found")
			return
		}

		if strings.HasSuffix(tail, "/certificate") {
			handleCAComplete(w, r, caProvider, tenantStore, auditProvider, pd, strings.TrimSuffix(tail, "/certificate"))
			return
		}

		if strings.HasSuffix(tail, "/suspend") {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			id := strings.TrimSuffix(tail, "/suspend")
			if id == "" || strings.Contains(id, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.suspend", "ca", id, AuditOutcomeFailure)
				writeNotFound(w, "ca not found")
				return
			}
			if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.suspend", "ca", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}

			change, err := caProvider.SuspendCA(r.Context(), id)
			if err != nil {
				if err == errCANotFound {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.suspend", "ca", id, AuditOutcomeFailure)
					writeNotFound(w, "ca not found")
					return
				}
				if err == errCAConflict {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.suspend", "ca", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"ca state conflict"}`))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "ca.suspend", "ca", id, AuditOutcomeFailure)
				logging.Warnf("ca suspend unavailable: %v", err)
				writeServiceUnavailable(w, "ca unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "ca.suspend", "ca", id, AuditOutcomeSuccess)

			resp := struct {
				Data CAStatusChange `json:"data"`
			}{Data: change}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode /api/v1/cas/{id}/suspend response: %v", err)
			}
			return
		}

		if strings.HasSuffix(tail, "/activate") {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			id := strings.TrimSuffix(tail, "/activate")
			if id == "" || strings.Contains(id, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.activate", "ca", id, AuditOutcomeFailure)
				writeNotFound(w, "ca not found")
				return
			}
			if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.activate", "ca", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}

			change, err := caProvider.ActivateCA(r.Context(), id)
			if err != nil {
				if err == errCANotFound {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.activate", "ca", id, AuditOutcomeFailure)
					writeNotFound(w, "ca not found")
					return
				}
				if err == errCAConflict {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.activate", "ca", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"ca state conflict"}`))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "ca.activate", "ca", id, AuditOutcomeFailure)
				logging.Warnf("ca activate unavailable: %v", err)
				writeServiceUnavailable(w, "ca unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "ca.activate", "ca", id, AuditOutcomeSuccess)

			resp := struct {
				Data CAStatusChange `json:"data"`
			}{Data: change}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode /api/v1/cas/{id}/activate response: %v", err)
			}
			return
		}

		if strings.HasSuffix(tail, "/revoke") {
			handleCARevoke(w, r, caProvider, tenantStore, auditProvider, dualControl, pd, strings.TrimSuffix(tail, "/revoke"))
			return
		}

		if strings.HasSuffix(tail, "/rotate-key") {
			// Re-keying a CA is more consequential than any other CA
			// mutation (it generates new key material and re-issues the
			// CA's own certificate) -- gated on BOTH tenant visibility
			// (this handler group's existing convention) AND admin role
			// (matching handlers_keys.go's admin-only gating for every
			// other key-management operation), a deliberate, stricter
			// combination for this one route rather than silently picking
			// just one convention (W9-04/G-35 ticket notes).
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			id := strings.TrimSuffix(tail, "/rotate-key")
			if id == "" || strings.Contains(id, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
				writeNotFound(w, "ca not found")
				return
			}
			if !isAdminRole(pd.Role) {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeDenied)
				writeForbidden(w, "admin role required for CA key rotation")
				return
			}
			if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}

			mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
			if mode != "" && mode != "rekey" && mode != "cross-sign" {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
				writeBadRequest(w, "mode must be rekey or cross-sign")
				return
			}
			rotator, rotatorOK := caProvider.(CARotator)
			rollover, rolloverOK := caProvider.(CARolloverRotator)
			if (mode == "cross-sign" && !rolloverOK) || (mode != "cross-sign" && !rotatorOK) {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
				if mode == "cross-sign" {
					writeServiceUnavailable(w, "ca key rollover not supported by this provider")
				} else {
					writeServiceUnavailable(w, "ca key rotation not supported by this provider")
				}
				return
			}

			var req struct {
				Algorithm        string `json:"algorithm"`
				ApprovedActionID string `json:"approved_action_id"`
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4*1024))
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			if len(strings.TrimSpace(string(body))) > 0 {
				if err := json.Unmarshal(body, &req); err != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
					writeBadRequest(w, "invalid request body")
					return
				}
			}

			// W23-15: re-keying a CA is dual-controlled. The grant is bound to
			// mode+algorithm so the proposer cannot swap a cross-sign for a
			// plain re-key, or change the algorithm, after the approver signed off.
			sum := sha256.Sum256([]byte("mode=" + mode + ";algorithm=" + strings.ToLower(strings.TrimSpace(req.Algorithm))))
			if !dualControl.gate(w, r, auth, auditProvider, pd, egressGate{
				actionType: keyActionCARotate, keyID: id, bundleSHA256: hex.EncodeToString(sum[:]),
				approvedID: req.ApprovedActionID, auditAction: "ca.rotate_key",
				message: "dual control is on - after approval, retry with approved_action_id",
			}) {
				return
			}

			if mode == "cross-sign" {
				out, err := rollover.RolloverCAKey(r.Context(), id, req.Algorithm)
				if err != nil {
					if errors.Is(err, errCARotationRolledBack) {
						writeRotationRolledBack(w, r, auditProvider, pd.ID, id, err)
						return
					}
					emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
					if err == errCANotFound {
						writeNotFound(w, "ca not found")
						return
					}
					logging.Warnf("ca cross-sign rotate-key failed for %s: %v", id, err)
					writeServiceUnavailable(w, "ca key rollover failed")
					return
				}
				emitAuditEventDetail(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeSuccess,
					fmt.Sprintf(`{"mode":"cross-sign","ledger_id":%q}`, out.LedgerID))
				resp := struct {
					Data CAKeyRollover `json:"data"`
				}{Data: out}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					logging.Warnf("failed to encode /api/v1/cas/{id}/rotate-key response: %v", err)
				}
				return
			}

			result, err := rotator.RotateCAKey(r.Context(), id, req.Algorithm)
			if err != nil {
				if errors.Is(err, errCARotationRolledBack) {
					writeRotationRolledBack(w, r, auditProvider, pd.ID, id, err)
					return
				}
				if err == errCANotFound {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
					writeNotFound(w, "ca not found")
					return
				}
				if err == errCARotateUnsupported {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
					writeServiceUnavailable(w, "ca key rotation not supported by this provider")
					return
				}
				// result.ID is non-empty only when the key rotation and
				// certificate re-issuance already succeeded and were
				// persisted -- today the only such error case is a
				// ledger-write failure. The rotation is NOT failed: report
				// 200 with LedgerPersisted:false rather than 503, so
				// callers don't retry a rotation that already happened
				// (which would generate ANOTHER new key on an already-
				// rotated CA). Any other error here means the CA may be
				// left inconsistent (ca.ErrCARotationInconsistent) --
				// logged loudly and reported as a genuine 503 failure.
				if result.ID != "" {
					logging.Warnf("ca rotate-key for %s succeeded but the ledger write failed: %v", id, err)
					emitAuditEventDetail(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeSuccess,
						fmt.Sprintf(`{"ledger_id":%q,"ledger_persisted":false,"ledger_error":%q}`, result.LedgerID, err.Error()))
					resp := struct {
						Data CAKeyRotationResult `json:"data"`
					}{Data: result}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						logging.Warnf("failed to encode /api/v1/cas/{id}/rotate-key response: %v", err)
					}
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeFailure)
				logging.Warnf("ca rotate-key failed for %s (CA may now be inconsistent -- see docs/ops/DR_RUNBOOK.md): %v", id, err)
				writeServiceUnavailable(w, "ca key rotation failed")
				return
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, "ca.rotate_key", "ca", id, AuditOutcomeSuccess,
				fmt.Sprintf(`{"ledger_id":%q,"ledger_persisted":true}`, result.LedgerID))

			resp := struct {
				Data CAKeyRotationResult `json:"data"`
			}{Data: result}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode /api/v1/cas/{id}/rotate-key response: %v", err)
			}
			return
		}

		if r.Method != http.MethodGet {
			if r.Method == http.MethodPatch {
				id := tail
				if strings.Contains(id, "/") {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.update", "ca", id, AuditOutcomeFailure)
					writeNotFound(w, "ca not found")
					return
				}
				if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.update", "ca", id, AuditOutcomeDenied)
					writeForbidden(w, "forbidden")
					return
				}

				updateReq, err := parseCAUpdateRequest(r.Body)
				if err != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.update", "ca", id, AuditOutcomeFailure)
					if errors.Is(err, errCAImmutableField) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"error":"unprocessable_entity","message":"attempt to modify immutable field"}`))
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}

				updated, err := caProvider.UpdateCA(r.Context(), id, updateReq)
				if err != nil {
					if err == errCANotFound {
						emitAuditEvent(r, auditProvider, pd.ID, "ca.update", "ca", id, AuditOutcomeFailure)
						writeNotFound(w, "ca not found")
						return
					}
					if err == errCAImmutableField {
						emitAuditEvent(r, auditProvider, pd.ID, "ca.update", "ca", id, AuditOutcomeFailure)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"error":"unprocessable_entity","message":"attempt to modify immutable field"}`))
						return
					}
					if err == errCAInvalidUpdateFields {
						emitAuditEvent(r, auditProvider, pd.ID, "ca.update", "ca", id, AuditOutcomeFailure)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
						return
					}
					emitAuditEvent(r, auditProvider, pd.ID, "ca.update", "ca", id, AuditOutcomeFailure)
					logging.Warnf("ca update unavailable: %v", err)
					writeServiceUnavailable(w, "ca unavailable")
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "ca.update", "ca", id, AuditOutcomeSuccess)
				updated = withCAEffectiveStatus(updated, time.Now().UTC())

				resp := struct {
					Data CAListItem `json:"data"`
				}{Data: updated}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					logging.Warnf("failed to encode /api/v1/cas/{id} patch response: %v", err)
				}
				return
			}
			if r.Method == http.MethodDelete {
				id := tail
				if strings.Contains(id, "/") {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.delete", "ca", id, AuditOutcomeFailure)
					writeNotFound(w, "ca not found")
					return
				}
				if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.delete", "ca", id, AuditOutcomeDenied)
					writeForbidden(w, "forbidden")
					return
				}

				// A keyless imported root is soft-removed under dual control;
				// every other CA goes through the revoked/expired-only delete.
				if importer, ok := caProvider.(CAImporter); ok &&
					!errors.Is(importer.CheckTrustAnchorRemovable(r.Context(), id), ca.ErrNotTrustAnchor) {
					handleTrustAnchorRemoval(w, r, auth, importer, auditProvider, dualControl, pd, id)
					return
				}

				if !isAdminRole(pd.Role) {
					emitAuditEvent(r, auditProvider, pd.ID, "ca.delete", "ca", id, AuditOutcomeDenied)
					writeForbidden(w, "admin role required to delete a CA")
					return
				}
				err := caProvider.DeleteCA(r.Context(), id)
				if err != nil {
					if err == errCANotFound {
						emitAuditEvent(r, auditProvider, pd.ID, "ca.delete", "ca", id, AuditOutcomeFailure)
						writeNotFound(w, "ca not found")
						return
					}
					if err == errCAConflict {
						emitAuditEvent(r, auditProvider, pd.ID, "ca.delete", "ca", id, AuditOutcomeFailure)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusConflict)
						_, _ = w.Write([]byte(`{"error":"conflict","message":"ca has active certificates"}`))
						return
					}
					if err == errCAUnprocessable {
						emitAuditEvent(r, auditProvider, pd.ID, "ca.delete", "ca", id, AuditOutcomeFailure)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnprocessableEntity)
						_, _ = w.Write([]byte(`{"error":"unprocessable_entity","message":"ca must be revoked or expired before deletion"}`))
						return
					}
					emitAuditEvent(r, auditProvider, pd.ID, "ca.delete", "ca", id, AuditOutcomeFailure)
					logging.Warnf("ca delete unavailable: %v", err)
					writeServiceUnavailable(w, "ca unavailable")
					return
				}

				emitAuditEvent(r, auditProvider, pd.ID, "ca.delete", "ca", id, AuditOutcomeSuccess)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}

		if strings.HasSuffix(tail, "/csr") {
			handleCAGetCSR(w, r, caProvider, tenantStore, auditProvider, pd, strings.TrimSuffix(tail, "/csr"))
			return
		}

		if strings.HasSuffix(tail, "/chain") {
			id := strings.TrimSuffix(tail, "/chain")
			if id == "" || strings.Contains(id, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.chain.get", "ca", id, AuditOutcomeFailure)
				writeNotFound(w, "ca not found")
				return
			}
			if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.chain.get", "ca", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}

			chain, found, err := caProvider.GetCAChain(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.chain.get", "ca", id, AuditOutcomeFailure)
				logging.Warnf("ca chain unavailable: %v", err)
				writeServiceUnavailable(w, "ca chain unavailable")
				return
			}
			if !found || len(chain) == 0 {
				emitAuditEvent(r, auditProvider, pd.ID, "ca.chain.get", "ca", id, AuditOutcomeFailure)
				writeNotFound(w, "ca not found")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "ca.chain.get", "ca", id, AuditOutcomeSuccess)

			if strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) == "pem" {
				// W19-01: this used to wrap the SHA-256 fingerprint HEX STRING
				// in BEGIN/END CERTIFICATE markers -- a value that looks like
				// a PEM block but fails to base64-decode into anything, let
				// alone a certificate. No test caught it because every test
				// only checked for the "-----BEGIN CERTIFICATE-----" marker
				// substring, never that openssl/x509 could parse the body.
				// It surfaced live: a real ACME client's cert could not be
				// chain-verified against this endpoint's output. Emit the
				// real PEM bytes (CAListItem.CertificatePEM, threaded through
				// from ca.CA.CertPEM); skip any chain entry that has none
				// rather than fabricate a placeholder.
				blocks := make([]string, 0, len(chain))
				for _, item := range chain {
					if pem := strings.TrimSpace(item.CertificatePEM); pem != "" {
						blocks = append(blocks, pem)
					}
				}
				if len(blocks) == 0 {
					writeServiceUnavailable(w, "ca certificate pem unavailable")
					return
				}
				w.Header().Set("Content-Type", "application/x-pem-file")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(strings.Join(blocks, "\n")))
				return
			}

			type chainItem struct {
				Depth             int    `json:"depth"`
				FingerprintSHA256 string `json:"fingerprint_sha256"`
				SubjectDN         string `json:"subject_dn"`
				IssuerDN          string `json:"issuer_dn"`
				ValidFrom         string `json:"valid_from"`
				ValidUntil        string `json:"valid_until"`
			}

			items := make([]chainItem, 0, len(chain))
			for i, ca := range chain {
				subjectDN := ""
				validFrom := ""
				validUntil := ""
				fingerprint := ca.CertificateFingerprintSHA256
				if ca.Certificate != nil {
					if ca.Certificate.FingerprintSHA256 != "" {
						fingerprint = ca.Certificate.FingerprintSHA256
					}
					subjectDN = ca.Certificate.SubjectDN
					validFrom = ca.Certificate.ValidFrom
					validUntil = ca.Certificate.ValidUntil
				}
				issuerDN := subjectDN
				if i+1 < len(chain) && chain[i+1].Certificate != nil {
					issuerDN = chain[i+1].Certificate.SubjectDN
				}
				items = append(items, chainItem{Depth: i, FingerprintSHA256: fingerprint, SubjectDN: subjectDN, IssuerDN: issuerDN, ValidFrom: validFrom, ValidUntil: validUntil})
			}

			resp := struct {
				Data struct {
					CAID  string      `json:"ca_id"`
					Chain []chainItem `json:"chain"`
				} `json:"data"`
			}{}
			resp.Data.CAID = id
			resp.Data.Chain = items

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode /api/v1/cas/{id}/chain response: %v", err)
			}
			return
		}

		id := tail
		if strings.Contains(id, "/") {
			emitAuditEvent(r, auditProvider, pd.ID, "ca.get", "ca", id, AuditOutcomeFailure)
			writeNotFound(w, "ca not found")
			return
		}
		if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
			emitAuditEvent(r, auditProvider, pd.ID, "ca.get", "ca", id, AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		item, found, err := caProvider.GetCA(r.Context(), id)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "ca.get", "ca", id, AuditOutcomeFailure)
			logging.Warnf("ca get unavailable: %v", err)
			writeServiceUnavailable(w, "ca unavailable")
			return
		}
		if !found {
			emitAuditEvent(r, auditProvider, pd.ID, "ca.get", "ca", id, AuditOutcomeFailure)
			writeNotFound(w, "ca not found")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "ca.get", "ca", id, AuditOutcomeSuccess)
		item = withCAEffectiveStatus(item, time.Now().UTC())
		item.CertificatePEM = "" // see the matching comment in the /cas list handler above

		resp := struct {
			Data CAListItem `json:"data"`
		}{Data: item}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/cas/{id} response: %v", err)
		}
	})
}

func parseCAUpdateRequest(body io.Reader) (CAUpdateRequest, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return CAUpdateRequest{}, errCAInvalidUpdateFields
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return CAUpdateRequest{}, nil
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		return CAUpdateRequest{}, errCAInvalidUpdateFields
	}

	for key := range payload {
		switch key {
		case "display_name", "crl_distribution_points", "ocsp_service_url":
			// mutable
		case "id", "name", "type", "parent_ca_id", "status", "key_storage_type", "certificate_fingerprint_sha256", "certificate", "created_at", "updated_at":
			return CAUpdateRequest{}, errCAImmutableField
		default:
			return CAUpdateRequest{}, errCAInvalidUpdateFields
		}
	}

	var req CAUpdateRequest
	if rawDisplay, ok := payload["display_name"]; ok {
		var display string
		if err := json.Unmarshal(rawDisplay, &display); err != nil {
			return CAUpdateRequest{}, errCAInvalidUpdateFields
		}
		req.DisplayName = &display
	}
	if rawCRL, ok := payload["crl_distribution_points"]; ok {
		var crl []string
		if err := json.Unmarshal(rawCRL, &crl); err != nil {
			return CAUpdateRequest{}, errCAInvalidUpdateFields
		}
		req.CRLDistributionPoints = &crl
	}
	if rawOCSP, ok := payload["ocsp_service_url"]; ok {
		var ocsp string
		if err := json.Unmarshal(rawOCSP, &ocsp); err != nil {
			return CAUpdateRequest{}, errCAInvalidUpdateFields
		}
		req.OCSPServiceURL = &ocsp
	}

	return req, nil
}

// handleCAImport serves POST /api/v1/cas/import (W23-03).
func handleCAImport(w http.ResponseWriter, r *http.Request, auth *Authenticator, caProvider CAProvider, tenantStore TenantStore, auditProvider AuditProvider, dc *KeyDualControl) {
	pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, auditProvider, "", "ca.import", "ca", "import", AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !isAdminRole(pd.Role) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.import", "ca", "import", AuditOutcomeDenied)
		writeForbidden(w, "admin role required to import a trust anchor")
		return
	}
	importer, ok := caProvider.(CAImporter)
	if !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.import", "ca", "import", AuditOutcomeFailure)
		writeServiceUnavailable(w, "ca import not supported by this provider")
		return
	}
	var req struct {
		Name             string `json:"name"`
		Type             string `json:"type"`
		KeyStorageType   string `json:"key_storage_type"`
		CertificatePEM   string `json:"certificate_pem"`
		ApprovedActionID string `json:"approved_action_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.import", "ca", "import", AuditOutcomeFailure)
		writeBadRequest(w, "invalid request body")
		return
	}
	if req.Type != "root" || req.KeyStorageType != "external" || strings.TrimSpace(req.CertificatePEM) == "" {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.import", "ca", "import", AuditOutcomeFailure)
		writeBadRequest(w, `type must be "root", key_storage_type must be "external" and certificate_pem is required`)
		return
	}
	cert, err := ca.ValidateRootImport([]byte(req.CertificatePEM))
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.import", "ca", "import", AuditOutcomeFailure)
		writeBadRequest(w, err.Error())
		return
	}
	fp := certFingerprint(cert)
	if !dc.gate(w, r, auth, auditProvider, pd, egressGate{
		actionType:  keyActionCAImport,
		keyID:       fp,
		approvedID:  req.ApprovedActionID,
		auditAction: "ca.import",
		message:     "dual control is on - a second approver must approve this trust-anchor import; after approval retry with approved_action_id",
	}) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = cert.Subject.CommonName
	}
	created, err := importer.ImportRootCA(r.Context(), name, []byte(req.CertificatePEM))
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.import", "ca", fp, AuditOutcomeFailure)
		switch {
		case errors.Is(err, ca.ErrCAAlreadyImported):
			writeConflict(w, err.Error())
		case errors.Is(err, ca.ErrNotSelfSigned):
			writeBadRequest(w, err.Error())
		default:
			logging.Warnf("ca import failed: %v", err)
			writeServiceUnavailable(w, "ca import failed")
		}
		return
	}
	created = withCAEffectiveStatus(created, time.Now().UTC())
	created.CertificatePEM = ""
	if !tenantBypass(pd) && pd.Tenant != DefaultTenant && tenantStore != nil {
		if merr := tenantStore.SetCATenant(r.Context(), created.ID, pd.Tenant); merr != nil {
			logging.Warnf("auto-map ca %s to tenant %s failed: %v", created.ID, pd.Tenant, merr)
		}
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, "ca.import", "ca", created.ID, AuditOutcomeSuccess,
		fmt.Sprintf(`{"fingerprint":%q}`, fp))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(struct {
		Data CAListItem `json:"data"`
	}{Data: created}); err != nil {
		logging.Warnf("failed to encode /api/v1/cas/import response: %v", err)
	}
}

// handleTrustAnchorRemoval serves DELETE /api/v1/cas/{id} for providers that
// can hold imported roots (W23-03). Removal is a dual-control grant: refused
// while a live child CA exists, soft (status revoked) so it can be rolled
// back by re-importing the same certificate.
func handleTrustAnchorRemoval(w http.ResponseWriter, r *http.Request, auth *Authenticator, importer CAImporter, auditProvider AuditProvider, dc *KeyDualControl, pd AuthPrincipal, id string) {
	if !isAdminRole(pd.Role) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.trust_anchor_remove", "ca", id, AuditOutcomeDenied)
		writeForbidden(w, "admin role required to remove a trust anchor")
		return
	}
	if err := importer.CheckTrustAnchorRemovable(r.Context(), id); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.trust_anchor_remove", "ca", id, AuditOutcomeFailure)
		switch {
		case errors.Is(err, errCANotFound):
			writeNotFound(w, "ca not found")
		case errors.Is(err, ca.ErrNotTrustAnchor):
			writeErrorEnvelope(w, http.StatusUnprocessableEntity, "unprocessable_entity", "only an imported keyless root CA can be removed")
		case errors.Is(err, ca.ErrTrustAnchorHasChildren):
			writeConflict(w, "trust anchor has active child CAs")
		default:
			logging.Warnf("trust anchor check failed: %v", err)
			writeServiceUnavailable(w, "ca unavailable")
		}
		return
	}
	if !dc.gate(w, r, auth, auditProvider, pd, egressGate{
		actionType:  keyActionCATrustAnchorRemove,
		keyID:       id,
		approvedID:  r.URL.Query().Get("approved_action_id"),
		auditAction: "ca.trust_anchor_remove",
		message:     "dual control is on - a second approver must approve this trust-anchor removal; after approval retry with approved_action_id",
	}) {
		return
	}
	if err := importer.RemoveTrustAnchor(r.Context(), id); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.trust_anchor_remove", "ca", id, AuditOutcomeFailure)
		switch {
		case errors.Is(err, ca.ErrTrustAnchorHasChildren):
			writeConflict(w, "trust anchor has active child CAs")
		case errors.Is(err, errCANotFound):
			writeNotFound(w, "ca not found")
		default:
			logging.Warnf("trust anchor removal failed: %v", err)
			writeServiceUnavailable(w, "ca unavailable")
		}
		return
	}
	emitAuditEvent(r, auditProvider, pd.ID, "ca.trust_anchor_remove", "ca", id, AuditOutcomeSuccess)
	w.WriteHeader(http.StatusNoContent)
}

// handleCAGetCSR serves GET /api/v1/cas/{id}/csr (W23-04): the PKCS#10 request
// of a CA awaiting its offline-signed certificate.
func handleCAGetCSR(w http.ResponseWriter, r *http.Request, caProvider CAProvider, tenantStore TenantStore, auditProvider AuditProvider, pd AuthPrincipal, id string) {
	if id == "" || strings.Contains(id, "/") {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.csr_get", "ca", id, AuditOutcomeFailure)
		writeNotFound(w, "ca not found")
		return
	}
	if !isAdminRole(pd.Role) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.csr_get", "ca", id, AuditOutcomeDenied)
		writeForbidden(w, "admin role required")
		return
	}
	if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.csr_get", "ca", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	csrProvider, ok := caProvider.(CACSRProvider)
	if !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.csr_get", "ca", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "ca csr flow not supported by this provider")
		return
	}
	csr, err := csrProvider.GetCSR(r.Context(), id)
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.csr_get", "ca", id, AuditOutcomeFailure)
		switch {
		case errors.Is(err, errCANotFound):
			writeNotFound(w, "ca not found")
		case errors.Is(err, ca.ErrCANotPendingCertificate):
			writeConflict(w, err.Error())
		default:
			logging.Warnf("ca csr unavailable: %v", err)
			writeServiceUnavailable(w, "ca unavailable")
		}
		return
	}
	emitAuditEvent(r, auditProvider, pd.ID, "ca.csr_get", "ca", id, AuditOutcomeSuccess)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ca_id": id, "csr_pem": csr}})
}

// handleCAComplete serves POST /api/v1/cas/{id}/certificate (W23-04): the
// offline-signed certificate for a pending issuing CA. The engine verifies
// key match, issuer signature, validity and path length; a mismatch is 400.
func handleCAComplete(w http.ResponseWriter, r *http.Request, caProvider CAProvider, tenantStore TenantStore, auditProvider AuditProvider, pd AuthPrincipal, id string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if id == "" || strings.Contains(id, "/") {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeFailure)
		writeNotFound(w, "ca not found")
		return
	}
	if !isAdminRole(pd.Role) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeDenied)
		writeForbidden(w, "admin role required")
		return
	}
	if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	csrProvider, ok := caProvider.(CACSRProvider)
	if !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "ca csr flow not supported by this provider")
		return
	}
	var req struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil || strings.TrimSpace(req.CertificatePEM) == "" {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeFailure)
		writeBadRequest(w, "certificate_pem is required")
		return
	}
	completed, err := csrProvider.CompleteCA(r.Context(), id, []byte(req.CertificatePEM))
	if err != nil {
		switch {
		case errors.Is(err, ca.ErrInvalidIssuedCertificate):
			emitAuditEventDetail(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeDenied,
				fmt.Sprintf(`{"reason":%q}`, err.Error()))
			writeBadRequest(w, err.Error())
		case errors.Is(err, errCANotFound):
			emitAuditEvent(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeFailure)
			writeNotFound(w, "ca not found")
		case errors.Is(err, ca.ErrCANotPendingCertificate):
			emitAuditEvent(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeFailure)
			writeConflict(w, err.Error())
		default:
			emitAuditEvent(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeFailure)
			logging.Warnf("ca certificate completion failed: %v", err)
			writeServiceUnavailable(w, "ca unavailable")
		}
		return
	}
	completed = withCAEffectiveStatus(completed, time.Now().UTC())
	completed.CertificatePEM = ""
	emitAuditEventDetail(r, auditProvider, pd.ID, "ca.certificate_complete", "ca", id, AuditOutcomeSuccess,
		fmt.Sprintf(`{"fingerprint":%q}`, completed.CertificateFingerprintSHA256))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		Data CAListItem `json:"data"`
	}{Data: completed})
}

// writeRotationRolledBack audits ca.rotate_key_rollback with the failing step
// and answers 503. The audit event is emitted here because internal/ca has no
// audit dependency.
func writeRotationRolledBack(w http.ResponseWriter, r *http.Request, audit AuditProvider, principal, caID string, err error) {
	step := ""
	var rb *ca.RotationRolledBackError
	if errors.As(err, &rb) {
		step = string(rb.Step)
	}
	emitAuditEventDetail(r, audit, principal, "ca.rotate_key_rollback", "ca", caID, AuditOutcomeFailure,
		fmt.Sprintf(`{"step":%q}`, step))
	logging.Infof("ca rotate-key for %s rolled back at %s: %v", caID, step, err)
	writeServiceUnavailable(w, "ca key rotation failed and was rolled back")
}

// listCAsTenantFiltered pages the provider to exhaustion, keeps the caller's
// tenant rows, then applies the requested window so meta.total is honest.
func listCAsTenantFiltered(ctx context.Context, p CAProvider, store TenantStore, pd AuthPrincipal, q CAListQuery) (CAListResult, error) {
	all, err := drainPages(func(offset, limit int) ([]CAListItem, int, error) {
		wq := q
		wq.Offset, wq.Limit = offset, limit
		res, err := p.ListCAs(ctx, wq)
		return res.Items, res.Total, err
	})
	if err != nil {
		return CAListResult{}, err
	}
	all = filterCAsByTenant(ctx, store, pd, all)
	return CAListResult{Items: pageSlice(all, q.Offset, q.Limit), Total: len(all), Limit: q.Limit}, nil
}
