// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// W11-03: the takeover API — an unmanaged/external certificate becomes
// managed with a chosen renewal path, in one audited call. Lives under
// /api/v1/estate/ rather than /api/v1/certificates/{fp}/ because that
// suffix router is owned by parked review branches (same reasoning as
// W5-13's route). Takeover mutates ownership + estate bookkeeping only —
// no key or cert material moves — so it is audit-logged, not
// approval-gated; the NFR-P2 approval gate applies at the issuance the
// takeover leads to (spec decision 6).

type takeoverRenewalPath struct {
	Mode        string `json:"mode"` // internal | connector
	ConnectorID string `json:"connector_id,omitempty"`
}

type takeoverRequest struct {
	Fingerprint string              `json:"fingerprint"`
	OwnerEmail  string              `json:"owner_email,omitempty"`
	OwnerTeam   string              `json:"owner_team,omitempty"`
	ServiceName string              `json:"service_name,omitempty"`
	RenewalPath takeoverRenewalPath `json:"renewal_path"`
}

// maxBulkTakeoverItems caps one bulk takeover request (W24-31, lowered to 500
// by W27-12). The UI mirrors this cap.
const maxBulkTakeoverItems = 500

// maxTakeoverSuggestions caps fingerprints per suggestions request.
const maxTakeoverSuggestions = 500

// takeoverFailure is a refusal from performTakeover, mapped by the caller to
// an HTTP response (single) or a per-row result (bulk).
type takeoverFailure struct {
	Status  int    // 400|403|404|503
	Code    string // bad_request|forbidden|not_found|unavailable
	Message string
	Audit   AuditOutcome // AuditOutcomeFailure|AuditOutcomeDenied
}

type connectorLookup struct {
	rec ConnectorRecord
	err error
}

type bulkTakeoverRequest struct {
	Items []takeoverRequest `json:"items"`
}

type bulkTakeoverRow struct {
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"` // ok | error | skipped
	Code        string `json:"code,omitempty"`
	Error       string `json:"error,omitempty"`
	// Reason says why a row was skipped: already_managed | other_tenant | not_permitted.
	Reason string `json:"reason,omitempty"`
}

// prevalidateBulkTakeover checks every item's renewal path and looks each
// distinct connector up once (filling cache) BEFORE any write, so an invalid
// request fails whole. It returns the HTTP status and message of the refusal,
// or 0 when the request is valid.
func prevalidateBulkTakeover(ctx context.Context, store ConnectorStore, items []takeoverRequest, cache map[string]connectorLookup) (int, string) {
	var ids []string
	seen := map[string]struct{}{}
	for i, it := range items {
		switch it.RenewalPath.Mode {
		case "internal":
		case "connector":
			id := it.RenewalPath.ConnectorID
			if id == "" {
				return http.StatusBadRequest, fmt.Sprintf("invalid renewal_path for item %d", i+1)
			}
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		default:
			return http.StatusBadRequest, fmt.Sprintf("invalid renewal_path for item %d", i+1)
		}
	}
	if len(ids) == 0 {
		return 0, ""
	}
	if store == nil {
		return http.StatusServiceUnavailable, "connector store not configured"
	}
	sort.Strings(ids)
	var missing []string
	for _, id := range ids {
		rec, err := store.Get(ctx, id)
		switch {
		case err == nil:
			cache[id] = connectorLookup{rec: rec}
		case errors.Is(err, errConnectorNotFound):
			missing = append(missing, id)
		default:
			return http.StatusServiceUnavailable, "connector lookup failed"
		}
	}
	if len(missing) > 0 {
		return http.StatusBadRequest, "unknown connector(s): " + strings.Join(missing, ", ")
	}
	return 0, ""
}

type revertRequest struct {
	Fingerprint string `json:"fingerprint"`
}

func writeTakeoverFailure(w http.ResponseWriter, f *takeoverFailure) {
	switch f.Status {
	case http.StatusNotFound:
		writeNotFound(w, f.Message)
	case http.StatusForbidden:
		writeForbidden(w, f.Message)
	case http.StatusServiceUnavailable:
		writeServiceUnavailable(w, f.Message)
	default:
		writeBadRequestJSON(w, f.Message)
	}
}

// performTakeover is the shared single/bulk takeover body. It authorizes the
// certificate, resolves the renewal path (connector lookups go through cache)
// BEFORE mutating anything, then applies ownership + estate updates.
func performTakeover(ctx context.Context, pd AuthPrincipal, provider CertificateProvider,
	connectorStore ConnectorStore, req takeoverRequest, cache map[string]connectorLookup) (CertificateItem, *takeoverFailure) {
	fail := func(status int, code, msg string, outcome AuditOutcome) (CertificateItem, *takeoverFailure) {
		return CertificateItem{}, &takeoverFailure{Status: status, Code: code, Message: msg, Audit: outcome}
	}

	if _, err := authorizeCertificateResourceAccess(ctx, provider, pd, req.Fingerprint); err != nil {
		switch {
		case errors.Is(err, errCertificateNotFound):
			return fail(http.StatusNotFound, "not_found", "certificate not found", AuditOutcomeFailure)
		case errors.Is(err, errCertificateForbidden):
			return fail(http.StatusForbidden, "forbidden", "forbidden", AuditOutcomeDenied)
		default:
			return fail(http.StatusServiceUnavailable, "unavailable", "certificate unavailable", AuditOutcomeFailure)
		}
	}

	// Resolve the renewal path BEFORE mutating anything: a takeover onto
	// a connector that does not exist must fail whole.
	update := EstateUpdate{ManagementState: "managed"}
	switch req.RenewalPath.Mode {
	case "internal":
		update.RenewalMethod = "api"
	case "connector":
		if req.RenewalPath.ConnectorID == "" {
			return fail(http.StatusBadRequest, "bad_request", "renewal_path.connector_id is required for mode connector", AuditOutcomeFailure)
		}
		if connectorStore == nil {
			return fail(http.StatusServiceUnavailable, "unavailable", "connector store not configured", AuditOutcomeFailure)
		}
		lk, ok := cache[req.RenewalPath.ConnectorID]
		if !ok {
			rec, err := connectorStore.Get(ctx, req.RenewalPath.ConnectorID)
			lk = connectorLookup{rec: rec, err: err}
			if cache != nil {
				cache[req.RenewalPath.ConnectorID] = lk
			}
		}
		if lk.err != nil {
			if errors.Is(lk.err, errConnectorNotFound) {
				return fail(http.StatusBadRequest, "bad_request", "renewal_path.connector_id does not name a configured connector", AuditOutcomeFailure)
			}
			return fail(http.StatusServiceUnavailable, "unavailable", "connector lookup failed", AuditOutcomeFailure)
		}
		rec := lk.rec
		// The upstream renewal method mirrors the connector type
		// (acme connectors renew via acme, etc.); internal-type
		// connectors are just the internal path with extra steps.
		if rec.Type == "internal" {
			update.RenewalMethod = "api"
		} else {
			update.RenewalMethod = rec.Type
		}
		update.RenewalConnectorID = rec.ID
	default:
		return fail(http.StatusBadRequest, "bad_request", "renewal_path.mode must be internal or connector", AuditOutcomeFailure)
	}

	if req.OwnerEmail != "" || req.OwnerTeam != "" || req.ServiceName != "" {
		if _, err := provider.UpdateOwnership(ctx, req.Fingerprint, CertificateOwnershipRequest{
			OwnerEmail: req.OwnerEmail, OwnerTeam: req.OwnerTeam, ServiceName: req.ServiceName,
		}); err != nil {
			return fail(http.StatusServiceUnavailable, "unavailable", "ownership update failed", AuditOutcomeFailure)
		}
	}

	item, err := provider.UpdateEstate(ctx, req.Fingerprint, update)
	if err != nil {
		if errors.Is(err, errCertificateInvalid) {
			return fail(http.StatusBadRequest, "bad_request", err.Error(), AuditOutcomeFailure)
		}
		return fail(http.StatusServiceUnavailable, "unavailable", "estate update failed", AuditOutcomeFailure)
	}
	return item, nil
}

// RegisterEstateHandlers mounts POST /api/v1/estate/takeover, the bulk
// variant /api/v1/estate/takeover/bulk and POST /api/v1/estate/revert.
func RegisterEstateHandlers(mux *http.ServeMux, auth *Authenticator, provider CertificateProvider, connectorStore ConnectorStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/estate/takeover", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "estate.takeover", "certificate", "takeover", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		body := http.MaxBytesReader(w, r.Body, 64*1024)
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequestJSON(w, "invalid request body")
			return
		}
		var req takeoverRequest
		if err := json.Unmarshal(raw, &req); err != nil || req.Fingerprint == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "fingerprint and renewal_path.mode are required")
			return
		}

		item, f := performTakeover(r.Context(), pd, provider, connectorStore, req, nil)
		if f != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, f.Audit)
			writeTakeoverFailure(w, f)
			return
		}

		emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeSuccess)
		writeJSONStatus(w, http.StatusOK, struct {
			Data CertificateItem `json:"data"`
		}{Data: item})
	})

	// W24-31: bulk takeover. Approval posture is inherited from single
	// takeover: audit-only (see file header). One audit row per item plus a
	// summary row.
	mux.HandleFunc("/api/v1/estate/takeover/bulk", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "estate.takeover.bulk", "certificate", "bulk", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		body := http.MaxBytesReader(w, r.Body, 2*1024*1024)
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			if rejectOversizeBody(w, err) {
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.bulk", "certificate", "bulk", AuditOutcomeFailure)
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.bulk", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequestJSON(w, "invalid request body")
			return
		}
		var req bulkTakeoverRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.bulk", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequestJSON(w, "invalid request body")
			return
		}
		if len(req.Items) == 0 {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.bulk", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequestJSON(w, "items must not be empty")
			return
		}
		if len(req.Items) > maxBulkTakeoverItems {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.bulk", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequestJSON(w, "bulk takeover limited to 500 certificates per request")
			return
		}

		cache := make(map[string]connectorLookup)
		if status, msg := prevalidateBulkTakeover(r.Context(), connectorStore, req.Items, cache); status != 0 {
			emitAuditEventDetail(r, auditProvider, pd.ID, "estate.takeover.bulk", "certificate", "bulk", AuditOutcomeFailure,
				fmt.Sprintf(`{"requested":%d,"succeeded":0,"failed":0,"skipped":0,"rejected":"validation"}`, len(req.Items)))
			writeTakeoverFailure(w, &takeoverFailure{Status: status, Message: msg})
			return
		}

		rows := make([]bulkTakeoverRow, 0, len(req.Items))
		seen := make(map[string]struct{}, len(req.Items))
		succeeded, skipped := 0, 0
		for _, item := range req.Items {
			fp := strings.TrimSpace(item.Fingerprint)
			item.Fingerprint = fp
			if fp == "" {
				rows = append(rows, bulkTakeoverRow{Fingerprint: fp, Status: "error", Code: "bad_request", Error: "fingerprint is required"})
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", fp, AuditOutcomeFailure)
				continue
			}
			if _, dup := seen[fp]; dup {
				rows = append(rows, bulkTakeoverRow{Fingerprint: fp, Status: "error", Code: "bad_request", Error: "duplicate fingerprint in request"})
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", fp, AuditOutcomeFailure)
				continue
			}
			seen[fp] = struct{}{}
			detail, aerr := authorizeCertificateResourceAccess(r.Context(), provider, pd, fp)
			switch {
			case aerr == nil:
				if detail.ManagementState == "managed" {
					skipped++
					rows = append(rows, bulkTakeoverRow{Fingerprint: fp, Status: "skipped", Reason: "already_managed"})
					continue
				}
			case errors.Is(aerr, errCertificateTenantForbidden), errors.Is(aerr, errCertificateForbidden):
				skipped++
				rows = append(rows, bulkTakeoverRow{Fingerprint: fp, Status: "skipped", Reason: "other_tenant"})
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", fp, AuditOutcomeDenied)
				continue
			case errors.Is(aerr, errCertificateTeamScopeForbidden):
				skipped++
				rows = append(rows, bulkTakeoverRow{Fingerprint: fp, Status: "skipped", Reason: "not_permitted"})
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", fp, AuditOutcomeDenied)
				continue
			}
			// not-found and lookup errors fall through: performTakeover
			// re-authorizes and reports them as the per-row error.
			if _, f := performTakeover(r.Context(), pd, provider, connectorStore, item, cache); f != nil {
				rows = append(rows, bulkTakeoverRow{Fingerprint: fp, Status: "error", Code: f.Code, Error: f.Message})
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", fp, f.Audit)
				continue
			}
			succeeded++
			rows = append(rows, bulkTakeoverRow{Fingerprint: fp, Status: "ok"})
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", fp, AuditOutcomeSuccess)
		}

		emitAuditEventDetail(r, auditProvider, pd.ID, "estate.takeover.bulk", "certificate", "bulk", AuditOutcomeSuccess,
			fmt.Sprintf(`{"requested":%d,"succeeded":%d,"failed":%d,"skipped":%d}`, len(rows), succeeded, len(rows)-succeeded-skipped, skipped))
		writeJSONStatus(w, http.StatusOK, struct {
			Data struct {
				Total     int               `json:"total"`
				Succeeded int               `json:"succeeded"`
				Failed    int               `json:"failed"`
				Skipped   int               `json:"skipped"`
				Results   []bulkTakeoverRow `json:"results"`
			} `json:"data"`
		}{Data: struct {
			Total     int               `json:"total"`
			Succeeded int               `json:"succeeded"`
			Failed    int               `json:"failed"`
			Skipped   int               `json:"skipped"`
			Results   []bulkTakeoverRow `json:"results"`
		}{Total: len(rows), Succeeded: succeeded, Failed: len(rows) - succeeded - skipped, Skipped: skipped, Results: rows}})
	})

	registerTakeoverSuggestions(mux, auth, provider, auditProvider)

	// W24-31: managed -> the pre-takeover state (B4: external for a
	// certificate synced from an inventory source, else unmanaged; see
	// revertTargetState). Changes ONLY management_state (decision:
	// EstateUpdate cannot clear RenewalMethod/RenewalConnectorID, so the old
	// renewal path stays as stale metadata). One UpdateEstate = one row UPDATE.
	mux.HandleFunc("/api/v1/estate/revert", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "estate.takeover.revert", "certificate", "revert", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		body := http.MaxBytesReader(w, r.Body, 64*1024)
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequestJSON(w, "invalid request body")
			return
		}
		var req revertRequest
		if err := json.Unmarshal(raw, &req); err != nil || strings.TrimSpace(req.Fingerprint) == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.revert", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "fingerprint is required")
			return
		}
		fp := strings.TrimSpace(req.Fingerprint)

		detail, err := authorizeCertificateResourceAccess(r.Context(), provider, pd, fp)
		if err != nil {
			switch {
			case errors.Is(err, errCertificateNotFound):
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.revert", "certificate", fp, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
			case errors.Is(err, errCertificateForbidden):
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.revert", "certificate", fp, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
			default:
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.revert", "certificate", fp, AuditOutcomeFailure)
				writeServiceUnavailable(w, "certificate unavailable")
			}
			return
		}
		if detail.ManagementState != "managed" {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover.revert", "certificate", fp, AuditOutcomeFailure)
			writeConflict(w, "certificate is not managed")
			return
		}
		to := revertTargetState(detail.CertificateItem)
		method := revertTargetRenewalMethod(detail.CertificateItem)
		transition := revertTransitionDetail(detail.ManagementState, to, detail.RenewalMethod, method, detail.RenewalConnectorID)
		item, err := provider.UpdateEstate(r.Context(), fp, EstateUpdate{
			ManagementState: to, RenewalMethod: method, ClearRenewalConnector: true,
		})
		if err != nil {
			emitAuditEventDetail(r, auditProvider, pd.ID, "estate.takeover.revert", "certificate", fp, AuditOutcomeFailure, transition)
			if errors.Is(err, errCertificateInvalid) {
				writeBadRequestJSON(w, err.Error())
				return
			}
			writeServiceUnavailable(w, "estate update failed")
			return
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, "estate.takeover.revert", "certificate", fp, AuditOutcomeSuccess, transition)
		writeJSONStatus(w, http.StatusOK, struct {
			Data CertificateItem `json:"data"`
		}{Data: item})
	})
}

// revertTargetState is the management state a reverted certificate returns
// to: the state it had before takeover. The estate model keeps no prior
// state, so it is derived from origin, which takeover never changes: a
// certificate an inventory source synced is managed by its upstream CA
// (external, what the sync stamps); anything else was unmanaged.
func revertTargetState(c CertificateItem) string {
	if c.Origin == "synced" {
		return "external"
	}
	return "unmanaged"
}

// revertTargetRenewalMethod is the renewal method a reverted certificate
// returns to. Takeover records no prior value, but the only certificates it
// can be applied to were never issued here: an imported, discovered or synced
// certificate is stored with method "manual" and no connector, and an
// internally issued one renews via "api". Origin is never changed by takeover.
func revertTargetRenewalMethod(c CertificateItem) string {
	if c.Origin == "internal" {
		return "api"
	}
	return "manual"
}

// takeoverSuggestion is one per-certificate owner suggestion (W27-12).
type takeoverSuggestion struct {
	Fingerprint string `json:"fingerprint"`
	OwnerEmail  string `json:"owner_email"`
	OwnerTeam   string `json:"owner_team"`
	ServiceName string `json:"service_name"`
	Source      string `json:"source"`     // existing_ownership | sibling_certificate | none | unavailable
	Confidence  string `json:"confidence"` // high | medium | low | none
}

type ownerTuple struct{ email, team, service string }

func (t ownerTuple) less(o ownerTuple) bool {
	if t.email != o.email {
		return t.email < o.email
	}
	if t.team != o.team {
		return t.team < o.team
	}
	return t.service < o.service
}

func certHostNames(c CertificateItem) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, n := range append([]string{c.CommonName}, c.SubjectAltNames...) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// registerTakeoverSuggestions mounts the read-only GET
// /api/v1/estate/takeover/suggestions (W27-12): an owner suggestion per
// certificate from its own ownership, else from visible certificates sharing
// a hostname. It never mutates and never exposes data from certificates the
// caller cannot see.
func registerTakeoverSuggestions(mux *http.ServeMux, auth *Authenticator, provider CertificateProvider, auditProvider AuditProvider) {
	const action = "estate.takeover.suggest"
	mux.HandleFunc("/api/v1/estate/takeover/suggestions", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "certificate", "suggestions", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		fps := r.URL.Query()["fingerprint"]
		for i := range fps {
			fps[i] = strings.TrimSpace(fps[i])
		}
		valid := len(fps) > 0 && len(fps) <= maxTakeoverSuggestions
		for _, fp := range fps {
			if fp == "" {
				valid = false
			}
		}
		if !valid {
			emitAuditEvent(r, auditProvider, pd.ID, action, "certificate", "suggestions", AuditOutcomeFailure)
			writeBadRequestJSON(w, "between 1 and 500 fingerprint parameters are required")
			return
		}

		all, err := listAllCertificates(r.Context(), provider, CertificateListQuery{})
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, action, "certificate", "suggestions", AuditOutcomeFailure)
			writeServiceUnavailable(w, "certificates unavailable")
			return
		}
		byHost := map[string][]CertificateItem{}
		for _, c := range all.Items {
			if ownerOf(c) == (ownerTuple{}) || !cmdbCertVisible(r.Context(), pd, c) {
				continue
			}
			for _, h := range certHostNames(c) {
				byHost[h] = append(byHost[h], c)
			}
		}

		out := make([]takeoverSuggestion, 0, len(fps))
		for _, fp := range fps {
			detail, aerr := authorizeCertificateResourceAccess(r.Context(), provider, pd, fp)
			switch {
			case aerr == nil:
				out = append(out, suggestOwner(detail.CertificateItem, byHost))
			case errors.Is(aerr, errCertificateNotFound), errors.Is(aerr, errCertificateForbidden),
				errors.Is(aerr, errCertificateTeamScopeForbidden), errors.Is(aerr, errCertificateTenantForbidden):
				out = append(out, takeoverSuggestion{Fingerprint: fp, Source: "unavailable", Confidence: "none"})
			default:
				emitAuditEvent(r, auditProvider, pd.ID, action, "certificate", "suggestions", AuditOutcomeFailure)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}
		}
		emitAuditEvent(r, auditProvider, pd.ID, action, "certificate", "suggestions", AuditOutcomeSuccess)
		writeJSONStatus(w, http.StatusOK, struct {
			Data []takeoverSuggestion `json:"data"`
		}{Data: out})
	})
}

func ownerOf(c CertificateItem) ownerTuple {
	return ownerTuple{email: c.OwnerEmail, team: c.OwnerTeam, service: c.ServiceName}
}

func suggestOwner(c CertificateItem, byHost map[string][]CertificateItem) takeoverSuggestion {
	s := takeoverSuggestion{Fingerprint: c.FingerprintSHA256, Source: "none", Confidence: "none"}
	if own := ownerOf(c); own != (ownerTuple{}) {
		s.OwnerEmail, s.OwnerTeam, s.ServiceName = own.email, own.team, own.service
		s.Source, s.Confidence = "existing_ownership", "high"
		return s
	}
	seen := map[string]struct{}{c.FingerprintSHA256: {}}
	counts := map[ownerTuple]int{}
	for _, h := range certHostNames(c) {
		for _, sib := range byHost[h] {
			if _, dup := seen[sib.FingerprintSHA256]; dup {
				continue
			}
			seen[sib.FingerprintSHA256] = struct{}{}
			counts[ownerOf(sib)]++
		}
	}
	var best ownerTuple
	bestN := 0
	for t, n := range counts {
		if n > bestN || (n == bestN && t.less(best)) {
			best, bestN = t, n
		}
	}
	if bestN == 0 {
		return s
	}
	s.OwnerEmail, s.OwnerTeam, s.ServiceName = best.email, best.team, best.service
	s.Source, s.Confidence = "sibling_certificate", "low"
	if bestN >= 2 {
		s.Confidence = "medium"
	}
	return s
}

// revertTransitionDetail builds the audit detail with encoding/json: %q is Go
// quoting, which emits \x.. escapes that are not valid JSON for non-printable
// or odd-unicode connector ids.
func revertTransitionDetail(fromState, toState, fromMethod, toMethod, fromConnector string) string {
	type change struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	raw, err := json.Marshal(struct {
		From        string `json:"from"`
		To          string `json:"to"`
		Method      change `json:"renewal_method"`
		ConnectorID change `json:"renewal_connector_id"`
	}{fromState, toState, change{fromMethod, toMethod}, change{fromConnector, ""}})
	if err != nil {
		return "{}"
	}
	return string(raw)
}
