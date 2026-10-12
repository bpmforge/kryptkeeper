// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// W11-02: bulk certificate import — a customer's pile of certs becomes a
// risk-scored estate in one call. Lives on its own exact-path route: the
// /api/v1/certificates/ suffix router (handlers_certificates.go) and the
// bulk-revoke file (handlers_bulk.go) are both owned by parked review
// branches. PKCS#7/CMS input is deliberately absent — no CMS parser exists
// in this repo and hand-rolling one is the crypto-hallucination hazard the
// verify-before-writing rule exists for (spec decision 3).

const (
	maxBulkImportBodyBytes = 8 << 20 // 8 MiB
	maxBulkImportCerts     = 1000
	maxBulkImportFailures  = 50 // cap the failed-items list in the response
)

type bulkImportRequest struct {
	// Format: "pem" (default), "der_b64", or "csv". Empty auto-detects pem.
	Format string `json:"format"`
	Bundle string `json:"bundle"`
	TeamID string `json:"team_id"`
	// Body-level ownership defaults; csv rows may override per cert.
	OwnerEmail  string `json:"owner_email"`
	OwnerTeam   string `json:"owner_team"`
	ServiceName string `json:"service_name"`
}

type bulkImportItem struct {
	pem       string
	ownership *CertificateOwnershipRequest
}

type bulkImportFailure struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

type bulkImportResult struct {
	Imported          int                 `json:"imported"`
	SkippedDuplicates int                 `json:"skipped_duplicates"`
	Failed            []bulkImportFailure `json:"failed"`
	Fingerprints      []string            `json:"fingerprints"`
}

// RegisterBulkImportHandler mounts POST /api/v1/certificates/bulk-import.
func RegisterBulkImportHandler(mux *http.ServeMux, auth *Authenticator, provider CertificateProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/certificates/bulk-import", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "certificate.bulk_import", "certificate", "bulk-import", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		body := http.MaxBytesReader(w, r.Body, maxBulkImportBodyBytes)
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.bulk_import", "certificate", "bulk-import", AuditOutcomeFailure)
			writeBadRequestJSON(w, "request body unreadable or over the 8 MiB limit")
			return
		}
		var req bulkImportRequest
		if err := json.Unmarshal(raw, &req); err != nil || strings.TrimSpace(req.Bundle) == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.bulk_import", "certificate", "bulk-import", AuditOutcomeFailure)
			writeBadRequestJSON(w, "bundle is required")
			return
		}

		if err := authorizeCertificateMutationRequest(pd, &req.TeamID); err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.bulk_import", "certificate", "bulk-import", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		items, err := parseBulkImportBundle(req)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.bulk_import", "certificate", "bulk-import", AuditOutcomeFailure)
			writeBadRequestJSON(w, err.Error())
			return
		}
		if len(items) == 0 {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.bulk_import", "certificate", "bulk-import", AuditOutcomeFailure)
			writeBadRequestJSON(w, "bundle contains no certificates")
			return
		}
		if len(items) > maxBulkImportCerts {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.bulk_import", "certificate", "bulk-import", AuditOutcomeFailure)
			writeBadRequestJSON(w, "bundle exceeds the 1000-certificate limit; split it")
			return
		}

		result := importBulkItems(r.Context(), provider, req, items)

		emitAuditEvent(r, auditProvider, pd.ID, "certificate.bulk_import", "certificate", "bulk-import", AuditOutcomeSuccess)
		writeJSONStatus(w, http.StatusOK, struct {
			Data bulkImportResult `json:"data"`
		}{Data: result})
	})
}

func importBulkItems(ctx context.Context, provider CertificateProvider, req bulkImportRequest, items []bulkImportItem) bulkImportResult {
	result := bulkImportResult{Failed: []bulkImportFailure{}, Fingerprints: []string{}}
	for i, item := range items {
		imported, err := provider.ImportCertificate(ctx, CertificateImportRequest{
			CertificatePEM: item.pem,
			TeamID:         req.TeamID,
		})
		if err != nil {
			// A fingerprint already in inventory is the expected dedupe
			// path, never an error (spec decision 4).
			if errors.Is(err, errCertificateConflict) {
				result.SkippedDuplicates++
				continue
			}
			if len(result.Failed) < maxBulkImportFailures {
				result.Failed = append(result.Failed, bulkImportFailure{Index: i, Reason: err.Error()})
			}
			continue
		}
		result.Imported++
		fp := imported.CertificateItem.FingerprintSHA256
		result.Fingerprints = append(result.Fingerprints, fp)

		ownership := item.ownership
		if ownership == nil && (req.OwnerEmail != "" || req.OwnerTeam != "" || req.ServiceName != "") {
			ownership = &CertificateOwnershipRequest{
				OwnerEmail: req.OwnerEmail, OwnerTeam: req.OwnerTeam, ServiceName: req.ServiceName,
			}
		}
		if ownership != nil {
			if _, err := provider.UpdateOwnership(ctx, fp, *ownership); err != nil {
				log.Printf("bulk import: ownership update failed for %s: %v", fp, err)
			}
		}
	}
	return result
}

// parseBulkImportBundle turns the request into per-cert PEM items.
func parseBulkImportBundle(req bulkImportRequest) ([]bulkImportItem, error) {
	format := strings.ToLower(strings.TrimSpace(req.Format))
	switch format {
	case "", "pem":
		return parsePEMBundle(req.Bundle)
	case "der_b64":
		return parseDERB64Bundle(req.Bundle)
	case "csv":
		return parseCSVBundle(req.Bundle)
	default:
		return nil, errors.New("format must be one of pem, der_b64, csv")
	}
}

func parsePEMBundle(bundle string) ([]bulkImportItem, error) {
	var items []bulkImportItem
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		// Key material must not enter through this door: reject the WHOLE
		// bundle before importing anything (spec decision 2).
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, errors.New("bundle contains private key material; remove all key blocks and re-submit — this endpoint imports certificates only")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		items = append(items, bulkImportItem{
			pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})),
		})
	}
	return items, nil
}

func parseDERB64Bundle(bundle string) ([]bulkImportItem, error) {
	var items []bulkImportItem
	for _, tok := range strings.Fields(bundle) {
		der, err := base64.StdEncoding.DecodeString(tok)
		if err != nil {
			return nil, errors.New("der_b64 bundle contains a token that is not valid base64")
		}
		items = append(items, bulkImportItem{
			pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		})
	}
	return items, nil
}

func parseCSVBundle(bundle string) ([]bulkImportItem, error) {
	reader := csv.NewReader(strings.NewReader(bundle))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, errors.New("csv bundle unparseable: " + err.Error())
	}
	if len(records) < 2 {
		return nil, errors.New("csv needs a header row (cert_b64[,owner_email,owner_team,service_name]) and at least one data row")
	}
	col := map[string]int{}
	for i, name := range records[0] {
		col[strings.ToLower(strings.TrimSpace(name))] = i
	}
	certCol, ok := col["cert_b64"]
	if !ok {
		return nil, errors.New("csv header must include cert_b64")
	}
	get := func(row []string, name string) string {
		if idx, ok := col[name]; ok && idx < len(row) {
			return strings.TrimSpace(row[idx])
		}
		return ""
	}
	var items []bulkImportItem
	for _, row := range records[1:] {
		if certCol >= len(row) || strings.TrimSpace(row[certCol]) == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(row[certCol]))
		if err != nil {
			return nil, errors.New("csv cert_b64 value is not valid base64")
		}
		// The cell may hold base64 of a PEM block or of raw DER.
		var certPEM string
		if block, _ := pem.Decode(decoded); block != nil {
			if strings.Contains(block.Type, "PRIVATE KEY") {
				return nil, errors.New("csv contains private key material; certificates only")
			}
			certPEM = string(pem.EncodeToMemory(block))
		} else {
			certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decoded}))
		}
		item := bulkImportItem{pem: certPEM}
		if o := (CertificateOwnershipRequest{
			OwnerEmail:  get(row, "owner_email"),
			OwnerTeam:   get(row, "owner_team"),
			ServiceName: get(row, "service_name"),
		}); o.OwnerEmail != "" || o.OwnerTeam != "" || o.ServiceName != "" {
			item.ownership = &o
		}
		items = append(items, item)
	}
	return items, nil
}
