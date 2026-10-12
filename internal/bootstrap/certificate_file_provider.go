// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"
)

const defaultCertificateFilePath = "./var/bootstrap-certificates.json"

type fileCertificateProvider struct {
	filePath string
}

func NewFileCertificateProviderFromEnv() CertificateProvider {
	path := strings.TrimSpace(os.Getenv("APP_CERTIFICATE_FILE"))
	if path == "" {
		path = defaultCertificateFilePath
	}
	return &fileCertificateProvider{filePath: path}
}

func (p *fileCertificateProvider) ListCertificates(_ context.Context, query CertificateListQuery) (CertificateListResult, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	items, err := p.loadItems()
	if err != nil {
		return CertificateListResult{}, err
	}
	filtered := filterFileCertificates(items, query)

	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return CertificateListResult{Items: filtered[offset:end], Total: total, Limit: limit}, nil
}

// ForEachCertificate reads the file once and visits every match in list
// order. Paging through ListCertificates would re-read and re-parse the whole
// file per page.
func (p *fileCertificateProvider) ForEachCertificate(ctx context.Context, query CertificateListQuery, fn func(CertificateItem) error) error {
	items, err := p.loadItems()
	if err != nil {
		return err
	}
	for _, item := range filterFileCertificates(items, query) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(item); err != nil {
			return err
		}
	}
	return nil
}

// filterFileCertificates applies the query's filters and Order to items.
func filterFileCertificates(items []CertificateItem, query CertificateListQuery) []CertificateItem {
	q := strings.ToLower(strings.TrimSpace(query.Q))
	gradeSet := map[string]bool{}
	for _, grade := range query.Grades {
		trimmed := strings.ToUpper(strings.TrimSpace(grade))
		if trimmed != "" {
			gradeSet[trimmed] = true
		}
	}

	filtered := make([]CertificateItem, 0, len(items))
	for _, item := range items {
		if query.CAID != "" && item.CAID != query.CAID {
			continue
		}
		if query.Origin != "" && item.Origin != query.Origin {
			continue
		}
		if query.ManagementState != "" && item.ManagementState != query.ManagementState {
			continue
		}
		if query.TemplateID != "" && item.TemplateID != query.TemplateID {
			continue
		}
		if query.TeamID != "" && item.TeamID != query.TeamID {
			continue
		}
		if query.Status != "" && item.RenewalStatus != query.Status {
			continue
		}
		if len(gradeSet) > 0 && !gradeSet[strings.ToUpper(strings.TrimSpace(item.Grade))] {
			continue
		}
		if q != "" {
			haystack := strings.ToLower(item.CommonName + " " + item.SubjectDN)
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		filtered = append(filtered, item)
	}

	if strings.ToLower(strings.TrimSpace(query.Order)) == "asc" {
		slices.Reverse(filtered)
	}
	return filtered
}

func (p *fileCertificateProvider) GetCertificate(_ context.Context, fingerprint string) (CertificateDetail, bool, error) {
	items, err := p.loadItems()
	if err != nil {
		return CertificateDetail{}, false, err
	}
	for _, item := range items {
		if item.FingerprintSHA256 != fingerprint {
			continue
		}
		return CertificateDetail{CertificateItem: item, Endpoints: []CertificateEndpoint{}}, true, nil
	}
	return CertificateDetail{}, false, nil
}

func (p *fileCertificateProvider) GetCertificateChain(_ context.Context, fingerprint string) (CertificateChainResult, bool, error) {
	items, err := p.loadItems()
	if err != nil {
		return CertificateChainResult{}, false, err
	}
	byFP := map[string]CertificateItem{}
	for _, item := range items {
		byFP[item.FingerprintSHA256] = item
	}
	current, found := byFP[fingerprint]
	if !found {
		return CertificateChainResult{}, false, nil
	}

	chain := make([]CertificateChainItem, 0, 4)
	if current.PredecessorFP != nil && *current.PredecessorFP != "" {
		if pred, ok := byFP[*current.PredecessorFP]; ok {
			chain = append(chain, CertificateChainItem{FingerprintSHA256: pred.FingerprintSHA256, CommonName: pred.CommonName, ValidFrom: pred.ValidFrom, ValidUntil: pred.ValidUntil, RenewalStatus: pred.RenewalStatus, Position: "predecessor"})
		}
	}
	chain = append(chain, CertificateChainItem{FingerprintSHA256: current.FingerprintSHA256, CommonName: current.CommonName, ValidFrom: current.ValidFrom, ValidUntil: current.ValidUntil, RenewalStatus: current.RenewalStatus, Position: "current"})
	if current.SuccessorFP != nil && *current.SuccessorFP != "" {
		if succ, ok := byFP[*current.SuccessorFP]; ok {
			chain = append(chain, CertificateChainItem{FingerprintSHA256: succ.FingerprintSHA256, CommonName: succ.CommonName, ValidFrom: succ.ValidFrom, ValidUntil: succ.ValidUntil, RenewalStatus: succ.RenewalStatus, Position: "successor"})
		}
	}

	return CertificateChainResult{CurrentFingerprint: fingerprint, Chain: chain}, true, nil
}

func (p *fileCertificateProvider) IssueCertificate(_ context.Context, req CertificateIssueRequest) (CertificateIssueResult, error) {
	if strings.TrimSpace(req.CAID) == "" || strings.TrimSpace(req.TemplateID) == "" || strings.TrimSpace(req.CSRPEM) == "" {
		return CertificateIssueResult{}, errCertificateInvalid
	}

	items, err := p.loadItems()
	if err != nil {
		return CertificateIssueResult{}, err
	}

	now := time.Now().UTC()
	fp := fingerprintForPayload(req.CSRPEM + req.CAID + req.TemplateID)
	if findCertificateIndex(items, fp) >= 0 {
		return CertificateIssueResult{}, errCertificateConflict
	}

	item := CertificateItem{
		FingerprintSHA256:  fp,
		SerialNumber:       fmt.Sprintf("%x", now.UnixNano()),
		CommonName:         "issued.local",
		SubjectDN:          "CN=issued.local",
		SubjectAltNames:    []string{"issued.local"},
		IssuerCN:           "Kryptkeeper Issuing CA",
		IssuerDN:           "CN=Kryptkeeper Issuing CA",
		CAID:               req.CAID,
		TemplateID:         req.TemplateID,
		TeamID:             strings.TrimSpace(req.TeamID),
		ValidFrom:          now.Format(time.RFC3339),
		ValidUntil:         now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
		PublicKeyAlgorithm: "ECDSA",
		KeySizeBits:        256,
		SignatureAlgorithm: "ecdsa-with-SHA256",
		ExtendedKeyUsage:   []string{"TLS Web Server Authentication"},
		KeyUsage:           []string{"Digital Signature"},
		ChainComplete:      true,
		ChainTrusted:       true,
		PQCVulnerable:      true,
		RiskScore:          5,
		RiskFlags:          []string{},
		Grade:              "A",
		RenewalMethod:      "api",
		RenewalStatus:      string(RenewalStatusActive),
		Source:             "api",
		Origin:             "internal",
		ManagementState:    "managed",
		ETag:               1,
		CreatedAt:          now.Format(time.RFC3339),
		UpdatedAt:          now.Format(time.RFC3339),
	}
	items = append(items, item)
	if err := p.saveItems(items); err != nil {
		return CertificateIssueResult{}, err
	}
	return CertificateIssueResult{CertificateItem: item}, nil
}

func (p *fileCertificateProvider) RenewCertificate(_ context.Context, fingerprint string, req CertificateRenewRequest) (CertificateIssueResult, error) {
	if strings.TrimSpace(req.CSRPEM) == "" {
		return CertificateIssueResult{}, errCertificateInvalid
	}

	items, err := p.loadItems()
	if err != nil {
		return CertificateIssueResult{}, err
	}

	idx := findCertificateIndex(items, fingerprint)
	if idx < 0 {
		return CertificateIssueResult{}, errCertificateNotFound
	}
	if items[idx].SuccessorFP != nil && strings.TrimSpace(*items[idx].SuccessorFP) != "" {
		return CertificateIssueResult{}, errCertificateConflict
	}

	now := time.Now().UTC()
	fp := fingerprintForPayload(req.CSRPEM + fingerprint + now.Format(time.RFC3339Nano))
	newItem := items[idx]
	newItem.FingerprintSHA256 = fp
	newItem.SerialNumber = fmt.Sprintf("%x", now.UnixNano())
	newItem.ValidFrom = now.Format(time.RFC3339)
	newItem.ValidUntil = now.Add(90 * 24 * time.Hour).Format(time.RFC3339)
	newItem.RenewalStatus = string(RenewalStatusActive)
	newItem.RenewalMethod = "api"
	newItem.Source = "api"
	newItem.Origin = "internal"
	newItem.ManagementState = "managed"
	newItem.PredecessorFP = &fingerprint
	newItem.SuccessorFP = nil
	newItem.RevokedAt = nil
	newItem.RevocationReason = nil
	newItem.ETag = 1
	newItem.CreatedAt = now.Format(time.RFC3339)
	newItem.UpdatedAt = now.Format(time.RFC3339)

	items[idx].RenewalStatus = string(RenewalStatusRenewed)
	items[idx].SuccessorFP = &fp
	items[idx].UpdatedAt = now.Format(time.RFC3339)
	items[idx].ETag++

	items = append(items, newItem)
	if err := p.saveItems(items); err != nil {
		return CertificateIssueResult{}, err
	}
	return CertificateIssueResult{CertificateItem: newItem}, nil
}

func (p *fileCertificateProvider) RevokeCertificate(_ context.Context, fingerprint string, req CertificateRevokeRequest) (CertificateRevokeResult, error) {
	if req.ReasonCode < 0 {
		return CertificateRevokeResult{}, errCertificateInvalid
	}

	items, err := p.loadItems()
	if err != nil {
		return CertificateRevokeResult{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range items {
		if items[i].FingerprintSHA256 != fingerprint {
			continue
		}
		if items[i].RenewalStatus == string(RenewalStatusRevoked) || items[i].RenewalStatus == string(RenewalStatusExpired) {
			return CertificateRevokeResult{}, errCertificateConflict
		}
		items[i].RenewalStatus = string(RenewalStatusRevoked)
		items[i].RevokedAt = &now
		reason := req.ReasonCode
		items[i].RevocationReason = &reason
		items[i].UpdatedAt = now
		items[i].ETag++
		if items[i].ETag <= 0 {
			items[i].ETag = 1
		}

		if err := p.saveItems(items); err != nil {
			return CertificateRevokeResult{}, err
		}
		return CertificateRevokeResult{FingerprintSHA256: fingerprint, RenewalStatus: string(RenewalStatusRevoked), RevokedAt: now, RevocationReason: reason}, nil
	}

	return CertificateRevokeResult{}, errCertificateNotFound
}

func (p *fileCertificateProvider) DownloadCertificate(_ context.Context, fingerprint string, format string, includeChain bool) (CertificateDownloadResult, error) {
	items, err := p.loadItems()
	if err != nil {
		return CertificateDownloadResult{}, err
	}
	idx := findCertificateIndex(items, fingerprint)
	if idx < 0 {
		return CertificateDownloadResult{}, errCertificateNotFound
	}
	commonName := sanitizeFilenameComponent(strings.TrimSpace(items[idx].CommonName))
	if commonName == "" {
		commonName = "certificate"
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "pem"
	}
	switch format {
	case "pem":
		body := []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", fingerprint))
		if includeChain {
			body = append(body, []byte("-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n")...)
		}
		return CertificateDownloadResult{ContentType: "application/x-pem-file", Filename: commonName + ".pem", Body: body}, nil
	case "der":
		return CertificateDownloadResult{ContentType: "application/pkix-cert", Filename: commonName + ".der", Body: []byte("DER:" + fingerprint)}, nil
	default:
		return CertificateDownloadResult{}, errCertificateInvalid
	}
}

func (p *fileCertificateProvider) ImportCertificate(_ context.Context, req CertificateImportRequest) (CertificateIssueResult, error) {
	if strings.TrimSpace(req.CertificatePEM) == "" {
		return CertificateIssueResult{}, errCertificateInvalid
	}
	items, err := p.loadItems()
	if err != nil {
		return CertificateIssueResult{}, err
	}

	fp := fingerprintForPayload(req.CertificatePEM)
	if findCertificateIndex(items, fp) >= 0 {
		return CertificateIssueResult{}, errCertificateConflict
	}
	now := time.Now().UTC().Format(time.RFC3339)
	item := CertificateItem{
		FingerprintSHA256:  fp,
		SerialNumber:       "imported",
		CommonName:         "imported.local",
		SubjectDN:          "CN=imported.local",
		SubjectAltNames:    []string{"imported.local"},
		IssuerCN:           "External Issuer",
		IssuerDN:           "CN=External Issuer",
		CAID:               "",
		TemplateID:         "",
		TeamID:             strings.TrimSpace(req.TeamID),
		ValidFrom:          now,
		ValidUntil:         now,
		PublicKeyAlgorithm: "RSA",
		KeySizeBits:        2048,
		SignatureAlgorithm: "sha256WithRSAEncryption",
		ExtendedKeyUsage:   []string{"TLS Web Server Authentication"},
		KeyUsage:           []string{"Digital Signature"},
		ChainComplete:      true,
		ChainTrusted:       true,
		PQCVulnerable:      false,
		RiskScore:          15,
		RiskFlags:          []string{},
		Grade:              "B",
		RenewalMethod:      "manual",
		RenewalStatus:      string(RenewalStatusActive),
		Source:             "import",
		Origin:             "imported",
		ManagementState:    "unmanaged",
		ETag:               1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	items = append(items, item)
	if err := p.saveItems(items); err != nil {
		return CertificateIssueResult{}, err
	}
	return CertificateIssueResult{CertificateItem: item}, nil
}

func (p *fileCertificateProvider) UpdateOwnership(_ context.Context, fingerprint string, req CertificateOwnershipRequest) (CertificateItem, error) {
	items, err := p.loadItems()
	if err != nil {
		return CertificateItem{}, err
	}
	idx := findCertificateIndex(items, fingerprint)
	if idx < 0 {
		return CertificateItem{}, errCertificateNotFound
	}
	items[idx].OwnerEmail = strings.TrimSpace(req.OwnerEmail)
	items[idx].OwnerTeam = strings.TrimSpace(req.OwnerTeam)
	items[idx].ServiceName = strings.TrimSpace(req.ServiceName)
	if req.Labels != nil {
		items[idx].Labels = req.Labels
	}
	items[idx].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := p.saveItems(items); err != nil {
		return CertificateItem{}, err
	}
	return items[idx], nil
}

func (p *fileCertificateProvider) loadItems() ([]CertificateItem, error) {
	body, err := os.ReadFile(p.filePath)
	if err != nil {
		log.Printf("certificate file unavailable: unreadable %q: %v", p.filePath, err)
		return nil, err
	}

	var items []CertificateItem
	if err := json.Unmarshal(body, &items); err != nil {
		log.Printf("certificate file unavailable: invalid JSON in %q", p.filePath)
		return nil, err
	}
	// W11-01: pre-estate files lack origin/management_state — derive from
	// source so filters and the dashboard split never see empty values.
	for i := range items {
		if items[i].Origin == "" || items[i].ManagementState == "" {
			items[i].Origin = estateOrigin(items[i])
			items[i].ManagementState = estateManagementState(items[i])
		}
	}
	return items, nil
}

func (p *fileCertificateProvider) saveItems(items []CertificateItem) error {
	body, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return os.WriteFile(p.filePath, body, 0o600)
}

func findCertificateIndex(items []CertificateItem, fingerprint string) int {
	for i := range items {
		if items[i].FingerprintSHA256 == fingerprint {
			return i
		}
	}
	return -1
}

func fingerprintForPayload(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func sanitizeFilenameComponent(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-._")
}

// UpdateEstate (W11-03): the file provider applies the same transition to
// its JSON records.
func (p *fileCertificateProvider) UpdateEstate(_ context.Context, fingerprint string, req EstateUpdate) (CertificateItem, error) {
	items, err := p.loadItems()
	if err != nil {
		return CertificateItem{}, err
	}
	for i := range items {
		if items[i].FingerprintSHA256 != fingerprint {
			continue
		}
		if req.Origin != "" {
			switch req.Origin {
			case "internal", "imported", "discovered", "synced":
			default:
				return CertificateItem{}, errCertificateInvalid
			}
			items[i].Origin = req.Origin
		}
		if req.ManagementState != "" {
			switch req.ManagementState {
			case "managed", "external", "unmanaged":
			default:
				return CertificateItem{}, errCertificateInvalid
			}
			items[i].ManagementState = req.ManagementState
		}
		if req.RenewalMethod != "" {
			items[i].RenewalMethod = req.RenewalMethod
		}
		if req.RenewalConnectorID != "" {
			items[i].RenewalConnectorID = req.RenewalConnectorID
		}
		if req.RenewalStatus != "" {
			if !validRenewalStatus(req.RenewalStatus) {
				return CertificateItem{}, errCertificateInvalid
			}
			items[i].RenewalStatus = req.RenewalStatus
		}
		items[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := p.saveItems(items); err != nil {
			return CertificateItem{}, err
		}
		return items[i], nil
	}
	return CertificateItem{}, errCertificateNotFound
}
