// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// NewDBActiveCertCountByCA counts active certificates per CA from the same
// certificates table issuance writes to (S-72). Plain SQL, valid on both
// sqlite and Postgres. A nil db yields a counter that reports no counts —
// the ca-mode boot path tolerates an unavailable core DB.
func NewDBActiveCertCountByCA(db *sql.DB) CertCountByCA {
	return func(ctx context.Context) (map[string]int, error) {
		if db == nil {
			return nil, nil
		}
		rows, err := db.QueryContext(ctx, `
SELECT ca_id, COUNT(*)
FROM certificates
WHERE `+activeCertSQL+` AND ca_id IS NOT NULL AND ca_id != ''
GROUP BY ca_id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		counts := make(map[string]int)
		for rows.Next() {
			var caID string
			var n int
			if err := rows.Scan(&caID, &n); err != nil {
				return nil, err
			}
			counts[caID] = n
		}
		return counts, rows.Err()
	}
}

// ActiveCertCountByCAFromProvider prefers the certificate provider's own
// incrementally maintained per-CA counts over fallback (the DB GROUP BY). The
// GROUP BY ran on every issuance via the revocation-pointer CA lookup and
// scanned the whole table (M1).
func ActiveCertCountByCAFromProvider(p CertificateProvider, fallback CertCountByCA) CertCountByCA {
	if counter, ok := p.(interface {
		ActiveCertCountsByCA(context.Context) (map[string]int, error)
	}); ok {
		return counter.ActiveCertCountsByCA
	}
	return fallback
}

// CertCountByCA reports, per CA id, how many active certificates the store
// holds for that CA. S-72: the engine knows CAs but not the certificate
// inventory, so the count is injected rather than reached for — the file
// provider gets it from its JSON records, ca mode from the core DB.
type CertCountByCA func(context.Context) (map[string]int, error)

// engineCAProvider implements CAProvider using a live ca.Service engine.
// All mutations go through the engine, which persists to the configured store.
type engineCAProvider struct {
	engine     ca.Service
	certCounts CertCountByCA
}

// NewEngineCAProvider creates a CAProvider backed by a real CA engine.
// Per-CA issued counts render as zero; use NewEngineCAProviderWithCounts
// where an inventory is available.
func NewEngineCAProvider(engine ca.Service) CAProvider {
	return &engineCAProvider{engine: engine}
}

// NewEngineCAProviderWithCounts is NewEngineCAProvider plus a source for
// per-CA active-certificate counts (S-72).
func NewEngineCAProviderWithCounts(engine ca.Service, counts CertCountByCA) CAProvider {
	return &engineCAProvider{engine: engine, certCounts: counts}
}

// loadCertCounts fetches per-CA counts, degrading to zeros on error: a
// broken count must never take down the CA listing itself.
func (p *engineCAProvider) loadCertCounts(ctx context.Context) map[string]int {
	if p.certCounts == nil {
		return nil
	}
	counts, err := p.certCounts(ctx)
	if err != nil {
		log.Printf("per-CA certificate counts unavailable: %v", err)
		return nil
	}
	return counts
}

func (p *engineCAProvider) ListCAs(ctx context.Context, query CAListQuery) (CAListResult, error) {
	all, err := p.engine.ListCAs()
	if err != nil {
		return CAListResult{}, err
	}
	counts := p.loadCertCounts(ctx)

	filtered := make([]CAListItem, 0, len(all))
	for _, ca := range all {
		if query.Type != "" && ca.Type != query.Type {
			continue
		}
		if query.Status != "" && ca.Status != query.Status {
			continue
		}
		item := caToListItem(ca)
		item.ActiveIssuedCertificates = counts[item.ID]
		filtered = append(filtered, item)
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 25
	}
	total := len(filtered)
	offset := query.Offset
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return CAListResult{Items: filtered[offset:end], Total: total, Limit: limit}, nil
}

func (p *engineCAProvider) GetCA(ctx context.Context, id string) (CAListItem, bool, error) {
	caObj, err := p.engine.GetCA(id)
	if err != nil {
		return CAListItem{}, false, nil
	}
	item := caToListItem(caObj)
	item.ActiveIssuedCertificates = p.loadCertCounts(ctx)[item.ID]
	return item, true, nil
}

func (p *engineCAProvider) GetCAChain(ctx context.Context, id string) ([]CAListItem, bool, error) {
	chain, err := p.engine.GetCAChain(id)
	if err != nil || len(chain) == 0 {
		return nil, false, err
	}
	counts := p.loadCertCounts(ctx)
	items := make([]CAListItem, len(chain))
	for i, ca := range chain {
		items[i] = caToListItem(ca)
		items[i].ActiveIssuedCertificates = counts[items[i].ID]
	}
	return items, true, nil
}

func (p *engineCAProvider) UpdateCA(_ context.Context, id string, req CAUpdateRequest) (CAListItem, error) {
	caObj, err := p.engine.GetCA(id)
	if err != nil {
		return CAListItem{}, errCANotFound
	}
	// Engine doesn't have a dedicated update method; surface display metadata via status no-op.
	// The updatable fields (display_name, crl, ocsp) are stored in the CA record name for now.
	if req.DisplayName != nil {
		caObj.Name = *req.DisplayName
	}
	return caToListItem(caObj), nil
}

func (p *engineCAProvider) DeleteCA(_ context.Context, _ string) error {
	return errCACreateUnsupported
}

// RotateCAKey implements the optional CARotator capability (W9-04/G-35).
// algorithm is optional -- when empty, the new key reuses the CA's current
// algorithm (ca.Engine.RotateCA's own default).
func (p *engineCAProvider) RotateCAKey(_ context.Context, id string, algorithm string) (CAKeyRotationResult, error) {
	var algo keystore.Algorithm
	if trimmed := strings.TrimSpace(algorithm); trimmed != "" {
		parsed, err := parseAlgorithm(trimmed)
		if err != nil {
			return CAKeyRotationResult{}, fmt.Errorf("unsupported algorithm %q: %w", algorithm, err)
		}
		algo = parsed
	}

	result, err := p.engine.RotateCA(id, ca.RotateCAOptions{Algorithm: algo})
	if err != nil {
		if err == ca.ErrCANotFound {
			return CAKeyRotationResult{}, errCANotFound
		}
		// result.CA is non-nil only when the key rotation and certificate
		// re-issuance already succeeded and were persisted -- today the
		// only such case is a ledger-write failure (RecordKeyRotation).
		// The rotation itself must not be reported as failed: the caller
		// would otherwise retry a rotation that already happened,
		// generating ANOTHER new key on a CA that is already rotated.
		// Any other error here (wrapping ca.ErrCARotationInconsistent)
		// leaves result.CA nil and is returned bare, unchanged.
		if result.CA != nil {
			return CAKeyRotationResult{
				ID:              result.CA.ID,
				Status:          result.CA.Status,
				KeyID:           result.NewKeyID,
				RotatedAt:       result.Rotation.RotatedAt.UTC().Format(time.RFC3339),
				LedgerID:        result.Rotation.ID,
				LedgerPersisted: false,
			}, err
		}
		return CAKeyRotationResult{}, err
	}

	return CAKeyRotationResult{
		ID:              result.CA.ID,
		Status:          result.CA.Status,
		KeyID:           result.NewKeyID,
		RotatedAt:       result.Rotation.RotatedAt.UTC().Format(time.RFC3339),
		LedgerID:        result.Rotation.ID,
		LedgerPersisted: true,
	}, nil
}

func (p *engineCAProvider) SuspendCA(_ context.Context, id string) (CAStatusChange, error) {
	if err := p.engine.UpdateCAStatus(id, "suspended"); err != nil {
		if err == ca.ErrCANotFound {
			return CAStatusChange{}, errCANotFound
		}
		return CAStatusChange{}, errCAConflict
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return CAStatusChange{ID: id, Status: "suspended", UpdatedAt: now}, nil
}

func (p *engineCAProvider) ActivateCA(_ context.Context, id string) (CAStatusChange, error) {
	if err := p.engine.UpdateCAStatus(id, "active"); err != nil {
		if err == ca.ErrCANotFound {
			return CAStatusChange{}, errCANotFound
		}
		return CAStatusChange{}, errCAConflict
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return CAStatusChange{ID: id, Status: "active", UpdatedAt: now}, nil
}

func (p *engineCAProvider) CreateCA(_ context.Context, req CACreateRequest) (CAListItem, error) {
	algo, err := parseAlgorithm(req.Algorithm)
	if err != nil {
		return CAListItem{}, fmt.Errorf("unsupported algorithm %q: %w", req.Algorithm, err)
	}
	validity, err := parseValidityStr(req.ValidityStr)
	if err != nil {
		return CAListItem{}, fmt.Errorf("invalid validity %q: %w", req.ValidityStr, err)
	}

	subject := buildSubject(req.SubjectCN, req.SubjectOrg)
	name := req.Name
	if name == "" {
		name = req.SubjectCN
	}

	var caObj *ca.CA
	switch strings.ToLower(req.Type) {
	case "root":
		caObj, err = p.engine.CreateRootCA(name, subject, algo, validity)
	case "intermediate":
		if req.ParentCAID == "" {
			return CAListItem{}, fmt.Errorf("parent_ca_id required for intermediate CA")
		}
		caObj, err = p.engine.CreateIntermediateCA(name, subject, algo, req.ParentCAID, validity)
	default:
		return CAListItem{}, fmt.Errorf("type must be 'root' or 'intermediate'")
	}
	if err != nil {
		return CAListItem{}, err
	}

	return caToListItem(caObj), nil
}

// caToListItem converts a ca.CA engine object to the API-layer CAListItem.
func caToListItem(c *ca.CA) CAListItem {
	// W19-08: was hardcoded to "software" here, so an HSM-held CA key was
	// misreported as software custody in every list/get response. c.KeyStorageType
	// is empty only for CAs with no keystore-backed key (ImportCA/ImportCAChain),
	// where "software" remains the correct label -- there is no other backend.
	keyStorageType := c.KeyStorageType
	if keyStorageType == "" {
		keyStorageType = "software"
	}
	item := CAListItem{
		ID:             c.ID,
		Name:           c.Name,
		DisplayName:    c.Name,
		Type:           c.Type,
		Status:         c.Status,
		KeyStorageType: keyStorageType,
		CreatedAt:      c.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      c.CreatedAt.UTC().Format(time.RFC3339),
	}
	if c.ParentCAID != "" {
		item.ParentCAID = &c.ParentCAID
	}
	if len(c.CertPEM) > 0 {
		item.CertificatePEM = strings.TrimSpace(string(c.CertPEM))
	}
	if c.Certificate != nil {
		fp := certFingerprint(c.Certificate)
		item.CertificateFingerprintSHA256 = fp
		item.Certificate = &struct {
			FingerprintSHA256 string `json:"fingerprint_sha256"`
			SubjectDN         string `json:"subject_dn"`
			ValidFrom         string `json:"valid_from"`
			ValidUntil        string `json:"valid_until"`
			PublicKeyAlg      string `json:"public_key_algorithm"`
			KeySizeBits       int    `json:"key_size_bits"`
		}{
			FingerprintSHA256: fp,
			SubjectDN:         c.Certificate.Subject.String(),
			ValidFrom:         c.Certificate.NotBefore.UTC().Format(time.RFC3339),
			ValidUntil:        c.Certificate.NotAfter.UTC().Format(time.RFC3339),
			PublicKeyAlg:      ca.StoredPublicKeyAlgorithm(c.Certificate),
		}
	} else if len(c.CertPEM) > 0 {
		if block, _ := pem.Decode(c.CertPEM); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				fp := certFingerprint(cert)
				item.CertificateFingerprintSHA256 = fp
				item.Certificate = &struct {
					FingerprintSHA256 string `json:"fingerprint_sha256"`
					SubjectDN         string `json:"subject_dn"`
					ValidFrom         string `json:"valid_from"`
					ValidUntil        string `json:"valid_until"`
					PublicKeyAlg      string `json:"public_key_algorithm"`
					KeySizeBits       int    `json:"key_size_bits"`
				}{
					FingerprintSHA256: fp,
					SubjectDN:         cert.Subject.String(),
					ValidFrom:         cert.NotBefore.UTC().Format(time.RFC3339),
					ValidUntil:        cert.NotAfter.UTC().Format(time.RFC3339),
					PublicKeyAlg:      ca.StoredPublicKeyAlgorithm(cert),
				}
			}
		}
	}
	return item
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum)
}

func buildSubject(cn, org string) pkix.Name {
	n := pkix.Name{CommonName: cn}
	if org != "" {
		n.Organization = []string{org}
	}
	return n
}

func parseAlgorithm(s string) (keystore.Algorithm, error) {
	// Separators and case are ignored so "ML-DSA-65", "mldsa65" and
	// "ml-dsa-65" all resolve to the one canonical keystore spelling.
	switch strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s)) {
	case "ecdsap256", "p256":
		return keystore.ECDSAP256, nil
	case "ecdsap384", "p384":
		return keystore.ECDSAP384, nil
	case "rsa2048":
		return keystore.RSA2048, nil
	case "rsa4096":
		return keystore.RSA4096, nil
	case "mldsa44":
		return keystore.MLDSA44, nil
	case "mldsa65":
		return keystore.MLDSA65, nil
	case "mldsa87":
		return keystore.MLDSA87, nil
	default:
		return keystore.ECDSAP256, fmt.Errorf("unknown algorithm; supported: ECDSA-P256, ECDSA-P384, RSA-2048, RSA-4096, ML-DSA-44, ML-DSA-65, ML-DSA-87")
	}
}

// parseValidityStr parses a human validity string: "10y", "365d", or plain integer (days).
func parseValidityStr(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 10 * 365 * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "y") {
		years, err := strconv.Atoi(strings.TrimSuffix(s, "y"))
		if err != nil || years <= 0 {
			return 0, fmt.Errorf("invalid years")
		}
		return time.Duration(years) * 365 * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid days")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	days, err := strconv.Atoi(s)
	if err != nil || days <= 0 {
		return 0, fmt.Errorf("expected NNy or NNd")
	}
	return time.Duration(days) * 24 * time.Hour, nil
}
