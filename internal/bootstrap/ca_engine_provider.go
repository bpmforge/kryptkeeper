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
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/revsign"
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
	// backends is non-nil only when the hub runs several key backends (W23-11).
	backends KeyBackendSelector
	// revStore and invalidators are set by AttachRevocation (W23-34).
	revStore     ca.RevocationStore
	invalidators []RevocationCacheFlusher
}

// KeyBackendSelector is the slice of keystore.Router the CA create path needs
// to pin a new CA's key to one backend.
type KeyBackendSelector interface {
	Backends() []string
	WithCreateBackend(label string, fn func() error) error
}

// SetKeyBackends enables per-CA backend selection on CreateCA.
func (p *engineCAProvider) SetKeyBackends(s KeyBackendSelector) { p.backends = s }

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
		logging.Warnf("per-CA certificate counts unavailable: %v", err)
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

// DeleteCA removes a revoked or expired CA. The engine has no inventory, so
// the active-certificate check happens here; the engine refuses a CA that
// still has child CAs.
func (p *engineCAProvider) DeleteCA(ctx context.Context, id string) error {
	deleter, ok := p.engine.(interface{ DeleteCA(id string) error })
	if !ok {
		return errCACreateUnsupported
	}
	item, found, err := p.GetCA(ctx, id)
	if err != nil {
		return err
	}
	if !found {
		return errCANotFound
	}
	if st := caEffectiveStatus(item, time.Now()); st != "revoked" && st != "expired" {
		return errCAUnprocessable
	}
	if item.ActiveIssuedCertificates > 0 {
		return errCAConflict
	}
	err = deleter.DeleteCA(id)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ca.ErrCANotFound):
		return errCANotFound
	case errors.Is(err, ca.ErrCANotDeletable):
		return errCAUnprocessable
	case errors.Is(err, ca.ErrCAHasChildren),
		// Revoked/expired certificates still reference the CA row.
		strings.Contains(strings.ToLower(err.Error()), "foreign key"):
		return errCAConflict
	}
	return err
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
		if rb := rolledBack(err); rb != nil {
			return CAKeyRotationResult{}, rb
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

// rolledBack wraps a *ca.RotationRolledBackError so callers can match both
// errCARotationRolledBack and the typed error (for its step). It returns nil
// for any other error.
func rolledBack(err error) error {
	var rb *ca.RotationRolledBackError
	if errors.As(err, &rb) {
		return fmt.Errorf("%w: %w", errCARotationRolledBack, err)
	}
	return nil
}

// CAKeyRollover is the result of a cross-signed rollover: the re-key result
// plus the bridge and the retired certificate relying parties may still trust.
type CAKeyRollover struct {
	CAKeyRotationResult
	CrossCertPEM string `json:"cross_cert_pem"`
	OldCertPEM   string `json:"old_cert_pem"`
	OldKeyID     string `json:"old_key_id"`
}

// CARolloverRotator is an optional CAProvider capability (see CARotator).
type CARolloverRotator interface {
	RolloverCAKey(ctx context.Context, id, algorithm string) (CAKeyRollover, error)
}

// RolloverCAKey re-keys a CA and issues the cross-signed bridge. The engine
// verifies both chains with a probe leaf before returning.
func (p *engineCAProvider) RolloverCAKey(_ context.Context, id, algorithm string) (CAKeyRollover, error) {
	var algo keystore.Algorithm
	if trimmed := strings.TrimSpace(algorithm); trimmed != "" {
		parsed, err := parseAlgorithm(trimmed)
		if err != nil {
			return CAKeyRollover{}, fmt.Errorf("unsupported algorithm %q: %w", algorithm, err)
		}
		algo = parsed
	}
	cs, ok := p.engine.(interface {
		CrossSignRotate(string, ca.RotateCAOptions) (ca.CrossSignResult, error)
	})
	if !ok {
		return CAKeyRollover{}, errCARotateUnsupported
	}
	res, err := cs.CrossSignRotate(id, ca.RotateCAOptions{Algorithm: algo})
	if err != nil {
		if errors.Is(err, ca.ErrCANotFound) {
			return CAKeyRollover{}, errCANotFound
		}
		if rb := rolledBack(err); rb != nil {
			return CAKeyRollover{}, rb
		}
		return CAKeyRollover{}, err
	}
	out := CAKeyRollover{
		CAKeyRotationResult: CAKeyRotationResult{
			ID: res.RolledCA.ID, Status: res.RolledCA.Status, KeyID: res.RolledCA.KeyID,
			RotatedAt: res.Rotation.RotatedAt.UTC().Format(time.RFC3339),
			LedgerID:  res.Rotation.ID, LedgerPersisted: true,
		},
		CrossCertPEM: string(res.CrossCertPEM),
		OldCertPEM:   string(res.OldCertPEM),
		OldKeyID:     res.OldKeyID,
	}
	return out, nil
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
		return CAListItem{}, fmt.Errorf("create ca: %w", err)
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
	create := func() error {
		var cerr error
		caObj, cerr = p.createCAOnCurrentBackend(req, name, subject, algo, validity)
		return cerr
	}
	if req.KeyStorageType != "" {
		label := keystore.BackendLabelFromStorageType(req.KeyStorageType)
		if p.backends == nil {
			return CAListItem{}, errors.New("key backend selection needs KRYPTKEEPER_KEY_BACKENDS")
		}
		if strings.EqualFold(strings.TrimSpace(req.Type), "root") {
			if cerr := keystore.CheckRootKeyCustody(label); cerr != nil {
				return CAListItem{}, cerr
			}
		}
		err = p.backends.WithCreateBackend(label, create)
	} else {
		err = create()
	}
	if err != nil {
		return CAListItem{}, err
	}

	return caToListItem(caObj), nil
}

// createCAOnCurrentBackend runs the engine create for req; the key lands on
// whichever backend the keystore currently targets.
func (p *engineCAProvider) createCAOnCurrentBackend(req CACreateRequest, name string, subject pkix.Name, algo keystore.Algorithm, validity time.Duration) (*ca.CA, error) {
	var caObj *ca.CA
	var err error
	switch strings.ToLower(req.Type) {
	case "root":
		caObj, err = p.engine.CreateRootCA(name, subject, algo, validity)
	case "intermediate":
		if req.ParentCAID == "" {
			return nil, fmt.Errorf("parent_ca_id required for intermediate CA")
		}
		// W23-04: under a keyless parent (an imported offline root) the hub
		// cannot sign, so it generates the key and hands back a CSR instead.
		if csr, ok := p.engine.(csrEngine); ok {
			if parent, perr := p.engine.GetCA(req.ParentCAID); perr == nil && parent.KeyID == "" {
				caObj, err = csr.CreateIntermediateCSR(name, subject, algo, req.ParentCAID)
				break
			}
		}
		caObj, err = p.engine.CreateIntermediateCA(name, subject, algo, req.ParentCAID, validity)
	default:
		return nil, fmt.Errorf("type must be 'root' or 'intermediate'")
	}
	return caObj, err
}

// csrEngine is the slice of *ca.Engine the CACSRProvider capability needs.
type csrEngine interface {
	CreateIntermediateCSR(name string, subject pkix.Name, algo keystore.Algorithm, parentCAID string) (*ca.CA, error)
	GetCSR(caID string) ([]byte, error)
	CompleteIntermediateCA(caID string, certPEM []byte) (*ca.CA, error)
}

// GetCSR implements CACSRProvider.
func (p *engineCAProvider) GetCSR(_ context.Context, id string) (string, error) {
	e, ok := p.engine.(csrEngine)
	if !ok {
		return "", errCACreateUnsupported
	}
	csr, err := e.GetCSR(id)
	if err != nil {
		return "", mapTrustAnchorErr(err)
	}
	return strings.TrimSpace(string(csr)), nil
}

// CompleteCA implements CACSRProvider.
func (p *engineCAProvider) CompleteCA(_ context.Context, id string, certPEM []byte) (CAListItem, error) {
	e, ok := p.engine.(csrEngine)
	if !ok {
		return CAListItem{}, errCACreateUnsupported
	}
	c, err := e.CompleteIntermediateCA(id, certPEM)
	if err != nil {
		return CAListItem{}, mapTrustAnchorErr(err)
	}
	return caToListItem(c), nil
}

// trustAnchorEngine is the slice of *ca.Engine the CAImporter capability needs.
type trustAnchorEngine interface {
	ImportCA(name string, certPEM []byte) (*ca.CA, error)
	CheckTrustAnchorRemovable(id string) error
	RemoveTrustAnchor(id string) error
}

func (p *engineCAProvider) trustAnchors() (trustAnchorEngine, error) {
	e, ok := p.engine.(trustAnchorEngine)
	if !ok {
		return nil, errCACreateUnsupported
	}
	return e, nil
}

// ImportRootCA implements CAImporter.
func (p *engineCAProvider) ImportRootCA(_ context.Context, name string, certPEM []byte) (CAListItem, error) {
	e, err := p.trustAnchors()
	if err != nil {
		return CAListItem{}, err
	}
	c, err := e.ImportCA(name, certPEM)
	if err != nil {
		return CAListItem{}, err
	}
	return caToListItem(c), nil
}

// CheckTrustAnchorRemovable implements CAImporter.
func (p *engineCAProvider) CheckTrustAnchorRemovable(_ context.Context, id string) error {
	e, err := p.trustAnchors()
	if err != nil {
		return err
	}
	return mapTrustAnchorErr(e.CheckTrustAnchorRemovable(id))
}

// RemoveTrustAnchor implements CAImporter.
func (p *engineCAProvider) RemoveTrustAnchor(_ context.Context, id string) error {
	e, err := p.trustAnchors()
	if err != nil {
		return err
	}
	return mapTrustAnchorErr(e.RemoveTrustAnchor(id))
}

func mapTrustAnchorErr(err error) error {
	if errors.Is(err, ca.ErrCANotFound) {
		return errCANotFound
	}
	return err
}

// caToListItem converts a ca.CA engine object to the API-layer CAListItem.
func caToListItem(c *ca.CA) CAListItem {
	// W19-08/W23-10: the stored backend label in the canonical vocabulary;
	// a CA with no label (legacy imports) reads as "software".
	keyStorageType := ca.NormalizeKeyStorageType(c.KeyStorageType)
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
	item.RevocationSigning = revsign.RevocationSigningClassical
	if len(c.CertPEM) > 0 {
		item.CertificatePEM = strings.TrimSpace(string(c.CertPEM))
	}
	if len(c.CSRPEM) > 0 {
		item.CSRPEM = strings.TrimSpace(string(c.CSRPEM))
	}
	if c.Certificate != nil && c.Certificate.PublicKeyAlgorithm == x509.Ed25519 {
		item.Warnings = append(item.Warnings, ed25519ListWarning)
	}
	if c.Certificate != nil {
		fp := certFingerprint(c.Certificate)
		item.CertificateFingerprintSHA256 = fp
		if revsign.IsMLDSAIssuer(c.Certificate) {
			item.RevocationSigning = revsign.RevocationSigningMLDSA
		}
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
				if revsign.IsMLDSAIssuer(cert) {
					item.RevocationSigning = revsign.RevocationSigningMLDSA
				}
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

// caSupportedAlgorithms is the single source of truth for the algorithms
// POST /cas accepts. The 400 body and parseAlgorithm's error both list it.
var caSupportedAlgorithms = []string{"ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072", "RSA-4096",
	"Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}

// errUnsupportedCAAlgorithm marks a caller-supplied algorithm outside the set.
var errUnsupportedCAAlgorithm = errors.New("unsupported ca algorithm")

// ed25519ListWarning is surfaced on CAs whose key is Ed25519.
const ed25519ListWarning = "Ed25519 chains are not validated by Windows/ADCS clients or many TLS stacks; use for internal, SSH and workload CAs, not for WSTEP/autoenrollment"

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
	case "rsa3072":
		return keystore.RSA3072, nil
	case "rsa4096":
		return keystore.RSA4096, nil
	case "ed25519":
		return keystore.Ed25519, nil
	case "mldsa44":
		return keystore.MLDSA44, nil
	case "mldsa65":
		return keystore.MLDSA65, nil
	case "mldsa87":
		return keystore.MLDSA87, nil
	default:
		return keystore.ECDSAP256, fmt.Errorf("%w %q; supported: %s", errUnsupportedCAAlgorithm, s, strings.Join(caSupportedAlgorithms, ", "))
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

// RevocationCacheFlusher is a CRL/OCSP cache RevokeCA can flush: the revoked
// CA's serial, and everything (children's cached "good" answers).
type RevocationCacheFlusher interface {
	ca.RevocationCacheInvalidator
	InvalidateAll()
}

// AttachRevocation gives a CA provider the revocation store and the CRL/OCSP
// caches that RevokeCA must tell. It reports whether p supports revocation.
func AttachRevocation(p CAProvider, rs ca.RevocationStore, inv ...RevocationCacheFlusher) bool {
	ep, ok := p.(*engineCAProvider)
	if !ok {
		return false
	}
	ep.revStore = rs
	ep.invalidators = inv
	return true
}

// RevokeCA implements CARevoker (W23-34).
func (p *engineCAProvider) RevokeCA(ctx context.Context, id string) (CARevokeResult, error) {
	certs, descendants, err := p.CARevokeBlastRadius(ctx, id)
	if err != nil {
		return CARevokeResult{}, err
	}
	rev, err := ca.RevokeCA(p.engine, p.revStore, id, time.Now())
	if err != nil {
		if errors.Is(err, ca.ErrCANotFound) {
			return CARevokeResult{}, errCANotFound
		}
		return CARevokeResult{}, err
	}
	if rev.Serial != nil {
		for _, inv := range p.invalidators {
			inv.InvalidateCache(rev.Serial)
			// Cached "good" answers for the CA's children must go too.
			inv.InvalidateAll()
		}
	}
	return CARevokeResult{
		ID: id, Status: "revoked", Reason: "cACompromise", StatusOnly: rev.StatusOnly,
		AffectedCerts: certs, DescendantCAs: descendants,
		RevokedAt: rev.RevokedAt.UTC().Format(time.RFC3339),
	}, nil
}

// CARevokeBlastRadius counts the active certificates issued by the CA and
// every descendant CA, and the descendant CAs themselves.
func (p *engineCAProvider) CARevokeBlastRadius(ctx context.Context, id string) (certs, descendants int, err error) {
	if _, err := p.engine.GetCA(id); err != nil {
		if errors.Is(err, ca.ErrCANotFound) {
			return 0, 0, errCANotFound
		}
		return 0, 0, err
	}
	all, err := p.engine.ListCAs()
	if err != nil {
		return 0, 0, err
	}
	children := map[string][]string{}
	for _, c := range all {
		if c.ParentCAID != "" {
			children[c.ParentCAID] = append(children[c.ParentCAID], c.ID)
		}
	}
	counts := p.loadCertCounts(ctx)
	seen := map[string]bool{id: true}
	queue := []string{id}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		certs += counts[cur]
		for _, ch := range children[cur] {
			if !seen[ch] {
				seen[ch] = true
				descendants++
				queue = append(queue, ch)
			}
		}
	}
	return certs, descendants, nil
}
