// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/metrics"
	"net/url"
	"strings"
	"sync"
	"time"
)

type caCertificateProvider struct {
	engine    ca.Service
	revStore  ca.RevocationStore // may be nil when no DB is configured
	db        *sql.DB            // may be nil when no DB is configured
	postgres  bool
	templates TemplateProvider // may be nil; when set, policy is enforced at issuance
	mu        sync.RWMutex
	certs     map[string]*storedCert // keyed by fingerprint
	// Derived indexes, all guarded by mu and kept in step with certs by
	// addLocked/removeLocked (certificate_index.go): order is the list order
	// (created_at desc, fingerprint asc) so a page is a slice window instead
	// of a copy+sort of the whole map (H3/M3); spkiIdx maps a public-key hash
	// to its holders so key-reuse detection is O(1) per insert (M1); and
	// activeByCA is the per-CA active count that used to be a GROUP BY per
	// issuance (M1).
	order      []*storedCert
	spkiIdx    map[string][]string
	activeByCA map[string]int
	// hydrateErr records a failed startup load (S-50). Non-nil means the
	// in-memory map is NOT a faithful view of the database, so reporting an
	// empty inventory would be a lie rather than a fact.
	hydrateErr error
	// ocspInvalidator tells a live OCSP responder that a just-revoked
	// serial's cached response is stale -- see ca.RevocationCacheInvalidator
	// and the identical seam in internal/acme (W19-01). Optional: nil means
	// RevokeCertificate still updates revStore, it just can't clear OCSP's
	// cache for the serial.
	ocspInvalidator ca.RevocationCacheInvalidator
	// upstreamRevoker revokes certificates at the upstream CA behind their
	// connector (W36-03); nil keeps the pre-1.1 inventory-only behaviour.
	upstreamRevoker UpstreamRevoker
	// Lazy pickup of rows other writers (discovery, peer hub replicas) add or
	// change in the certificates table after startup; see
	// certificate_discovery_refresh.go.
	discoveryRefreshEvery time.Duration
	refreshMu             sync.Mutex // serialises refreshes; never held with mu
	tableWatermark        time.Time  // newest updated_at already merged
	lastTableRefresh      time.Time
}

type storedCert struct {
	item    CertificateItem
	certPEM []byte
	x509    *x509.Certificate
	spki    string // spkiHash of x509; empty when x509 is nil
}

// NewCACertificateProvider creates a certificate provider backed by a real CA engine.
// revStore, db, and templates are optional (pass nil for in-memory-only behaviour).
func NewCACertificateProvider(engine ca.Service, revStore ca.RevocationStore, db *sql.DB, postgres bool) CertificateProvider {
	p := &caCertificateProvider{
		engine:   engine,
		revStore: revStore,
		db:       db,
		postgres: postgres,
		certs:    make(map[string]*storedCert),

		discoveryRefreshEvery: defaultDiscoveryRefreshEvery,
	}
	if db != nil {
		// S-50: a failed hydrate used to be discarded, leaving the provider
		// with an empty map — a database hiccup at boot made the entire
		// inventory disappear from the UI, reports, expiry monitoring and
		// renewal while every screen looked healthy. Record it so
		// ListCertificates reports a failure instead of an empty inventory.
		if err := p.loadCertsFromDB(); err != nil {
			p.hydrateErr = err
			logging.Warnf("certificate provider: failed to load certificates from DB, "+
				"inventory will report an error rather than an empty list: %v", err)
		}
	}
	return p
}

// loadCertsFromDB hydrates the in-memory cert map from the certificates table.
// Called once at startup. A failure is recorded as hydrateErr rather than
// discarded (S-50): the map is then not a faithful view of the database, and
// serving it as an empty inventory would report "no certificates" for a
// database full of them.
func (p *caCertificateProvider) loadCertsFromDB() error {
	loaded, err := p.queryCerts("")
	if err != nil {
		return err
	}
	p.mu.Lock()
	for _, sc := range loaded {
		p.putUnindexedLocked(sc.item.FingerprintSHA256, sc)
	}
	// One sort and one key-reuse pass for the whole load, not one per row.
	p.rebuildIndexLocked()
	p.flagAllKeyReuseLocked()
	p.mu.Unlock()
	p.noteTableWatermark(loaded)
	return nil
}

// queryCerts reads certificates rows (optionally narrowed by a trailing SQL
// clause with ?-style placeholders in args) into storedCerts without touching
// the in-memory indexes. Every nullable column is COALESCEd here: discovery
// writes rows with NULL issuer_cn, key_size_bits, key usages and so on, and a
// plain-string Scan of a NULL fails the whole row, which silently dropped
// every discovered certificate from the inventory.
func (p *caCertificateProvider) queryCerts(where string, args ...any) ([]*storedCert, error) {
	// Postgres stores subject_alt_names/extended_key_usage/key_usage/risk_flags
	// as native TEXT[] and chain_complete/chain_trusted/pqc_vulnerable as native
	// BOOLEAN (see writeCertToDB); sqlite has neither type and stores the same
	// data as JSON-encoded text and 0/1 integers. Normalizing to the sqlite
	// shape in the query itself lets the scan targets and json.Unmarshal calls
	// below stay identical for both backends.
	query := `
		SELECT fingerprint_sha256, serial_number, COALESCE(common_name,''), subject_dn,
		       COALESCE(subject_alt_names,'[]'), issuer_dn, COALESCE(issuer_cn,''), ca_id, template_id,
		       team_id, valid_from, valid_until, public_key_algorithm, COALESCE(key_size_bits,0),
		       signature_algorithm, COALESCE(extended_key_usage,'[]'), COALESCE(key_usage,'[]'),
		       chain_complete, chain_trusted, pqc_vulnerable, COALESCE(pqc_readiness,''),
		       risk_score, risk_flags, grade, renewal_method, renewal_status,
		       source, raw_cert_b64, revoked_at, revocation_reason,
		       created_at, updated_at,
		       COALESCE(owner_email,''), COALESCE(owner_team,''), COALESCE(service_name,''), COALESCE(labels,'[]'), COALESCE(ownership_source,''),
		       COALESCE(origin,''), COALESCE(management_state,''), COALESCE(renewal_connector_id,''),
		       COALESCE(trust_class,''), COALESCE(template_revision,0),
		       COALESCE(predecessor_fingerprint,''), COALESCE(successor_fingerprint,'')
		FROM certificates`
	notChainCA := " COALESCE(is_ca,0) = 0"
	if p.postgres {
		query = `
		SELECT fingerprint_sha256, serial_number, COALESCE(common_name,''), subject_dn,
		       COALESCE(array_to_json(subject_alt_names)::text, '[]'), issuer_dn, COALESCE(issuer_cn,''), ca_id, template_id,
		       team_id, valid_from, valid_until, public_key_algorithm, COALESCE(key_size_bits,0),
		       signature_algorithm, COALESCE(array_to_json(extended_key_usage)::text, '[]'), COALESCE(array_to_json(key_usage)::text, '[]'),
		       CASE WHEN chain_complete THEN 1 ELSE 0 END, CASE WHEN chain_trusted THEN 1 ELSE 0 END, CASE WHEN pqc_vulnerable THEN 1 ELSE 0 END, COALESCE(pqc_readiness,''),
		       risk_score, COALESCE(array_to_json(risk_flags)::text, '[]'), grade, renewal_method, renewal_status,
		       source, raw_cert_b64, revoked_at, revocation_reason,
		       created_at, updated_at,
		       COALESCE(owner_email,''), COALESCE(owner_team,''), COALESCE(service_name,''), COALESCE(labels,'[]'), COALESCE(ownership_source,''),
		       COALESCE(origin,''), COALESCE(management_state,''), COALESCE(renewal_connector_id,''),
		       COALESCE(trust_class,''), COALESCE(template_revision,0),
		       COALESCE(predecessor_fingerprint,''), COALESCE(successor_fingerprint,'')
		FROM certificates`
		notChainCA = " NOT COALESCE(is_ca, FALSE)"
	}
	// Intermediates/roots captured from a served chain stay in the table
	// (queryable via discovery) but are not leaf inventory.
	if where == "" {
		where = " WHERE" + notChainCA
	} else {
		where += " AND" + notChainCA
	}
	rows, err := p.db.Query(query+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var loaded []*storedCert
	for rows.Next() {
		var (
			fp, serial, cn, subjectDN            string
			sanJSON, issuerDN, issuerCN          string
			caID, templateID, teamID             sql.NullString
			validFrom, validUntil                string
			pkaStr                               string
			keySizeBits                          int
			sigAlgo                              string
			ekuJSON, kuJSON                      string
			chainComplete, chainTrusted, pqcVuln int
			pqcReadiness                         string
			riskScore                            int
			riskFlagsJSON, grade                 string
			renewalMethod, renewalStatus, source sql.NullString
			rawCertB64                           sql.NullString
			revokedAt                            sql.NullString
			revocationReason                     sql.NullInt64
			createdAt, updatedAt                 string
			ownerEmail, ownerTeam, serviceName   string
			ownershipSource                      string
			labelsJSON                           string
			origin, managementState              string
			renewalConnectorID                   string
			trustClass                           string
			predecessorFP, successorFP           string
			templateRevision                     int
		)

		if err := rows.Scan(
			&fp, &serial, &cn, &subjectDN,
			&sanJSON, &issuerDN, &issuerCN, &caID, &templateID,
			&teamID, &validFrom, &validUntil, &pkaStr, &keySizeBits,
			&sigAlgo, &ekuJSON, &kuJSON,
			&chainComplete, &chainTrusted, &pqcVuln, &pqcReadiness,
			&riskScore, &riskFlagsJSON, &grade, &renewalMethod, &renewalStatus,
			&source, &rawCertB64, &revokedAt, &revocationReason,
			&createdAt, &updatedAt,
			&ownerEmail, &ownerTeam, &serviceName, &labelsJSON, &ownershipSource,
			&origin, &managementState, &renewalConnectorID, &trustClass, &templateRevision,
			&predecessorFP, &successorFP,
		); err != nil {
			// S-50: skipping is right — one unreadable row should not cost
			// the whole inventory — but it must not be silent.
			logging.Infof("certificate row skipped during load (it will be missing from the inventory): %v", err)
			continue
		}

		var sans, ekus, kus, riskFlags, labels []string
		_ = json.Unmarshal([]byte(sanJSON), &sans)            // corrupt row degrades to zero value, not a fatal
		_ = json.Unmarshal([]byte(ekuJSON), &ekus)            // corrupt row degrades to zero value, not a fatal
		_ = json.Unmarshal([]byte(kuJSON), &kus)              // corrupt row degrades to zero value, not a fatal
		_ = json.Unmarshal([]byte(riskFlagsJSON), &riskFlags) // corrupt row degrades to zero value, not a fatal
		_ = json.Unmarshal([]byte(labelsJSON), &labels)       // corrupt row degrades to zero value, not a fatal

		item := CertificateItem{
			FingerprintSHA256:  fp,
			SerialNumber:       serial,
			CommonName:         cn,
			SubjectDN:          subjectDN,
			SubjectAltNames:    sans,
			URISANs:            uriSANsFromRawCert(rawCertB64.String),
			IssuerCN:           issuerCN,
			IssuerDN:           issuerDN,
			CAID:               caID.String,
			TemplateID:         templateID.String,
			TemplateRevision:   templateRevision,
			TeamID:             teamID.String,
			ValidFrom:          validFrom,
			ValidUntil:         validUntil,
			PublicKeyAlgorithm: pkaStr,
			KeySizeBits:        keySizeBits,
			SignatureAlgorithm: sigAlgo,
			ExtendedKeyUsage:   ekus,
			KeyUsage:           kus,
			ChainComplete:      chainFact(origin, chainComplete == 1),
			ChainTrusted:       chainFact(origin, chainTrusted == 1),
			PQCVulnerable:      pqcVuln == 1,
			PQCReadiness:       pqcReadiness,
			RiskScore:          riskScore,
			RiskFlags:          riskFlags,
			Grade:              grade,
			RenewalMethod:      renewalMethod.String,
			RenewalStatus:      renewalStatus.String,
			Source:             source.String,
			CreatedAt:          createdAt,
			UpdatedAt:          updatedAt,
			OwnerEmail:         ownerEmail,
			OwnerTeam:          ownerTeam,
			OwnershipSource:    ownershipSource,
			ServiceName:        serviceName,
			Labels:             labels,
			Origin:             origin,
			ManagementState:    managementState,
			RenewalConnectorID: renewalConnectorID,
			TrustClass:         trustClass,
		}
		// The renewal chain is row state a peer replica wrote; without it
		// this replica would accept a second renewal of a superseded cert.
		if predecessorFP != "" {
			item.PredecessorFP = &predecessorFP
		}
		if successorFP != "" {
			item.SuccessorFP = &successorFP
		}
		// Discovery never writes a grade (the column defaults to 'A'), so a
		// risky discovered cert would read as grade A. Derive it from the
		// stored score the same way issuance does.
		if isDiscoverySource(item.Source) {
			item.Grade = computeGrade(item.RiskScore)
		}
		// Defensive derivation (spec decision 3): a snapshot restored from a
		// pre-000043 database loads with empty estate fields — derive them
		// from source so the estate model is never silently absent.
		if item.Origin == "" || item.ManagementState == "" {
			item.Origin = estateOrigin(item)
			item.ManagementState = estateManagementState(item)
		}

		if revokedAt.Valid {
			item.RevokedAt = &revokedAt.String
		}
		if revocationReason.Valid {
			rc := int(revocationReason.Int64)
			item.RevocationReason = &rc
		}

		var parsed *x509.Certificate
		var certPEM []byte
		if rawCertB64.Valid && rawCertB64.String != "" {
			certPEM = []byte(rawCertB64.String)
			if block, _ := pem.Decode(certPEM); block != nil {
				parsed, _ = x509.ParseCertificate(block.Bytes)
			}
		}

		// Rows written before 000051 have no stored classification, and a
		// missing one reads as not_applicable — which is what made the
		// posture report claim 0 vulnerable. Derive it from the stored
		// certificate instead of leaving the estate permanently
		// unclassified until every certificate happens to be re-issued.
		// It is a pure function of the certificate and its chain, so
		// deriving it here yields exactly what issuance would have.
		if item.PQCReadiness == "" && parsed != nil {
			item.PQCReadiness = computePQCReadiness(parsed, resolveChainClassical(p.engine, item.CAID, parsed))
		}

		// publicKeyBits used to be a stub, so every previously issued row
		// stores 0. Recompute from the stored certificate so the weak-key
		// posture is real without a data migration.
		if item.KeySizeBits == 0 && parsed != nil {
			item.KeySizeBits = publicKeyBits(parsed)
		}

		loaded = append(loaded, &storedCert{item: item, certPEM: certPEM, x509: parsed})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return loaded, nil
}

// spkiHash returns a hex-encoded SHA-256 hash of the certificate's SubjectPublicKeyInfo DER bytes.
func spkiHash(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", sha256.Sum256(cert.RawSubjectPublicKeyInfo))
}

// WithTemplateProvider attaches a TemplateProvider for policy enforcement at issuance time.
// Returns the provider itself for chaining.
func WithTemplateProvider(p CertificateProvider, tp TemplateProvider) CertificateProvider {
	if ca, ok := p.(*caCertificateProvider); ok {
		ca.templates = tp
	}
	return p
}

func (p *caCertificateProvider) IssueCertificate(ctx context.Context, req CertificateIssueRequest) (CertificateIssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil {
		return CertificateIssueResult{}, errCertificateInvalid
	}

	// Apply template policy when a template is specified and a provider is wired in.
	issuanceReq := ca.IssuanceRequest{
		TemplateID:  req.TemplateID,
		Validity:    90 * 24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if err := parseCSRBlock(block, &issuanceReq); err != nil {
		return CertificateIssueResult{}, err
	}

	var templateRevision int
	if req.TemplateID != "" && p.templates != nil {
		tpl, found, terr := p.templates.GetTemplate(ctx, req.TemplateID)
		if terr != nil {
			return CertificateIssueResult{}, fmt.Errorf("template lookup: %w", terr)
		}
		if !found {
			return CertificateIssueResult{}, fmt.Errorf("%w: template %q not found", ca.ErrPolicyViolation, req.TemplateID)
		}
		if !tpl.Active {
			return CertificateIssueResult{}, fmt.Errorf("%w: template %q is inactive", ca.ErrPolicyViolation, req.TemplateID)
		}
		// W23-42: before the approval branch so a denied role never queues a
		// request. The approval re-entry already passed this check for the
		// requester; the approver's role is not an enrollment role.
		if ctx.Value(approvalBypassKey{}) == nil {
			if err := ca.CheckEnrollment(ctx, tpl.ID, tpl.EnrollRoles()); err != nil {
				return CertificateIssueResult{}, err
			}
		}
		// W26-23: refuse an unattested code-signing CSR before anything is queued.
		if ctx.Value(approvalBypassKey{}) == nil {
			if err := codesignPreIssueCheck(ctx, tpl, req); err != nil {
				return CertificateIssueResult{}, err
			}
		}
		// W26-32: checked after the policy gates above and before the approval
		// queue, so a repeat POST on an approval template returns the issued cert.
		if res, ok := p.reuseIssued(ctx, req, issuanceReq.CSR, tpl.Revision); ok {
			return res, nil
		}
		if err := applyTemplateToIssuance(&issuanceReq, tpl); err != nil {
			return CertificateIssueResult{}, err
		}
		if templateNeedsApproval(tpl) && ctx.Value(approvalBypassKey{}) == nil {
			// Dry-run the checks the post-approval issuance will run, so a
			// request the engine would refuse is never queued.
			if err := p.dryPolicyCheck(req.CAID, issuanceReq); err != nil {
				return CertificateIssueResult{}, err
			}
			return CertificateIssueResult{}, errApprovalRequired
		}
		templateRevision = tpl.Revision
	} else {
		if req.TemplateID == "" {
			// SUP-A04-3: issuance without a template is allowed (existing
			// behaviour) but has no name policy; leave a trail of it.
			logging.Infof("certificate issuance without a template: no name policy applied (ca=%s)", req.CAID)
		}
		if res, ok := p.reuseIssued(ctx, req, issuanceReq.CSR, 0); ok {
			return res, nil
		}
	}

	// W23-25: a (CA, serial) clash is rejected by idx_cert_serial_ca; the
	// engine is called again so the retry signs with a fresh serial. Nothing
	// stays stored from a failed attempt (removeLocked above).
	var (
		issued *ca.IssuedCertificate
		item   CertificateItem
	)
	err := ca.RetryOnSerialCollision(5, func(int) error {
		var err error
		issued = nil
		t0 := time.Now()
		issued, err = p.engine.IssueCertificate(req.CAID, issuanceReq)
		metrics.CertIssueDuration.Observe(time.Since(t0).Seconds())
		if err != nil {
			metrics.CertIssueErrors.Inc()
			err = classifyKeystoreFailure(req.CAID, err)
			return wrapEngineIssueError("ca issuance failed", err)
		}
		metrics.CertIssueTotal.Inc()

		now := time.Now().UTC().Format(time.RFC3339)
		chainClassical := resolveChainClassical(p.engine, req.CAID, issued.Certificate)
		item = CertificateItem{
			FingerprintSHA256:  issued.Fingerprint,
			SerialNumber:       issued.SerialNumber.String(),
			CommonName:         issued.Certificate.Subject.CommonName,
			SubjectDN:          issued.Certificate.Subject.String(),
			SubjectAltNames:    ca.SubjectAltNameStrings(issued.Certificate),
			URISANs:            uriStrings(issued.Certificate.URIs),
			IssuerCN:           issued.Certificate.Issuer.CommonName,
			IssuerDN:           issued.Certificate.Issuer.String(),
			CAID:               req.CAID,
			TemplateID:         req.TemplateID,
			TemplateRevision:   templateRevision,
			TeamID:             req.TeamID,
			ValidFrom:          issued.Certificate.NotBefore.UTC().Format(time.RFC3339),
			ValidUntil:         issued.Certificate.NotAfter.UTC().Format(time.RFC3339),
			PublicKeyAlgorithm: ca.StoredPublicKeyAlgorithm(issued.Certificate),
			KeySizeBits:        publicKeyBits(issued.Certificate),
			SignatureAlgorithm: issued.Certificate.SignatureAlgorithm.String(),
			ExtendedKeyUsage:   ekuStrings(issued.Certificate.ExtKeyUsage),
			KeyUsage:           kuStrings(issued.Certificate.KeyUsage),
			ChainComplete:      boolRef(true),
			ChainTrusted:       boolRef(true),
			PQCVulnerable:      isPQCVulnerable(issued.Certificate),
			PQCReadiness:       computePQCReadiness(issued.Certificate, chainClassical),
			RiskScore:          adjustRiskForChain(computeRiskScore(issued.Certificate, time.Now()), true),
			RiskFlags:          adjustFlagsForChain(computeRiskFlags(issued.Certificate, chainClassical, time.Now()), true),
			Grade:              computeGrade(adjustRiskForChain(computeRiskScore(issued.Certificate, time.Now()), true)),
			RenewalMethod:      "manual",
			RenewalStatus:      string(RenewalStatusActive),
			Source:             "api",
			Origin:             "internal",
			ManagementState:    "managed",
			ETag:               1,
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		// addLocked derives this on the stored copy only; the response item is a
		// separate value and would otherwise omit it.
		item.KeyAlgorithmDisplay = keyAlgorithmDisplay(issued.Certificate)
		p.markExternalIssuance(&item)

		// An external CA's chain is the one its response verified (W36-02);
		// GetCAChain only knows the operator's trust anchor.
		storedPEM := issued.CertPEM
		if len(issued.ChainPEM) > 0 {
			storedPEM = append(append([]byte(nil), issued.CertPEM...), issued.ChainPEM...)
		}
		p.mu.Lock()
		p.addLocked(issued.Fingerprint, &storedCert{
			item:    item,
			certPEM: storedPEM,
			x509:    issued.Certificate,
		})
		p.mu.Unlock()

		// S-50: persist BEFORE reporting success, and fail the request if the
		// record cannot be written. This used to be `_ = p.writeCertToDB(...)`:
		// the API returned 200, the UI listed the cert — and after a restart it
		// was gone with nothing logged (observed live: 3 certificates served by
		// the API while the table held none). Failing is the safe side: the
		// signed leaf never leaves this process, so the only residue is a
		// consumed serial; success would hand out a credential this system can
		// never inventory, renew, expire or revoke.
		if p.db != nil {
			if err := p.writeCertToDB(item, storedPEM); err != nil {
				p.mu.Lock()
				p.removeLocked(issued.Fingerprint)
				p.mu.Unlock()
				return err
			}
		}
		return nil
	})
	if err != nil {
		if issued != nil {
			logging.Warnf("ISSUANCE NOT RECORDED: signed but failed to persist — fingerprint=%s serial=%s ca=%s: %v",
				issued.Fingerprint, item.SerialNumber, item.CAID, err)
			return CertificateIssueResult{}, fmt.Errorf(
				"certificate was signed but could not be recorded (fingerprint %s): %w", issued.Fingerprint, err)
		}
		return CertificateIssueResult{}, err
	}

	p.flagKeyReuse(issued.Fingerprint)

	return CertificateIssueResult{CertificateItem: item}, nil
}

// dryPolicyCheck runs the template-policy and engine-policy gates exactly as
// the signing path does, without signing or consuming a serial. A CSR the
// engine cannot dry-check (non-classical, no policy engine) passes; the
// signing path remains the authority.
func (p *caCertificateProvider) dryPolicyCheck(caID string, req ca.IssuanceRequest) error {
	if req.CSR == nil {
		return nil
	}
	if req.Policy != nil {
		if err := ca.ValidateAgainstTemplate(req, *req.Policy); err != nil {
			return err
		}
	}
	if pe, ok := p.engine.(interface{ PolicyEngine() *ca.PolicyEngine }); ok {
		if eng := pe.PolicyEngine(); eng != nil {
			return eng.Check(caID, req)
		}
	}
	return nil
}

// reuseIssued answers an idempotent repeat (W26-32). The approval re-entry
// never reuses: an approver completing a request always signs.
func (p *caCertificateProvider) reuseIssued(ctx context.Context, req CertificateIssueRequest, csr *x509.CertificateRequest, templateRevision int) (CertificateIssueResult, bool) {
	if ctx.Value(approvalBypassKey{}) != nil {
		return CertificateIssueResult{}, false
	}
	item, ok := p.findReusableCertificate(req, csr, templateRevision, time.Now())
	if !ok {
		return CertificateIssueResult{}, false
	}
	return CertificateIssueResult{CertificateItem: item, Reused: true}, true
}

func (p *caCertificateProvider) RevokeCertificate(ctx context.Context, fingerprint string, req CertificateRevokeRequest) (CertificateRevokeResult, error) {
	p.ensureCertLoaded(fingerprint)
	p.mu.Lock()
	locked := true
	defer func() {
		if locked {
			p.mu.Unlock()
		}
	}()

	stored, ok := p.certs[fingerprint]
	if !ok {
		metrics.CertRevokeErrors.Inc()
		return CertificateRevokeResult{}, errCertificateNotFound
	}
	if stored.item.RevokedAt != nil {
		metrics.CertRevokeErrors.Inc()
		return CertificateRevokeResult{}, errCertificateConflict
	}
	if req.Scope != "" && req.Scope != RevocationScopeInventoryOnly {
		metrics.CertRevokeErrors.Inc()
		return CertificateRevokeResult{}, fmt.Errorf("%w: scope must be empty or inventory_only", errCertificateInvalid)
	}

	external := p.isExternalCA(stored.item.CAID)
	hubCA := stored.item.CAID != "" && !external
	connID := stored.item.RenewalConnectorID
	scope := RevocationScopeCA
	switch {
	case req.Scope == RevocationScopeInventoryOnly:
		if hubCA {
			metrics.CertRevokeErrors.Inc()
			return CertificateRevokeResult{}, fmt.Errorf("%w: inventory_only applies only to certificates no hub CA issued", errCertificateInvalid)
		}
		scope = RevocationScopeInventoryOnly
	case connID != "" && p.upstreamRevoker != nil && p.upstreamRevoker.SupportsRevoke(ctx, connID) && !hubCA:
		scope = RevocationScopeUpstream
	case external:
		// D-306: an external CA's certificate is revoked at that CA or, by an
		// admin's explicit choice, only here -- never silently only here.
		metrics.CertRevokeErrors.Inc()
		return CertificateRevokeResult{}, ErrUpstreamRevokeUnsupported
	case stored.item.CAID == "":
		// A certificate with no issuing CA in this hub (imported, discovered,
		// synced) has no CRL or OCSP responder to publish to, and revStore
		// keys rows by (serial, ca_id) so it can never match one. Record the
		// revocation in the inventory row by fingerprint instead of failing
		// the request with a misleading 503; revoking at the real issuer stays
		// the operator's job.
		scope = RevocationScopeInventoryOnly
	}

	if scope == RevocationScopeUpstream {
		if stored.x509 == nil {
			metrics.CertRevokeErrors.Inc()
			return CertificateRevokeResult{}, fmt.Errorf("%w: certificate body unavailable for upstream revocation", errCertificateInvalid)
		}
		upReq := connectors.RevokeRequest{
			SerialHex:      fmt.Sprintf("%x", stored.x509.SerialNumber),
			CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stored.x509.Raw})),
			Reason:         req.ReasonCode,
		}
		// The upstream call can take seconds; never hold the inventory lock
		// across it.
		p.mu.Unlock()
		locked = false
		err := p.upstreamRevoker.RevokeUpstream(ctx, connID, upReq)
		if err != nil {
			metrics.CertRevokeErrors.Inc()
			return CertificateRevokeResult{}, &UpstreamRevokeError{ConnectorID: connID, Err: err}
		}
		p.mu.Lock()
		locked = true
		stored, ok = p.certs[fingerprint]
		if !ok {
			metrics.CertRevokeErrors.Inc()
			return CertificateRevokeResult{}, errCertificateNotFound
		}
		if stored.item.RevokedAt != nil {
			metrics.CertRevokeErrors.Inc()
			return CertificateRevokeResult{}, errCertificateConflict
		}
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	if scope != RevocationScopeCA {
		if p.db != nil {
			if err := p.persistInventoryRevocation(fingerprint, req.ReasonCode, nowStr); err != nil {
				metrics.CertRevokeErrors.Inc()
				if scope == RevocationScopeUpstream {
					logging.Warnf("REVOKED UPSTREAM BUT NOT RECORDED: fingerprint=%s connector=%s: %v", fingerprint, connID, err)
				}
				return CertificateRevokeResult{}, fmt.Errorf("persist revocation: %w", err)
			}
		}
	} else if p.revStore != nil && stored.x509 != nil {
		// Persist revocation to DB so OCSP and CRL reflect it immediately.
		if err := p.revStore.Revoke(stored.x509.SerialNumber, stored.item.CAID, req.ReasonCode, now); err != nil {
			metrics.CertRevokeErrors.Inc()
			return CertificateRevokeResult{}, fmt.Errorf("persist revocation: %w", err)
		}
		if p.ocspInvalidator != nil {
			// Without this, "immediately" above was a lie: OCSP kept
			// answering "good" for this serial until its cached response's
			// validity window (24h default) aged out on its own (W19-01).
			p.ocspInvalidator.InvalidateCache(stored.x509.SerialNumber)
		}
	}

	// RevokedAt is set AFTER the status change: the per-CA active count is
	// adjusted from the item's state before and after, and isActiveCertificate
	// reads RevokedAt, so setting it first would skip the decrement.
	p.setRenewalStatusLocked(stored, string(RenewalStatusRevoked))
	stored.item.RevokedAt = &nowStr
	stored.item.RevocationReason = &req.ReasonCode
	stored.item.UpdatedAt = nowStr
	stored.item.ETag++
	metrics.CertRevokeTotal.Inc()

	return CertificateRevokeResult{
		FingerprintSHA256: fingerprint,
		RenewalStatus:     string(RenewalStatusRevoked),
		RevokedAt:         nowStr,
		RevocationReason:  req.ReasonCode,
		RevocationScope:   scope,
	}, nil
}

// isExternalCA reports whether caID names an external CA (W36-02).
func (p *caCertificateProvider) isExternalCA(caID string) bool {
	if caID == "" || p.engine == nil {
		return false
	}
	c, err := p.engine.GetCA(caID)
	return err == nil && c.Type == ca.CATypeExternal
}

// SetUpstreamRevoker attaches the connector bridge used for upstream
// revocation (W36-03). Set once at startup.
func (p *caCertificateProvider) SetUpstreamRevoker(u UpstreamRevoker) {
	p.mu.Lock()
	p.upstreamRevoker = u
	p.mu.Unlock()
}

func (p *caCertificateProvider) persistInventoryRevocation(fingerprint string, reason int, at string) error {
	q := `UPDATE certificates SET revoked_at = ?, revocation_reason = ?, renewal_status = 'revoked', updated_at = ? WHERE fingerprint_sha256 = ?`
	if p.postgres {
		q = rebindPostgres(q)
	}
	res, err := p.db.Exec(q, at, reason, at, fingerprint)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errors.New("no certificates row for fingerprint")
	}
	return nil
}

// applyTemplateToIssuance copies a template's policy and issuance defaults
// onto req.
func applyTemplateToIssuance(req *ca.IssuanceRequest, tpl TemplateItem) error {
	validity, err := templateValidity(tpl)
	if err != nil {
		return fmt.Errorf("%w: %v", ca.ErrPolicyViolation, err)
	}
	policy := templateItemToPolicy(tpl)
	req.Policy = &policy
	req.Validity = validity
	if len(tpl.ExtendedKeyUsage) > 0 {
		req.ExtKeyUsage = parseEKUPolicy(tpl.ExtendedKeyUsage)
	}
	return nil
}

func (p *caCertificateProvider) RenewCertificate(ctx context.Context, fingerprint string, req CertificateRenewRequest) (CertificateIssueResult, error) {
	p.ensureCertLoaded(fingerprint)
	p.mu.RLock()
	predecessor, ok := p.certs[fingerprint]
	p.mu.RUnlock()
	if !ok {
		return CertificateIssueResult{}, errCertificateNotFound
	}
	if predecessor.item.SuccessorFP != nil {
		return CertificateIssueResult{}, errCertificateConflict
	}

	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil {
		return CertificateIssueResult{}, errCertificateInvalid
	}

	renewReq := ca.IssuanceRequest{
		TemplateID:  predecessor.item.TemplateID,
		Validity:    90 * 24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if err := parseCSRBlock(block, &renewReq); err != nil {
		return CertificateIssueResult{}, err
	}

	// SUP-A04-3: a renewal takes its names from the new CSR, so the
	// predecessor's template name policy binds it too. Only the name policy:
	// renewal deliberately does not enforce the template's algorithm,
	// validity or EKU policy (PQC migration waves renew a classical-template
	// certificate onto ML-DSA). A template that no longer exists leaves no
	// policy to apply; a lookup error fails closed.
	var templateRevision int
	if renewReq.TemplateID != "" && p.templates != nil {
		tpl, found, terr := p.templates.GetTemplate(ctx, renewReq.TemplateID)
		if terr != nil {
			return CertificateIssueResult{}, fmt.Errorf("template lookup: %w", terr)
		}
		if found {
			templateRevision = tpl.Revision
		}
		if found && tpl.NamePolicy != nil {
			renewReq.Policy = &ca.TemplatePolicy{ID: tpl.ID, Names: tpl.NamePolicy}
		}
		// The successor keeps the lifetime its template asks for, not a
		// hard-coded default. Only the lifetime is carried over: the
		// template's validity is not enforced as a policy cap (see above).
		if found {
			validity, verr := templateValidity(tpl)
			if verr != nil {
				return CertificateIssueResult{}, fmt.Errorf("%w: %v", ca.ErrPolicyViolation, verr)
			}
			renewReq.Validity = validity
		}
	}

	// W23-25: re-sign with a fresh serial when (CA, serial) collides.
	var (
		issued *ca.IssuedCertificate
		item   CertificateItem
		now    string
	)
	err := ca.RetryOnSerialCollision(5, func(int) error {
		var err error
		issued = nil
		issued, err = p.engine.IssueCertificate(predecessor.item.CAID, renewReq)
		if err != nil {
			return wrapEngineIssueError("ca renewal failed", err)
		}

		now = time.Now().UTC().Format(time.RFC3339)
		chainClassical := resolveChainClassical(p.engine, predecessor.item.CAID, issued.Certificate)
		item = CertificateItem{
			FingerprintSHA256:  issued.Fingerprint,
			SerialNumber:       issued.SerialNumber.String(),
			CommonName:         issued.Certificate.Subject.CommonName,
			SubjectDN:          issued.Certificate.Subject.String(),
			SubjectAltNames:    ca.SubjectAltNameStrings(issued.Certificate),
			URISANs:            uriStrings(issued.Certificate.URIs),
			IssuerCN:           issued.Certificate.Issuer.CommonName,
			IssuerDN:           issued.Certificate.Issuer.String(),
			CAID:               predecessor.item.CAID,
			TemplateID:         predecessor.item.TemplateID,
			TemplateRevision:   templateRevision,
			TeamID:             predecessor.item.TeamID,
			ValidFrom:          issued.Certificate.NotBefore.UTC().Format(time.RFC3339),
			ValidUntil:         issued.Certificate.NotAfter.UTC().Format(time.RFC3339),
			PublicKeyAlgorithm: ca.StoredPublicKeyAlgorithm(issued.Certificate),
			KeySizeBits:        publicKeyBits(issued.Certificate),
			SignatureAlgorithm: issued.Certificate.SignatureAlgorithm.String(),
			ExtendedKeyUsage:   ekuStrings(issued.Certificate.ExtKeyUsage),
			KeyUsage:           kuStrings(issued.Certificate.KeyUsage),
			ChainComplete:      boolRef(true),
			ChainTrusted:       boolRef(true),
			PQCVulnerable:      isPQCVulnerable(issued.Certificate),
			PQCReadiness:       computePQCReadiness(issued.Certificate, chainClassical),
			RiskScore:          adjustRiskForChain(computeRiskScore(issued.Certificate, time.Now()), true),
			RiskFlags:          adjustFlagsForChain(computeRiskFlags(issued.Certificate, chainClassical, time.Now()), true),
			Grade:              computeGrade(adjustRiskForChain(computeRiskScore(issued.Certificate, time.Now()), true)),
			// "renewal" is not a renewal METHOD — it named the event, not how
			// this successor gets renewed next — and it is not in
			// certificates.renewal_method's CHECK (acme|est|scep|api|manual),
			// so INSERT OR IGNORE silently discarded every renewed row.
			RenewalMethod:   "api",
			RenewalStatus:   string(RenewalStatusActive),
			Source:          "api",
			Origin:          "internal",
			ManagementState: "managed",
			PredecessorFP:   &fingerprint,
			ETag:            1,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		item.KeyAlgorithmDisplay = keyAlgorithmDisplay(issued.Certificate)

		// S-50 (found while landing it): renewed certificates were never
		// persisted AT ALL — memory-only, gone on restart, same family as the
		// issuance discard. Persist before mutating shared state so a failure
		// leaves nothing to unwind.
		if p.db != nil {
			return p.writeCertToDB(item, issued.CertPEM)
		}
		return nil
	})
	if err != nil {
		if issued != nil {
			logging.Warnf("RENEWAL NOT RECORDED: signed but failed to persist — fingerprint=%s predecessor=%s: %v",
				issued.Fingerprint, fingerprint, err)
			return CertificateIssueResult{}, fmt.Errorf(
				"renewal was signed but could not be recorded (fingerprint %s): %w", issued.Fingerprint, err)
		}
		return CertificateIssueResult{}, err
	}

	// The link is row state too: only the renewing replica knows the
	// predecessor is superseded, and a peer's renewal-reminder run would
	// otherwise keep paging for a certificate that has already been renewed.
	p.mu.RLock()
	linkStamp := nextRowStamp(predecessor.item.UpdatedAt)
	p.mu.RUnlock()
	if p.db != nil {
		if err := p.persistRenewalLink(fingerprint, issued.Fingerprint, linkStamp); err != nil {
			logging.Infof("RENEWAL LINK NOT RECORDED: successor %s is stored but predecessor %s is not marked renewed for peer replicas: %v",
				issued.Fingerprint, fingerprint, err)
		}
	}

	p.mu.Lock()
	p.addLocked(issued.Fingerprint, &storedCert{
		item:    item,
		certPEM: issued.CertPEM,
		x509:    issued.Certificate,
	})
	// Link predecessor → successor.
	predecessor.item.SuccessorFP = &issued.Fingerprint
	p.setRenewalStatusLocked(predecessor, string(RenewalStatusRenewed))
	predecessor.item.UpdatedAt = linkStamp
	predecessor.item.ETag++
	p.mu.Unlock()

	p.flagKeyReuse(issued.Fingerprint)

	return CertificateIssueResult{CertificateItem: item}, nil
}

// persistRenewalLink records predecessor -> successor in both rows, bumping
// the predecessor's updated_at so peers' incremental refresh picks it up.
func (p *caCertificateProvider) persistRenewalLink(predecessorFP, successorFP, now string) error {
	predQ := `UPDATE certificates SET renewal_status=?, successor_fingerprint=?, updated_at=? WHERE fingerprint_sha256=?`
	succQ := `UPDATE certificates SET predecessor_fingerprint=? WHERE fingerprint_sha256=?`
	if p.postgres {
		predQ = `UPDATE certificates SET renewal_status=$1, successor_fingerprint=$2, updated_at=$3 WHERE fingerprint_sha256=$4`
		succQ = `UPDATE certificates SET predecessor_fingerprint=$1 WHERE fingerprint_sha256=$2`
	}
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(predQ, string(RenewalStatusRenewed), successorFP, now, predecessorFP); err != nil {
		return err
	}
	if _, err := tx.Exec(succQ, predecessorFP, successorFP); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *caCertificateProvider) ListCertificates(_ context.Context, query CertificateListQuery) (CertificateListResult, error) {
	// S-50: an inventory that could not be loaded is not an empty inventory.
	if p.hydrateErr != nil {
		return CertificateListResult{}, fmt.Errorf(
			"certificate inventory unavailable: failed to load from database: %w", p.hydrateErr)
	}
	p.ensureIndex()
	p.mu.RLock()
	defer p.mu.RUnlock()

	// This is the HTTP page: the cap is an API contract, not a capacity
	// limit. Internal callers that need every row use ForEachCertificate.
	limit := query.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > maxCertificatePageSize {
		limit = maxCertificatePageSize
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	// S-62: pagination happens across SEPARATE calls, so the order must be
	// TOTAL; p.order is kept sorted by (created_at desc, fingerprint asc) on
	// every write, so a page is a window over it rather than a per-request
	// copy and sort of the whole inventory (M3).
	f := newCertFilter(query)
	var items []CertificateItem
	total := 0
	if f.matchesAll() {
		total = len(p.order)
		if offset > total {
			offset = total
		}
		end := offset + limit
		if end > total {
			end = total
		}
		items = make([]CertificateItem, 0, end-offset)
		for _, stored := range p.order[offset:end] {
			items = append(items, stored.item)
		}
	} else {
		items = make([]CertificateItem, 0, limit)
		for _, stored := range p.order {
			if !f.matches(&stored.item) {
				continue
			}
			if total >= offset && len(items) < limit {
				items = append(items, stored.item)
			}
			total++
		}
	}

	return CertificateListResult{
		Items: items,
		Total: total,
		Limit: limit,
	}, nil
}

// RecordIssuedCertificate implements acme.IssuedCertificateRecorder (W18-16).
// ACME finalize used to leave issued certificates out of the certificates
// table entirely -- invisible to inventory/dashboard, un-renewable hub-side,
// and only ever backfilled on demand by the revocation path. This builds the
// same CertificateItem shape IssueCertificate does for the API path and
// writes it through the same p.certs cache + writeCertToDB, so GetCertificate
// and ListCertificates see ACME issuances exactly like API ones. ctx is
// accepted to satisfy the interface; writeCertToDB/GetCertificate take none
// either, matching the rest of this provider.
// SetOCSPCacheInvalidator wires a ca.RevocationCacheInvalidator into the
// provider so RevokeCertificate can clear a live OCSP responder's cache for
// a serial it just revoked (W19-01). Optional: leaving it unset (nil, the
// default) is a valid, tested configuration -- RevokeCertificate still
// persists the revocation via revStore exactly as before.
func (p *caCertificateProvider) SetOCSPCacheInvalidator(inv ca.RevocationCacheInvalidator) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ocspInvalidator = inv
}

func (p *caCertificateProvider) RecordIssuedCertificate(ctx context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source string) error {
	return p.RecordIssuedCertificateWithTemplate(ctx, caID, cert, chainPEM, source, "")
}

// RecordIssuedCertificateWithTemplate implements
// ca.TemplateIssuedCertificateRecorder (W20-15): the row carries the template
// that governed issuance, as an API-issued row does.
func (p *caCertificateProvider) RecordIssuedCertificateWithTemplate(ctx context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source, templateID string) error {
	var templateRevision int
	if templateID != "" && p.templates != nil {
		// Best effort: the certificate is already signed, so a lookup failure
		// leaves the revision unrecorded rather than losing the row.
		if tpl, found, terr := p.templates.GetTemplate(ctx, templateID); terr != nil {
			logging.Warnf("template revision lookup for %s failed: %v", templateID, terr)
		} else if found {
			templateRevision = tpl.Revision
		}
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	now := time.Now().UTC().Format(time.RFC3339)
	chainClassical := resolveChainClassical(p.engine, caID, cert)
	item := CertificateItem{
		FingerprintSHA256:  fingerprint,
		SerialNumber:       cert.SerialNumber.String(),
		CommonName:         cert.Subject.CommonName,
		SubjectDN:          cert.Subject.String(),
		SubjectAltNames:    ca.SubjectAltNameStrings(cert),
		URISANs:            uriStrings(cert.URIs),
		IssuerCN:           cert.Issuer.CommonName,
		IssuerDN:           cert.Issuer.String(),
		CAID:               caID,
		TemplateID:         templateID,
		TemplateRevision:   templateRevision,
		ValidFrom:          cert.NotBefore.UTC().Format(time.RFC3339),
		ValidUntil:         cert.NotAfter.UTC().Format(time.RFC3339),
		PublicKeyAlgorithm: ca.StoredPublicKeyAlgorithm(cert),
		KeySizeBits:        publicKeyBits(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		ExtendedKeyUsage:   ekuStrings(cert.ExtKeyUsage),
		KeyUsage:           kuStrings(cert.KeyUsage),
		ChainComplete:      boolRef(true),
		ChainTrusted:       boolRef(true),
		PQCVulnerable:      isPQCVulnerable(cert),
		PQCReadiness:       computePQCReadiness(cert, chainClassical),
		RiskScore:          adjustRiskForChain(computeRiskScore(cert, time.Now()), true),
		RiskFlags:          adjustFlagsForChain(computeRiskFlags(cert, chainClassical, time.Now()), true),
		Grade:              computeGrade(adjustRiskForChain(computeRiskScore(cert, time.Now()), true)),
		RenewalMethod:      "manual",
		RenewalStatus:      string(RenewalStatusActive),
		Source:             source,
		Origin:             "internal",
		ManagementState:    "managed",
		// TeamID intentionally left empty: RFC 8555 carries no tenant/team
		// concept, so there is nothing to assign it from. This matches
		// IssueCertificate's own behavior when req.TeamID is unset -- an
		// unscoped item, not an ACME-specific gap.
		ETag:      1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	p.markExternalIssuance(&item)

	p.mu.Lock()
	p.addLocked(fingerprint, &storedCert{
		item:    item,
		certPEM: chainPEM,
		x509:    cert,
	})
	p.mu.Unlock()

	if p.db != nil {
		if err := p.writeCertToDB(item, chainPEM); err != nil {
			p.mu.Lock()
			p.removeLocked(fingerprint)
			p.mu.Unlock()
			return fmt.Errorf("record ACME-issued certificate %s: %w", fingerprint, err)
		}
	}

	p.flagKeyReuse(fingerprint)
	return nil
}

func (p *caCertificateProvider) GetCertificate(_ context.Context, fingerprint string) (CertificateDetail, bool, error) {
	p.ensureCertLoaded(fingerprint)
	p.mu.RLock()
	defer p.mu.RUnlock()

	stored, ok := p.certs[fingerprint]
	if !ok {
		return CertificateDetail{}, false, nil
	}
	return CertificateDetail{CertificateItem: stored.item}, true, nil
}

func (p *caCertificateProvider) GetCertificateChain(_ context.Context, fingerprint string) (CertificateChainResult, bool, error) {
	p.ensureCertLoaded(fingerprint)
	p.mu.RLock()
	defer p.mu.RUnlock()

	stored, ok := p.certs[fingerprint]
	if !ok {
		return CertificateChainResult{}, false, nil
	}

	chain := []CertificateChainItem{{
		FingerprintSHA256: stored.item.FingerprintSHA256,
		CommonName:        stored.item.CommonName,
		ValidFrom:         stored.item.ValidFrom,
		ValidUntil:        stored.item.ValidUntil,
		RenewalStatus:     stored.item.RenewalStatus,
		Position:          "leaf",
	}}

	return CertificateChainResult{
		CurrentFingerprint: fingerprint,
		Chain:              chain,
	}, true, nil
}

// DownloadCertificate serves the leaf. With includeChain and PEM output it
// appends the issuing intermediates (nearest first) -- the conventional
// "fullchain" -- and deliberately omits the self-signed root: relying parties
// hold the root in their trust store, and shipping it adds nothing a verifier
// may trust. A leaf issued directly by a root therefore downloads as a single
// certificate; the root itself comes from GET /api/v1/cas/{id}/chain?format=pem.
// DER is a single-certificate encoding and ignores includeChain.
func (p *caCertificateProvider) DownloadCertificate(_ context.Context, fingerprint string, format string, includeChain bool) (CertificateDownloadResult, error) {
	p.ensureCertLoaded(fingerprint)
	p.mu.RLock()
	defer p.mu.RUnlock()

	stored, ok := p.certs[fingerprint]
	if !ok {
		return CertificateDownloadResult{}, errCertificateNotFound
	}

	switch format {
	case "pem", "":
		body := stored.certPEM
		if includeChain {
			body = p.appendIntermediatesPEM(body, stored.item.CAID)
		}
		return CertificateDownloadResult{
			ContentType: "application/x-pem-file",
			Filename:    stored.item.CommonName + ".pem",
			Body:        body,
		}, nil
	case "der":
		return CertificateDownloadResult{
			ContentType: "application/x-x509-ca-cert",
			Filename:    stored.item.CommonName + ".der",
			Body:        stored.x509.Raw,
		}, nil
	default:
		return CertificateDownloadResult{}, fmt.Errorf("unsupported format: %s", format)
	}
}

// appendIntermediatesPEM appends every non-root CA certificate between the
// issuing CA and its root. A chain lookup failure degrades to the bare leaf
// rather than failing the download: the leaf is still the correct answer to
// "download this certificate", and the caller can fetch the chain separately.
func (p *caCertificateProvider) appendIntermediatesPEM(leafPEM []byte, caID string) []byte {
	if caID == "" || p.engine == nil {
		return leafPEM
	}
	chain, err := p.engine.GetCAChain(caID)
	if err != nil {
		logging.Warnf("certificate download: CA chain for %s unavailable, serving leaf only: %v", caID, err)
		return leafPEM
	}
	// Clone: stored.certPEM is shared state and append must not write into it.
	out := bytes.Clone(bytes.TrimRight(leafPEM, "\n"))
	for _, c := range chain {
		if c.ParentCAID == "" || len(c.CertPEM) == 0 {
			continue
		}
		out = append(out, '\n')
		out = append(out, bytes.TrimRight(c.CertPEM, "\n")...)
	}
	return append(out, '\n')
}

func (p *caCertificateProvider) ImportCertificate(_ context.Context, req CertificateImportRequest) (CertificateIssueResult, error) {
	block, _ := pem.Decode([]byte(req.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return CertificateIssueResult{}, errCertificateInvalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertificateIssueResult{}, fmt.Errorf("%w: %v", errCertificateInvalid, err)
	}

	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))

	p.mu.Lock()

	if _, exists := p.certs[fingerprint]; exists {
		p.mu.Unlock()
		return CertificateIssueResult{}, errCertificateConflict
	}

	now := time.Now().UTC().Format(time.RFC3339)
	// No local CAID is resolvable for an imported certificate -- this
	// reduces to the single-hop isChainClassical(cert) check, unchanged.
	chainClassical := resolveChainClassical(p.engine, "", cert)
	item := CertificateItem{
		FingerprintSHA256:  fingerprint,
		SerialNumber:       cert.SerialNumber.String(),
		CommonName:         cert.Subject.CommonName,
		SubjectDN:          cert.Subject.String(),
		SubjectAltNames:    ca.SubjectAltNameStrings(cert),
		URISANs:            uriStrings(cert.URIs),
		IssuerCN:           cert.Issuer.CommonName,
		IssuerDN:           cert.Issuer.String(),
		TeamID:             req.TeamID,
		ValidFrom:          cert.NotBefore.UTC().Format(time.RFC3339),
		ValidUntil:         cert.NotAfter.UTC().Format(time.RFC3339),
		PublicKeyAlgorithm: ca.StoredPublicKeyAlgorithm(cert),
		KeySizeBits:        publicKeyBits(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		ExtendedKeyUsage:   ekuStrings(cert.ExtKeyUsage),
		KeyUsage:           kuStrings(cert.KeyUsage),
		PQCVulnerable:      isPQCVulnerable(cert),
		PQCReadiness:       computePQCReadiness(cert, chainClassical),
		RiskScore:          adjustRiskForChain(computeRiskScore(cert, time.Now()), false),
		RiskFlags:          adjustFlagsForChain(computeRiskFlags(cert, chainClassical, time.Now()), false),
		Grade:              computeGrade(adjustRiskForChain(computeRiskScore(cert, time.Now()), false)),
		RenewalMethod:      "manual", // W11-01: "imported" violates the schema CHECK (acme/est/scep/api/manual) and INSERT OR IGNORE silently ate the row
		RenewalStatus:      string(RenewalStatusActive),
		Source:             "import",
		Origin:             "imported",
		ManagementState:    "unmanaged",
		ETag:               1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	p.addLocked(fingerprint, &storedCert{
		item:    item,
		certPEM: []byte(req.CertificatePEM),
		x509:    cert,
	})
	p.mu.Unlock()

	// W11-01: imports were memory-only — every imported certificate silently
	// vanished on restart (same durability family as S-51/S-66). With S-50
	// landed, a persist failure now fails the import outright: an import
	// that only exists in memory is a restart away from being a lie.
	if p.db != nil {
		if err := p.writeCertToDB(item, []byte(req.CertificatePEM)); err != nil {
			p.mu.Lock()
			p.removeLocked(fingerprint)
			p.mu.Unlock()
			logging.Warnf("IMPORT NOT RECORDED: failed to persist — fingerprint=%s: %v", fingerprint, err)
			return CertificateIssueResult{}, fmt.Errorf(
				"certificate import could not be recorded (fingerprint %s): %w", fingerprint, err)
		}
	}

	p.flagKeyReuse(fingerprint)

	// Re-read the item after scan in case KEY_REUSE flag was added.
	p.mu.RLock()
	updatedItem := p.certs[fingerprint].item
	p.mu.RUnlock()

	return CertificateIssueResult{CertificateItem: updatedItem}, nil
}

func (p *caCertificateProvider) UpdateOwnership(_ context.Context, fingerprint string, req CertificateOwnershipRequest) (CertificateItem, error) {
	p.ensureCertLoaded(fingerprint)
	p.mu.Lock()
	defer p.mu.Unlock()

	stored, ok := p.certs[fingerprint]
	if !ok {
		return CertificateItem{}, errCertificateNotFound
	}

	// Work on a copy and commit it only once the row is written, so a failed
	// persist leaves memory matching the database.
	src, err := resolveOwnershipSource(req)
	if err != nil {
		return CertificateItem{}, err
	}
	item := stored.item
	item.OwnershipSource = src
	item.OwnerEmail = strings.TrimSpace(req.OwnerEmail)
	item.OwnerTeam = strings.TrimSpace(req.OwnerTeam)
	item.ServiceName = strings.TrimSpace(req.ServiceName)
	if req.Labels != nil {
		item.Labels = req.Labels
	}
	item.UpdatedAt = nextRowStamp(stored.item.UpdatedAt)

	if p.db != nil {
		labelsJSON, _ := json.Marshal(item.Labels)
		var q string
		if p.postgres {
			q = `UPDATE certificates SET owner_email=$1, owner_team=$2, service_name=$3, labels=$4, ownership_source=$5, updated_at=$6 WHERE fingerprint_sha256=$7`
		} else {
			q = `UPDATE certificates SET owner_email=?, owner_team=?, service_name=?, labels=?, ownership_source=?, updated_at=? WHERE fingerprint_sha256=?`
		}
		// S-50: an ownership change that only lands in memory is reverted by
		// the next restart while the operator is told it succeeded.
		if _, err := p.db.Exec(q,
			nullableString(item.OwnerEmail),
			nullableString(item.OwnerTeam),
			nullableString(item.ServiceName),
			string(labelsJSON),
			item.OwnershipSource,
			item.UpdatedAt,
			fingerprint,
		); err != nil {
			logging.Infof("ownership change not persisted for %s: %v", fingerprint, err)
			return CertificateItem{}, fmt.Errorf("ownership change could not be recorded: %w", err)
		}
	}

	stored.item = item
	return stored.item, nil
}

// UpdateEstate transitions estate bookkeeping (W11-03 takeover): management
// state and the chosen renewal path. Persisted in memory and, when a DB is
// configured, on the row — mirroring UpdateOwnership's shape.
func (p *caCertificateProvider) UpdateEstate(_ context.Context, fingerprint string, req EstateUpdate) (CertificateItem, error) {
	p.ensureCertLoaded(fingerprint)
	p.mu.Lock()
	defer p.mu.Unlock()

	stored, ok := p.certs[fingerprint]
	if !ok {
		return CertificateItem{}, errCertificateNotFound
	}
	// Mutate a copy; commit only after validation and the DB write succeed.
	item := stored.item
	if req.Origin != "" {
		switch req.Origin {
		case "internal", "imported", "discovered", "synced":
		default:
			return CertificateItem{}, fmt.Errorf("%w: origin must be internal, imported, discovered, or synced", errCertificateInvalid)
		}
		item.Origin = req.Origin
	}
	if req.ManagementState != "" {
		switch req.ManagementState {
		case "managed", "external", "unmanaged":
		default:
			return CertificateItem{}, fmt.Errorf("%w: management_state must be managed, external, or unmanaged", errCertificateInvalid)
		}
		item.ManagementState = req.ManagementState
	}
	if req.RenewalConnectorID != "" {
		item.RenewalConnectorID = req.RenewalConnectorID
	} else if req.ClearRenewalConnector {
		item.RenewalConnectorID = ""
	}
	if req.RenewalStatus != "" {
		if !validRenewalStatus(req.RenewalStatus) {
			return CertificateItem{}, fmt.Errorf("%w: renewal_status must be one of %s", errCertificateInvalid, renewalStatusList())
		}
		item.RenewalStatus = req.RenewalStatus
	}
	if req.RenewalMethod != "" {
		item.RenewalMethod = req.RenewalMethod
	}
	item.UpdatedAt = nextRowStamp(stored.item.UpdatedAt)

	if p.db != nil {
		var q string
		if p.postgres {
			q = `UPDATE certificates SET origin=$1, management_state=$2, renewal_method=$3, renewal_connector_id=$4, renewal_status=$5, updated_at=$6 WHERE fingerprint_sha256=$7`
		} else {
			q = `UPDATE certificates SET origin=?, management_state=?, renewal_method=?, renewal_connector_id=?, renewal_status=?, updated_at=? WHERE fingerprint_sha256=?`
		}
		if _, err := p.db.Exec(q,
			item.Origin,
			item.ManagementState,
			nullableString(item.RenewalMethod),
			nullableString(item.RenewalConnectorID),
			nullableString(item.RenewalStatus),
			item.UpdatedAt,
			fingerprint,
		); err != nil {
			return CertificateItem{}, fmt.Errorf("estate update persist failed: %w", err)
		}
	}
	newStatus := item.RenewalStatus
	item.RenewalStatus = stored.item.RenewalStatus
	stored.item = item
	if newStatus != stored.item.RenewalStatus {
		p.setRenewalStatusLocked(stored, newStatus)
	}
	return stored.item, nil
}

// --- Helper functions ---

// publicKeyBits is the stored KeySizeBits. 0 means "not determinable" (e.g. a
// pure ML-DSA subject key Go's x509 cannot parse), never a real size; the
// weak-key flags are computed from the key itself and do not depend on this.
func publicKeyBits(cert *x509.Certificate) int {
	return ca.PublicKeyBits(cert.PublicKey)
}

// uriStrings renders URI SANs (e.g. SPIFFE IDs) as strings.
func uriStrings(uris []*url.URL) []string {
	if len(uris) == 0 {
		return nil
	}
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		if u != nil {
			out = append(out, u.String())
		}
	}
	return out
}

// uriSANsFromRawCert parses a base64-DER cert and returns its URI SANs, or nil.
func uriSANsFromRawCert(rawCertB64 string) []string {
	if rawCertB64 == "" {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(rawCertB64)
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return uriStrings(cert.URIs)
}

func ekuStrings(ekus []x509.ExtKeyUsage) []string {
	names := make([]string, 0, len(ekus))
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "emailProtection")
		default:
			names = append(names, fmt.Sprintf("eku-%d", eku))
		}
	}
	return names
}

func kuStrings(ku x509.KeyUsage) []string {
	names := make([]string, 0)
	if ku&x509.KeyUsageDigitalSignature != 0 {
		names = append(names, "digitalSignature")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		names = append(names, "keyEncipherment")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		names = append(names, "certSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		names = append(names, "crlSign")
	}
	return names
}

func isPQCVulnerable(cert *x509.Certificate) bool {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA, x509.ECDSA:
		// A hybrid cert's SUBJECT SPKI (cert.PublicKeyAlgorithm) is always
		// classical by design (hybrid_cert.go: "Standard classical (ECDSA)
		// primary key in SubjectPublicKeyInfo") -- the real ML-DSA subject
		// key lives in the non-standard subjectAltPublicKeyInfo extension
		// (2.5.29.72), invisible to a plain PublicKeyAlgorithm check. Found
		// empirically while testing W4-09 (G-70's fix): without this check,
		// every hybrid cert issued by W4-08 would be reported fully
		// classical/vulnerable, silently ignoring its real alt-key PQC
		// protection entirely -- the opposite failure mode from G-70
		// (undercounting real progress instead of overclaiming safety), but
		// the same root cause: computePQCReadiness/isPQCVulnerable not
		// actually inspecting what protection a cert carries.
		if hasAltKey, _, _, _ := ca.HybridCertInfo(cert); hasAltKey {
			return false
		}
		return true // vulnerable to quantum attacks
	default:
		return false
	}
}

// pqcReadinessLeafOnly (G-70/D-104): the certificate's own (subject) public
// key is PQC-safe, but the ISSUER's signature over it is classical, so the
// certificate's chain-level authenticity remains classically forgeable.
// Deliberately distinct from "quantum_safe" (leaf + chain both PQC) --
// migrate-wave (W4-03) re-issues members against their EXISTING, typically
// classical, CA (D-104: leaf-key protection is the accepted deliverable, not
// gated on CA-level PQC rotation first), and reporting those certs as fully
// quantum_safe would be the exact false-safety-record class G-67 was
// originally logged for.
const pqcReadinessLeafOnly = "quantum_safe_leaf_only"

// isChainClassical reports whether cert's IMMEDIATE ISSUER's signature
// (cert's own SignatureAlgorithm field, populated by the parser from the
// outer AlgorithmIdentifier -- not the subject's public key) is one of the
// classical algorithms (RSA/DSA/ECDSA/Ed25519). This inspects only the
// ONE signature on THIS certificate; resolveChainClassical extends it to
// the full chain (G-73).
//
// The test is a POSITIVE match against the classical set, not "anything
// the parser recognises". It used to be the latter, on the verified
// observation that stdlib x509 parsed an ML-DSA signature as
// x509.UnknownSignatureAlgorithm -- and that stopped being true when the
// toolchain moved to Go 1.27, whose x509 names ML-DSA-44/65/87 as
// SignatureAlgorithm values (18..20). Under the old test every ML-DSA-signed
// leaf demoted to quantum_safe_leaf_only, the mirror image of the G-70
// false-safety record. The ML-DSA constants are deliberately not referenced
// by name so the file still builds on go.mod's 1.25 floor; anything outside
// the classical set -- ML-DSA, SLH-DSA, or a genuinely unknown foreign
// algorithm on a discovery-scanned cert -- is treated as NOT classical,
// which keeps the original conservative direction: a cert is only ever
// demoted when the chain is DEFINITELY classical, never on an uncertain
// signal. A hybrid leaf's primary/outer signature is always classical
// (hybrid_cert.go: no altSignatureValue on CA-issued leaves per D-104), so
// those still correctly report classical here.
func isChainClassical(cert *x509.Certificate) bool {
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.DSAWithSHA1, x509.DSAWithSHA256,
		x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.PureEd25519:
		return true
	}
	return false
}

// resolveChainClassical closes G-73: extends isChainClassical's single-hop
// check to the FULL chain up to the root, so a classical link anywhere --
// not just the leaf's immediate issuer -- correctly prevents a quantum_safe
// classification. caID is the leaf's issuing CA (empty for imported
// certificates with no locally-resolvable issuer, e.g. req.CAID/
// predecessor.item.CAID at the call sites below); when empty, this is
// exactly isChainClassical(cert), unchanged.
//
// engine.GetCAChain walks ParentCAID from caID to the root (cycle-detected)
// -- this reuses that existing primitive rather than adding new CA-store
// traversal logic. On any error (CA not found, a circular chain, or a CA
// left inconsistent by an interrupted rotation -- see S-16/G-78) with a
// non-empty caID this returns true (classical): an unverifiable chain must
// degrade to the weaker quantum_safe_leaf_only label, never claim full PQC.
//
// Deliberately resolved ONCE per certificate at the caller (issuance,
// renewal, import) and passed in as a bool, rather than threading engine/
// caID into computePQCReadiness/computeRiskFlags themselves: those helpers
// only ever see a *x509.Certificate today and have no CA-store dependency
// of their own -- keeping it that way means they stay pure functions,
// trivial to unit test without an engine fixture. Fleet-wide reports
// (crypto-posture, pqc-countdown) don't recompute this at all; they
// aggregate the PQCReadiness string already stored on CertificateItem at
// issuance time, so there's no hot per-cert report loop this is guarding.
func resolveChainClassical(engine ca.Service, caID string, cert *x509.Certificate) bool {
	if isChainClassical(cert) {
		return true
	}
	if caID == "" || engine == nil {
		return false
	}
	chain, err := engine.GetCAChain(caID)
	if err != nil {
		// W31-02/D-104: a known issuer whose chain cannot be walked cannot be
		// proven PQC all the way up, so take the weaker label (leaf-only).
		return true
	}
	for _, c := range chain {
		if c.Certificate != nil && isChainClassical(c.Certificate) {
			return true
		}
	}
	return false
}

// computePQCReadiness classifies a certificate's post-quantum migration status.
// chainClassical is resolved once per certificate by the caller (see
// resolveChainClassical, G-73) -- true means a classical signature exists
// somewhere in the chain up to the root, not just the leaf's immediate
// issuer. Categories:
//   - quantum_safe: leaf key AND every signature up to the root are PQC (ML-DSA/SLH-DSA)
//   - quantum_safe_leaf_only: leaf key is PQC, but a classical signature
//     exists somewhere in the chain -- see pqcReadinessLeafOnly (G-70/D-104)
//   - migration_ready: short-lived (<= 100 days) so rotation before PQC deadline is feasible
//   - vulnerable: long-lived classical algorithm requiring active migration planning
//   - not_applicable: non-signing use (unlikely but defensive)
func computePQCReadiness(cert *x509.Certificate, chainClassical bool) string {
	// W31-01: a key whose algorithm Go cannot name and that is not ML-DSA is
	// unclassifiable, so it is not_applicable rather than falling through
	// isPQCVulnerable's default as quantum_safe. Ed25519 is classical, so it
	// takes the vulnerable/migration_ready path below; isPQCVulnerable and the
	// PQC_VULNERABLE risk flag deliberately stay unchanged (US-032).
	if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm && ca.StoredPublicKeyAlgorithm(cert) != "ML-DSA" {
		return "not_applicable"
	}
	if !isPQCVulnerable(cert) && cert.PublicKeyAlgorithm != x509.Ed25519 {
		if chainClassical {
			return pqcReadinessLeafOnly
		}
		return "quantum_safe"
	}
	// Short-lived certs (<=100 days) are easier to migrate — just rotate at renewal.
	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity <= 100*24*time.Hour {
		return "migration_ready"
	}
	return "vulnerable"
}

// nistSunsetDate is the NIST SP 800-131A Rev.3 date after which RSA-2048/ECC-224 are disallowed.
var nistSunsetDate = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)

// sanSprawlThreshold is the DNS SAN count above which a cert is flagged for blast-radius risk.
const sanSprawlThreshold = 25

// riskFlagWeights is the single source of risk-score points. computeRiskScore
// sums these over the flags computeRiskFlags raises, so the score and the flag
// list cannot drift apart. Flags absent here (e.g. PQC_MIGRATION_NEEDED, a
// refinement of PQC_VULNERABLE) carry no points.
var riskFlagWeights = map[string]int{
	"EXPIRED":                   40,
	"EXPIRING_7_DAYS":           20,
	"EXPIRING_30_DAYS":          20,
	"EXPIRING_47_DAYS":          5,
	"EXPIRING_90_DAYS":          5,
	"PQC_VULNERABLE":            10,
	"WEAK_SIGNATURE":            30,
	"WEAK_RSA_KEY":              35,
	"NIST_SUNSET_RSA2048":       20,
	"WEAK_EC_KEY":               20,
	"NIST_SUNSET_ECC224":        20,
	"OUTLIVES_NIST_SUNSET":      10,
	"VALIDITY_EXCEEDS_397_DAYS": 10,
	"VALIDITY_EXCEEDS_200_DAYS": 15,
	"SELF_SIGNED":               15,
	"WILDCARD_SAN":              5,
	"SAN_SPRAWL":                5,
	"NO_OCSP_URL":               10,
	"NO_CRL_DP":                 5,
}

// scReduction200DayStart is when CA/B Forum SC-081v3 phase 2 (200-day maximum
// validity) applies.
var scReduction200DayStart = time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC)

// computeRiskScore is the sum of riskFlagWeights over the flags raised at now,
// capped at 100. chainClassical only affects the non-vulnerable PQC readiness
// split, never which flags carry points, so it is irrelevant here.
func computeRiskScore(cert *x509.Certificate, now time.Time) int {
	score := 0
	for _, f := range computeRiskFlags(cert, false, now) {
		score += riskFlagWeights[f]
	}
	if score > 100 {
		score = 100
	}
	return score
}

// computeRiskFlags is the one rule ladder; now is injected so reports and
// tests evaluate every certificate against the same instant.
func computeRiskFlags(cert *x509.Certificate, chainClassical bool, now time.Time) []string {
	flags := make([]string, 0)

	if cert.NotAfter.Before(now) {
		flags = append(flags, "EXPIRED")
	} else if cert.NotAfter.Before(now.Add(7 * 24 * time.Hour)) {
		flags = append(flags, "EXPIRING_7_DAYS")
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		flags = append(flags, "EXPIRING_30_DAYS")
	} else if cert.NotAfter.Before(now.Add(47 * 24 * time.Hour)) {
		flags = append(flags, "EXPIRING_47_DAYS")
	} else if cert.NotAfter.Before(now.Add(90 * 24 * time.Hour)) {
		flags = append(flags, "EXPIRING_90_DAYS")
	}

	switch computePQCReadiness(cert, chainClassical) {
	case "vulnerable":
		flags = append(flags, "PQC_VULNERABLE", "PQC_MIGRATION_NEEDED")
	case "migration_ready":
		flags = append(flags, "PQC_VULNERABLE")
	}

	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		flags = append(flags, "WEAK_SIGNATURE")
	}

	if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		bits := pub.N.BitLen()
		if bits < 2048 {
			flags = append(flags, "WEAK_RSA_KEY")
		} else if bits == 2048 && now.After(nistSunsetDate) {
			flags = append(flags, "NIST_SUNSET_RSA2048")
		} else if bits == 2048 && cert.NotAfter.After(nistSunsetDate) {
			flags = append(flags, "OUTLIVES_NIST_SUNSET")
		}
	}

	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		bits := pub.Curve.Params().BitSize
		if bits < 256 {
			flags = append(flags, "WEAK_EC_KEY")
		}
		if bits <= 224 && now.After(nistSunsetDate) {
			flags = append(flags, "NIST_SUNSET_ECC224")
		} else if bits <= 224 && cert.NotAfter.After(nistSunsetDate) {
			flags = append(flags, "OUTLIVES_NIST_SUNSET")
		}
	}

	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity > 397*24*time.Hour {
		flags = append(flags, "VALIDITY_EXCEEDS_397_DAYS")
	}
	if now.After(scReduction200DayStart) && validity > 200*24*time.Hour {
		flags = append(flags, "VALIDITY_EXCEEDS_200_DAYS")
	}

	if cert.Issuer.String() == cert.Subject.String() && !cert.IsCA {
		flags = append(flags, "SELF_SIGNED")
	}

	for _, name := range cert.DNSNames {
		if strings.HasPrefix(name, "*.") {
			flags = append(flags, "WILDCARD_SAN")
			break
		}
	}

	if len(cert.DNSNames) > sanSprawlThreshold {
		flags = append(flags, "SAN_SPRAWL")
	}

	// OCSP not required for short-lived certs (<=7 days, CA/B Forum).
	if len(cert.OCSPServer) == 0 && !cert.IsCA && validity > 7*24*time.Hour {
		flags = append(flags, "NO_OCSP_URL")
	}
	if len(cert.CRLDistributionPoints) == 0 && !cert.IsCA {
		flags = append(flags, "NO_CRL_DP")
	}

	return flags
}

// adjustRiskForChain applies the untrusted-chain penalty to a pre-computed score.
// Kept separate because chain trust is a CertificateItem property, not derivable
// from *x509.Certificate alone (it requires verifying against the CA pool).
func adjustRiskForChain(score int, chainTrusted bool) int {
	if !chainTrusted {
		score += 25
	}
	if score > 100 {
		score = 100
	}
	return score
}

// adjustFlagsForChain appends UNTRUSTED_CHAIN when the chain is not trusted.
func adjustFlagsForChain(flags []string, chainTrusted bool) []string {
	if !chainTrusted {
		flags = append(flags, "UNTRUSTED_CHAIN")
	}
	return flags
}

// writeCertToDB inserts a leaf certificate into the certificates table.
// A failure here fails the operation (S-50): see the call sites for why.
// Errors are non-fatal (cert is already in the in-memory map); callers log/ignore them.
// estateOrigin / estateManagementState fall back from the item's explicit
// estate fields to a source-derived default (W11-01 spec decision 3), so
// pre-estate rows and callers never persist empty strings into the CHECKed
// columns.
func estateOrigin(item CertificateItem) string {
	if item.Origin != "" {
		return item.Origin
	}
	if item.Source == "import" {
		return "imported"
	}
	return "internal"
}

func estateManagementState(item CertificateItem) string {
	if item.ManagementState != "" {
		return item.ManagementState
	}
	if item.Source == "import" {
		return "unmanaged"
	}
	return "managed"
}

func (p *caCertificateProvider) writeCertToDB(item CertificateItem, certPEM []byte) error {
	var query string
	if p.postgres {
		query = `
INSERT INTO certificates
    (fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names,
     issuer_dn, issuer_cn, ca_id, template_id, team_id,
     valid_from, valid_until, public_key_algorithm, key_size_bits,
     signature_algorithm, extended_key_usage, key_usage,
     chain_complete, chain_trusted, pqc_vulnerable, pqc_readiness,
     risk_score, risk_flags, grade, renewal_method, renewal_status,
     source, raw_cert_b64, created_at, updated_at, origin, management_state, template_revision, renewal_connector_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)
ON CONFLICT (fingerprint_sha256) DO NOTHING`
	} else {
		query = `
INSERT OR IGNORE INTO certificates
    (fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names,
     issuer_dn, issuer_cn, ca_id, template_id, team_id,
     valid_from, valid_until, public_key_algorithm, key_size_bits,
     signature_algorithm, extended_key_usage, key_usage,
     chain_complete, chain_trusted, pqc_vulnerable, pqc_readiness,
     risk_score, risk_flags, grade, renewal_method, renewal_status,
     source, raw_cert_b64, created_at, updated_at, origin, management_state, template_revision, renewal_connector_id)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	}

	teamID := sql.NullString{String: item.TeamID, Valid: item.TeamID != ""}
	templateID := sql.NullString{String: item.TemplateID, Valid: item.TemplateID != ""}
	caID := sql.NullString{String: item.CAID, Valid: item.CAID != ""}
	renewalMethod := sql.NullString{String: item.RenewalMethod, Valid: item.RenewalMethod != ""}
	rawCertB64 := sql.NullString{String: string(certPEM), Valid: len(certPEM) > 0}
	templateRevisionArg := sql.NullInt64{Int64: int64(item.TemplateRevision), Valid: item.TemplateRevision > 0}

	// Postgres's schema types these columns BOOLEAN and TEXT[]; sqlite has
	// neither type, so its columns hold the same data as 0/1 integers and
	// JSON-encoded text. Sending the sqlite encoding to Postgres is exactly
	// the bug this function used to have (S-66): a bool column rejects an
	// int arg, and a TEXT[] column rejects a JSON string.
	var sanArg, ekuArg, kuArg, riskFlagsArg any
	var chainCompleteArg, chainTrustedArg, pqcVulnArg any
	if p.postgres {
		sanArg, ekuArg, kuArg = item.SubjectAltNames, item.ExtendedKeyUsage, item.KeyUsage
		// pgx encodes a nil []string as NULL, and risk_flags is the one TEXT[]
		// here that migration 000002 declares NOT NULL — the other three are
		// nullable. An empty slice keeps a flagless cert insertable.
		if item.RiskFlags == nil {
			riskFlagsArg = []string{}
		} else {
			riskFlagsArg = item.RiskFlags
		}
		chainCompleteArg, chainTrustedArg, pqcVulnArg = boolVal(item.ChainComplete), boolVal(item.ChainTrusted), item.PQCVulnerable
	} else {
		sanJSON, _ := json.Marshal(item.SubjectAltNames)
		ekuJSON, _ := json.Marshal(item.ExtendedKeyUsage)
		kuJSON, _ := json.Marshal(item.KeyUsage)
		riskFlagsJSON, _ := json.Marshal(item.RiskFlags)
		sanArg, ekuArg, kuArg, riskFlagsArg = string(sanJSON), string(ekuJSON), string(kuJSON), string(riskFlagsJSON)

		toInt := func(b bool) int {
			if b {
				return 1
			}
			return 0
		}
		chainCompleteArg = toInt(boolVal(item.ChainComplete))
		chainTrustedArg = toInt(boolVal(item.ChainTrusted))
		pqcVulnArg = toInt(item.PQCVulnerable)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := p.db.Exec(query,
		item.FingerprintSHA256, item.SerialNumber, item.SubjectDN, item.CommonName, sanArg,
		item.IssuerDN, item.IssuerCN, caID, templateID, teamID,
		item.ValidFrom, item.ValidUntil, item.PublicKeyAlgorithm, item.KeySizeBits,
		item.SignatureAlgorithm, ekuArg, kuArg,
		chainCompleteArg, chainTrustedArg, pqcVulnArg, item.PQCReadiness,
		item.RiskScore, riskFlagsArg, item.Grade, renewalMethod, item.RenewalStatus,
		item.Source, rawCertB64, now, now,
		estateOrigin(item), estateManagementState(item),
		templateRevisionArg, sql.NullString{String: item.RenewalConnectorID, Valid: item.RenewalConnectorID != ""},
	)
	if err != nil {
		return err
	}
	// INSERT OR IGNORE / ON CONFLICT DO NOTHING suppresses more than the
	// duplicate it was added for: a CHECK violation also writes nothing and
	// reports no error, which is how renewed certificates disappeared while
	// the API reported success (and how W11-01's "imported" disappeared
	// before that). Zero rows is only acceptable when the fingerprint is
	// genuinely already stored; anything else is a write that did not happen
	// and must say so.
	if n, rerr := res.RowsAffected(); rerr == nil && n == 0 {
		var exists int
		q := `SELECT 1 FROM certificates WHERE fingerprint_sha256 = ?`
		if p.postgres {
			q = `SELECT 1 FROM certificates WHERE fingerprint_sha256 = $1`
		}
		if scanErr := p.db.QueryRow(q, item.FingerprintSHA256).Scan(&exists); scanErr != nil {
			// sqlite's INSERT OR IGNORE also swallows the (CA, serial) unique
			// violation (W23-25); surface it so the issuance path re-signs
			// with a fresh serial instead of reporting an opaque rejection.
			if item.CAID != "" {
				sq := `SELECT 1 FROM certificates WHERE serial_number = ? AND ca_id = ?`
				if p.postgres {
					sq = `SELECT 1 FROM certificates WHERE serial_number = $1 AND ca_id = $2`
				}
				if p.db.QueryRow(sq, item.SerialNumber, item.CAID).Scan(&exists) == nil {
					return fmt.Errorf("%w: ca %s serial %s", ca.ErrSerialCollision, item.CAID, item.SerialNumber)
				}
			}
			return fmt.Errorf(
				"certificate %s (source %q) not persisted: rejected by a table constraint",
				item.FingerprintSHA256, item.Source)
		}
	}
	return nil
}

// TemplatePolicy is the engine-level issuance policy of a hub template, the
// one conversion every issuing path uses (API issuance, WSTEP; W20-09).
func TemplatePolicy(tpl TemplateItem) ca.TemplatePolicy { return templateItemToPolicy(tpl) }

// templateItemToPolicy converts a TemplateItem to a ca.TemplatePolicy for engine-level enforcement.
func templateItemToPolicy(tpl TemplateItem) ca.TemplatePolicy {
	policy := ca.TemplatePolicy{
		ID:                tpl.ID,
		AllowedAlgorithms: tpl.AllowedAlgorithms,
		AllowedEKUs:       parseEKUPolicy(tpl.ExtendedKeyUsage),
		Names:             tpl.NamePolicy,
		EnrollRoles:       tpl.EnrollRoles(),
	}
	minKeySize := tpl.MinKeySize
	if tpl.MsPKIMinimalKeySize > minKeySize {
		minKeySize = tpl.MsPKIMinimalKeySize
	}
	policy.MinKeySize = minKeySize
	// An unparseable period is rejected where it matters (issuance, template
	// create/update); here it leaves the cap unset rather than guessing one.
	if d, err := ParseValidityPeriod(tpl.ValidityPeriod); err == nil {
		policy.MaxValidity = d
	}
	if tpl.ShortLived {
		const shortLivedMax = 7 * 24 * time.Hour
		if policy.MaxValidity == 0 || policy.MaxValidity > shortLivedMax {
			policy.MaxValidity = shortLivedMax
		}
	}
	return policy
}

func parseEKUPolicy(names []string) []x509.ExtKeyUsage {
	ekus := make([]x509.ExtKeyUsage, 0, len(names))
	for _, n := range names {
		switch strings.ToLower(n) {
		case "serverauth":
			ekus = append(ekus, x509.ExtKeyUsageServerAuth)
		case "clientauth":
			ekus = append(ekus, x509.ExtKeyUsageClientAuth)
		case "codesigning":
			ekus = append(ekus, x509.ExtKeyUsageCodeSigning)
		case "emailprotection":
			ekus = append(ekus, x509.ExtKeyUsageEmailProtection)
		case "timestamping":
			ekus = append(ekus, x509.ExtKeyUsageTimeStamping)
		case "ocspsigning":
			ekus = append(ekus, x509.ExtKeyUsageOCSPSigning)
		}
	}
	if len(ekus) == 0 {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	return ekus
}

func computeGrade(riskScore int) string {
	switch {
	case riskScore <= 10:
		return "A"
	case riskScore <= 30:
		return "B"
	case riskScore <= 50:
		return "C"
	case riskScore <= 70:
		return "D"
	default:
		return "F"
	}
}

// IssuerChainPEM returns the PEM chain of CA caID up to its root. Installers
// that must trust the root on the target (the macOS keychain, W18-05) need
// it; the certificate download carries only the leaf.
func (p *caCertificateProvider) IssuerChainPEM(_ context.Context, caID string) ([]byte, error) {
	chain, err := p.engine.GetCAChain(caID)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, c := range chain {
		if c != nil && c.Certificate != nil {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw})...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("CA %s has no certificates in its chain", caID)
	}
	return out, nil
}

// parseCSRBlock fills the CSR field of req that matches the PEM block. The
// parser is chosen deterministically: by label for the custom ML-DSA and
// hybrid labels, and for the standard "CERTIFICATE REQUEST" label by the
// subjectPKInfo algorithm OID the DER declares. openssl >= 3.5 emits ML-DSA
// CSRs under the standard label; crypto/x509 cannot verify their signature,
// so they must reach ca.ParseCertificateRequestMLDSA, which verifies it.
// There is deliberately no try-one-parser-then-the-other fallback.
func parseCSRBlock(block *pem.Block, req *ca.IssuanceRequest) error {
	switch block.Type {
	case "CERTIFICATE REQUEST":
		if ca.IsMLDSACSR(block.Bytes) {
			return parseMLDSACSR(block.Bytes, req)
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return csrParseError(err)
		}
		req.CSR = csr
	case "ML-DSA CERTIFICATE REQUEST":
		return parseMLDSACSR(block.Bytes, req)
	case "HYBRID CERTIFICATE REQUEST":
		hybridCSR, err := ca.ParseCertificateRequestHybrid(block.Bytes)
		if err != nil {
			return csrParseError(err)
		}
		req.HybridCSR = hybridCSR
	default:
		return errCertificateInvalid
	}
	return nil
}

func parseMLDSACSR(der []byte, req *ca.IssuanceRequest) error {
	pqcCSR, err := ca.ParseCertificateRequestMLDSA(der)
	if err != nil {
		return csrParseError(err)
	}
	req.PQCCSR = pqcCSR
	return nil
}

// csrParseError marks a CSR failure as both an invalid certificate request
// (-> HTTP 400) and a ca.ErrInvalidCSR so handlers can say why.
func csrParseError(err error) error {
	return fmt.Errorf("%w: %w: %v", errCertificateInvalid, ca.ErrInvalidCSR, err)
}

// wrapEngineIssueError keeps a bad-CSR engine failure classified as a client
// error (errCertificateInvalid) instead of an opaque backend failure.
// errKeystoreBackendUnavailable marks an issuance that failed because the
// signing backend (HSM/KMS) could not sign, as opposed to a bad request.
// Issuance fails closed: nothing is recorded and the API answers 503.
var errKeystoreBackendUnavailable = errors.New("keystore backend unavailable")

// keystoreAlertHook receives ("keystore.backend_unavailable", caID, err) once
// per failed issuance. No notification fan-out exists in bootstrap yet; the
// default logs, and tests swap it.
var keystoreAlertHook = func(code, caID string, err error) {
	logging.Infof("ALERT %s ca=%s: %v", code, caID, err)
}

// classifyKeystoreFailure wraps err with errKeystoreBackendUnavailable unless
// it is a request/CA-state problem. The allow-list is load-bearing: a client
// error must never be reported as a backend outage (503).
func classifyKeystoreFailure(caID string, err error) error {
	for _, client := range []error{
		ca.ErrInvalidCSR, ca.ErrPolicyViolation, ca.ErrCANotFound, ca.ErrCANotActive,
		ca.ErrCANoSigningKey, ca.ErrSerialCollision, ca.ErrAlgorithmUnsupportedByBackend,
	} {
		if errors.Is(err, client) {
			return err
		}
	}
	keystoreAlertHook("keystore.backend_unavailable", caID, err)
	return fmt.Errorf("%w: %w", errKeystoreBackendUnavailable, err)
}

func wrapEngineIssueError(prefix string, err error) error {
	if errors.Is(err, ca.ErrInvalidCSR) {
		return fmt.Errorf("%s: %w: %w", prefix, errCertificateInvalid, err)
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

// nextRowStamp is the updated_at for a local write to a certificate row: the
// wall clock at millisecond resolution, forced strictly past prev. Two things
// make a plain second-resolution time.Now() wrong here. The row trigger
// trg_certificates_set_updated_at rewrites a same-value updated_at to a
// millisecond stamp, so a second write inside one second leaves the row newer
// than the memory copy; and refreshFromTable fetches full rows before it takes
// p.mu, so a row read before this write but merged after it carries an
// updated_at that must not beat the write. A strictly increasing stamp makes
// the DB value and the memory value identical (an echo is a tie) and any
// older row lose rowSupersedes.
func nextRowStamp(prev string) string {
	t := time.Now().UTC().Truncate(time.Millisecond)
	if p, ok := parseRowTime(prev); ok && !t.After(p) {
		t = p.UTC().Truncate(time.Millisecond).Add(time.Millisecond)
	}
	return t.Format("2006-01-02T15:04:05.000Z")
}

// markExternalIssuance records a certificate signed by an external CA
// (W36-02, D-304) as synced from upstream, with the CA's connector as its
// renewal and revocation path.
func (p *caCertificateProvider) markExternalIssuance(item *CertificateItem) {
	if item.CAID == "" || p.engine == nil {
		return
	}
	c, err := p.engine.GetCA(item.CAID)
	if err != nil || c.Type != ca.CATypeExternal {
		return
	}
	item.Origin = "synced"
	item.RenewalConnectorID = c.ConnectorID
}
