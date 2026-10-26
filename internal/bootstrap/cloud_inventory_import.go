// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/cloudinventory"
	"kryptkeeper/internal/discovery/scanner"
	"kryptkeeper/internal/logging"
)

// W38-05 (D-323): certificates found in AWS ACM, Azure Key Vault and GCP
// Certificate Manager become rows of the certificates table, so they are
// listed, graded, reported and (through the W11-06 takeover) renewed like any
// other row. Estate model (D-106): origin=discovered, management_state=
// unmanaged, source=discovery_cloud, exactly like every other discovery
// source; a managed row with the same fingerprint is never touched.
//
// Fingerprint source, decided before any import code (W24-46 acceptance):
//   - the SHA-256 of the real DER whenever the connector returned the
//     certificate body (ACM GetCertificate, Key Vault "cer", Certificate
//     Manager pemCertificate). The same certificate found in two regions, or
//     already issued or discovered elsewhere, is then one row with two links.
//   - otherwise a synthetic key, sha256 over a versioned label, provider,
//     scope and resource id, and only when the metadata is enough to describe
//     the row honestly (a known classical key algorithm and an expiry).
//     fingerprint_kind='synthetic' on the link marks it. When the body later
//     becomes available the real row supersedes the synthetic one.
// A certificate with neither is counted as skipped, never stored half-known.

// cloudStampFormat is fixed-width so last_seen_at comparisons in SQL are
// chronological (RFC3339Nano trims trailing zeros and would not be).
const cloudStampFormat = "2006-01-02T15:04:05.000000000Z"

const cloudSyntheticFingerprintLabel = "kryptkeeper:cloud-certificate:v1"

// cloudImportSummary is the import's share of a scan's results_summary.
type cloudImportSummary struct {
	Imported int `json:"imported"` // new certificate rows
	Known    int `json:"known"`    // fingerprint already in the inventory: deduplicated, linked
	Skipped  int `json:"skipped"`  // not enough information to store honestly
	Removed  int `json:"removed_at_source"`
	// MetadataOnly counts rows keyed by the synthetic fingerprint.
	MetadataOnly int      `json:"metadata_only"`
	Failed       []string `json:"failed,omitempty"`
}

// cloudScopeKeyLegacy is the scope key of a scan with no configured scopes
// (the single env-configured connector); its certificates carry no Scope.
func cloudScopeKeyLegacy(provider string) string { return "legacy:" + provider }

// cloudCertFingerprint returns the row key for c and whether the key is the
// real DER fingerprint. ok is false when c cannot be stored honestly.
func cloudCertFingerprint(c cloudinventory.CloudCertificate, scopeKey string) (fp string, cert *x509.Certificate, ok bool) {
	if block, _ := pem.Decode([]byte(c.CertificatePEM)); block != nil && block.Type == "CERTIFICATE" {
		if parsed, err := x509.ParseCertificate(block.Bytes); err == nil {
			sum := sha256.Sum256(parsed.Raw)
			return hex.EncodeToString(sum[:]), parsed, true
		}
	}
	if _, _, usable := cloudMetadataKey(c); !usable {
		return "", nil, false
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{cloudSyntheticFingerprintLabel, c.Provider, scopeKey, c.ResourceID}, "\x00")))
	return hex.EncodeToString(sum[:]), nil, true
}

// cloudMetadataKey maps a provider's key-algorithm label onto the stored
// vocabulary. ACM reports RSA_2048 / EC_prime256v1 style labels
// (https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateSummary.html).
// Key Vault's list gives none, and Certificate Manager's connector value is a
// default rather than a reading, so those are unusable without the body: a
// guessed key type would feed the PQC and risk reports a fact nobody observed.
// An expiry is also required, since an undated row cannot be graded.
func cloudMetadataKey(c cloudinventory.CloudCertificate) (alg string, bits int, ok bool) {
	if c.Provider != cloudinventory.ProviderAWSACM || c.NotAfter.IsZero() {
		return "", 0, false
	}
	up := strings.ToUpper(c.KeyAlgorithm)
	switch {
	case strings.HasPrefix(up, "RSA"):
		alg = "RSA"
		if i := strings.LastIndexAny(up, "_-"); i >= 0 {
			bits, _ = strconv.Atoi(up[i+1:])
		}
	case strings.HasPrefix(up, "EC"):
		alg = "ECDSA"
		switch {
		case strings.Contains(up, "256"):
			bits = 256
		case strings.Contains(up, "384"):
			bits = 384
		case strings.Contains(up, "521"):
			bits = 521
		}
	default:
		return "", 0, false
	}
	return alg, bits, true
}

// cloudResourceAccount names the account, subscription-side vault or project
// a resource lives in, from the identifier the provider returned.
func cloudResourceAccount(c cloudinventory.CloudCertificate) string {
	switch c.Provider {
	case cloudinventory.ProviderAWSACM:
		// arn:aws:acm:<region>:<account>:certificate/<id>
		if parts := strings.Split(c.ResourceID, ":"); len(parts) >= 6 {
			return parts[4]
		}
	case cloudinventory.ProviderGCPCertManager:
		if parts := strings.Split(c.ResourceID, "/"); len(parts) >= 2 && parts[0] == "projects" {
			return parts[1]
		}
	case cloudinventory.ProviderAzureKeyVault:
		rest := strings.TrimPrefix(c.ResourceID, "https://")
		if i := strings.Index(rest, "/"); i > 0 {
			return rest[:i]
		}
	}
	return ""
}

func cloudRowArgs(c cloudinventory.CloudCertificate, fp string, cert *x509.Certificate, now string, postgres bool) (args []any, kind string) {
	if cert != nil {
		dc := scanner.CertToDiscovered(cert, "", true)
		dc.Fingerprint = fp
		row, ok := discoveredCertRow(dc, now, postgres)
		if !ok {
			return nil, ""
		}
		return row, "der"
	}
	alg, bits, _ := cloudMetadataKey(c)
	cn := c.CommonName
	var keyBits any
	if bits > 0 {
		keyBits = bits
	}
	dns := c.DNSNames
	if dns == nil {
		dns = []string{}
	}
	var sansArg, flagsArg any = dns, []string{}
	if !postgres {
		sans, _ := json.Marshal(dns)
		sansArg, flagsArg = string(sans), "[]"
	}
	issuer := c.Issuer
	if issuer == "" {
		issuer = "unknown"
	}
	from := ""
	if !c.NotBefore.IsZero() {
		from = c.NotBefore.UTC().Format(time.RFC3339)
	}
	return []any{
		fp,
		fp[:32], // serial: unique per synthetic row; the real serial is unknown
		"CN=" + cn,
		cn,
		sansArg,
		issuer,
		from,
		c.NotAfter.UTC().Format(time.RFC3339),
		alg,
		"unknown", // signature algorithm is not in any provider's list response
		0,
		flagsArg,
		"", // no body
		now,
		nil,
		keyBits,
		boolArg(false, postgres),
		boolArg(false, postgres),
		nil,
		boolArg(false, postgres),
		nil,
	}, "synthetic"
}

const cloudCertInsertSQLite = `
INSERT INTO certificates ` + discoveredCertUpsertColumns + `
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'discovery_cloud', 'discovered', 'unmanaged')
ON CONFLICT (fingerprint_sha256) DO UPDATE SET` + discoveredCertConflictUpdateSQLite

const cloudCertInsertPostgres = `
INSERT INTO certificates ` + discoveredCertUpsertColumns + `
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, 'discovery_cloud', 'discovered', 'unmanaged')
ON CONFLICT (fingerprint_sha256) DO UPDATE SET` + discoveredCertConflictUpdatePostgres

// importCloudCertificates writes certs for one scan and retires the links of
// every scope in sweepScopes that this scan did not see again. A scope that
// failed is left out of sweepScopes by the caller: not hearing from a scope is
// not evidence its certificates are gone. tenant is the owning scan job's
// stored tenant.
func importCloudCertificates(ctx context.Context, db *sql.DB, postgres bool, tenant string, certs []cloudinventory.CloudCertificate, sweepScopes []string, provider string, now time.Time) cloudImportSummary {
	var out cloudImportSummary
	stamp := now.UTC().Format(cloudStampFormat)
	q := func(s string) string {
		if postgres {
			return rebindPostgres(s)
		}
		return s
	}
	fail := func(c cloudinventory.CloudCertificate, err error) {
		if len(out.Failed) < 20 {
			out.Failed = append(out.Failed, fmt.Sprintf("%s: %v", c.ResourceID, err))
		}
	}

	for _, c := range certs {
		scopeKey := c.Scope
		if scopeKey == "" {
			scopeKey = cloudScopeKeyLegacy(c.Provider)
		}
		fp, cert, ok := cloudCertFingerprint(c, scopeKey)
		if !ok {
			out.Skipped++
			continue
		}
		args, kind := cloudRowArgs(c, fp, cert, now.UTC().Format(time.RFC3339), postgres)
		if args == nil {
			out.Skipped++
			continue
		}

		var exists int
		known := false
		if err := db.QueryRowContext(ctx, q(`SELECT 1 FROM certificates WHERE fingerprint_sha256 = ?`), fp).Scan(&exists); err == nil {
			known = true
		} else if err != sql.ErrNoRows {
			fail(c, err)
			continue
		}
		insert := cloudCertInsertSQLite
		if postgres {
			insert = cloudCertInsertPostgres
		}
		if _, err := db.ExecContext(ctx, insert, args...); err != nil {
			fail(c, fmt.Errorf("upsert certificate: %w", err))
			continue
		}
		if kind == "synthetic" {
			out.MetadataOnly++
			// Classical key by construction (cloudMetadataKey admits only RSA
			// and EC), so readiness is known without a parsed certificate.
			if _, err := db.ExecContext(ctx, q(`UPDATE certificates SET pqc_vulnerable = ?, pqc_readiness = 'vulnerable'
				WHERE fingerprint_sha256 = ? AND source = 'discovery_cloud' AND COALESCE(pqc_readiness, '') = ''`),
				boolArg(true, postgres), fp); err != nil {
				fail(c, fmt.Errorf("classify synthetic row: %w", err))
			}
		}
		if known {
			out.Known++
		} else {
			out.Imported++
		}
		if strings.EqualFold(c.Status, "revoked") {
			if _, err := db.ExecContext(ctx, q(`UPDATE certificates SET renewal_status = 'revoked'
				WHERE fingerprint_sha256 = ? AND source = 'discovery_cloud' AND management_state <> 'managed'`), fp); err != nil {
				fail(c, fmt.Errorf("mark revoked: %w", err))
			}
		}
		if err := linkCloudResource(ctx, db, postgres, tenant, scopeKey, c, fp, kind, stamp); err != nil {
			fail(c, err)
		}
	}

	for _, sk := range sweepScopes {
		res, err := db.ExecContext(ctx, q(`UPDATE certificate_cloud_resources SET currently_active = ?, removed_at = ?
			WHERE provider = ? AND scope_key = ? AND tenant = ? AND last_seen_at < ? AND currently_active = ?`),
			boolArg(false, postgres), stamp, provider, sk, tenant, stamp, boolArg(true, postgres))
		if err != nil {
			logging.Warnf("cloud inventory: retire links for %s: %v", sk, err)
			continue
		}
		if n, err := res.RowsAffected(); err == nil {
			out.Removed += int(n)
		}
	}
	return out
}

// linkCloudResource records where a certificate row was found. A resource
// whose key moved from synthetic to the real DER supersedes its old row with
// the existing predecessor/successor chain, so the placeholder drops out of
// the active inventory instead of lingering beside the real one.
func linkCloudResource(ctx context.Context, db *sql.DB, postgres bool, tenant, scopeKey string, c cloudinventory.CloudCertificate, fp, kind, stamp string) error {
	q := func(s string) string {
		if postgres {
			return rebindPostgres(s)
		}
		return s
	}
	var prevFP, prevKind string
	err := db.QueryRowContext(ctx, q(`SELECT fingerprint_sha256, fingerprint_kind FROM certificate_cloud_resources
		WHERE provider = ? AND scope_key = ? AND resource_id = ? AND tenant = ?`), c.Provider, scopeKey, c.ResourceID, tenant).Scan(&prevFP, &prevKind)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read link: %w", err)
	}
	if _, err := db.ExecContext(ctx, q(`
INSERT INTO certificate_cloud_resources
    (provider, scope_key, resource_id, tenant, fingerprint_sha256, fingerprint_kind, account, region, status, in_use,
     first_seen_at, last_seen_at, currently_active, removed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
ON CONFLICT (provider, scope_key, resource_id, tenant) DO UPDATE SET
    fingerprint_sha256 = excluded.fingerprint_sha256, fingerprint_kind = excluded.fingerprint_kind,
    account = excluded.account, region = excluded.region, status = excluded.status, in_use = excluded.in_use,
    last_seen_at = excluded.last_seen_at, currently_active = excluded.currently_active, removed_at = NULL`),
		c.Provider, scopeKey, c.ResourceID, tenant, fp, kind, cloudResourceAccount(c), c.Region, c.Status,
		boolArg(c.InUse, postgres), stamp, stamp, boolArg(true, postgres)); err != nil {
		return fmt.Errorf("write link: %w", err)
	}
	if prevKind == "synthetic" && prevFP != "" && prevFP != fp && kind == "der" {
		if _, err := db.ExecContext(ctx, q(`UPDATE certificates SET successor_fingerprint = ?, renewal_status = 'renewed', updated_at = ?
			WHERE fingerprint_sha256 = ? AND source = 'discovery_cloud' AND management_state <> 'managed'`), fp, stamp, prevFP); err != nil {
			return fmt.Errorf("supersede synthetic row: %w", err)
		}
		if _, err := db.ExecContext(ctx, q(`UPDATE certificates SET predecessor_fingerprint = ? WHERE fingerprint_sha256 = ? AND predecessor_fingerprint IS NULL`), prevFP, fp); err != nil {
			return fmt.Errorf("link predecessor: %w", err)
		}
	}
	return nil
}
