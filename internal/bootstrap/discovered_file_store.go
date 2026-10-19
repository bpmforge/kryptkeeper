// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/discovery/scanner"
)

// W34-08: install posture storage. discovered_files holds one row per
// certificate, key or keystore path a host scan statted; certificate_files
// links a certificate to every file it lives in. Findings are a JSON array in
// TEXT, matching the risk_flags convention. Key files are rows without bytes.

// DiscoveryInstallPosture is the posture a network endpoint inherits from the
// discovered file that holds its served leaf, so the Discovery row shows it
// without opening the target.
type DiscoveryInstallPosture struct {
	// FileID is discovered_files.id, the target_id of a target_file exception.
	FileID string `json:"file_id,omitempty"`
	// Posture is standard, privileged, root_service or unknown; when several
	// files hold the leaf, the most severe.
	Posture     string   `json:"posture"`
	Path        string   `json:"path"`
	Host        string   `json:"host"`
	Owner       string   `json:"owner,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	ServiceTech string   `json:"service_tech,omitempty"`
	Findings    []string `json:"findings,omitempty"`
	// AcceptedFindings are the finding codes with an active accepted-risk
	// exception on this file (W34): still listed in Findings, no longer
	// counted as open by the UI.
	AcceptedFindings []string `json:"accepted_findings,omitempty"`
}

func nullID(v int) any {
	if v < 0 {
		return nil
	}
	return v
}

func dialectQuery(postgres bool, q string) string {
	if postgres {
		return rebindPostgres(q)
	}
	return q
}

// persistHostFiles replaces a host's discovered files with what the scan saw
// and keeps managed_targets.renewal_privilege_required in step: set while any
// service-attributed file needs privilege to replace, cleared when a scan
// sees none. A scan that statted nothing leaves the flag alone, so an
// unprivileged run cannot mask a problem a privileged one found.
func persistHostFiles(ctx context.Context, db *sql.DB, postgres bool, tenant, host string, obs *scanner.HostObservations) error {
	if obs == nil || !obs.FilesScanned {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var observed any = time.Now().UTC().Format(time.RFC3339)
	if postgres {
		observed = time.Now().UTC()
	}
	upsert := dialectQuery(postgres, `
INSERT INTO discovered_files (id, tenant, target_id, host, path, kind, owner_uid, owner_gid, owner_name, group_name, mode,
    service_tech, service_uid, service_name, posture, findings, observed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (tenant, host, path) DO UPDATE SET
    target_id = excluded.target_id, kind = excluded.kind, owner_uid = excluded.owner_uid, owner_gid = excluded.owner_gid,
    owner_name = excluded.owner_name, group_name = excluded.group_name, mode = excluded.mode,
    service_tech = excluded.service_tech, service_uid = excluded.service_uid, service_name = excluded.service_name,
    posture = excluded.posture, findings = excluded.findings, observed_at = excluded.observed_at
RETURNING id`)
	delLinks := dialectQuery(postgres, `DELETE FROM certificate_files WHERE file_id = ?`)
	insLink := dialectQuery(postgres, `INSERT INTO certificate_files (certificate_fingerprint, file_id) VALUES (?, ?) ON CONFLICT DO NOTHING`)

	seen := map[string]bool{}
	privileged, statted := false, false
	for _, f := range obs.Files {
		findings := f.Findings
		if findings == nil {
			findings = []string{}
		}
		fj, _ := json.Marshal(findings) // []string always marshals
		var id string
		if err := tx.QueryRowContext(ctx, upsert, newDiscoveryEndpointID(), tenant, nullString(obs.TargetID), host, f.Path, f.Kind,
			nullID(f.OwnerUID), nullID(f.OwnerGID), nullString(f.Owner), nullString(f.Group), nullString(f.Mode),
			nullString(f.ServiceTech), nullID(f.ServiceUID), nullString(f.ServiceName), f.Posture, string(fj), observed).Scan(&id); err != nil {
			return fmt.Errorf("upsert discovered file %s:%s: %w", host, f.Path, err)
		}
		seen[f.Path] = true
		if _, err := tx.ExecContext(ctx, delLinks, id); err != nil {
			return err
		}
		for _, fp := range f.CertFingerprints {
			if _, err := tx.ExecContext(ctx, insLink, fp, id); err != nil {
				return fmt.Errorf("link certificate %s to %s: %w", fp, f.Path, err)
			}
		}
		statted = statted || f.Statted
		privileged = privileged || f.Posture == scanner.PosturePrivileged
	}

	rows, err := tx.QueryContext(ctx, dialectQuery(postgres, `SELECT id, path FROM discovered_files WHERE tenant = ? AND host = ?`), tenant, host)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var id, p string
		if err := rows.Scan(&id, &p); err != nil {
			rows.Close()
			return err
		}
		if !seen[p] {
			gone = append(gone, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, id := range gone {
		// Explicit: SQLite enforces ON DELETE CASCADE only with foreign_keys on.
		if _, err := tx.ExecContext(ctx, delLinks, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, dialectQuery(postgres, `DELETE FROM discovered_files WHERE id = ?`), id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if obs.TargetID != "" && statted {
		_, err := db.ExecContext(ctx, dialectQuery(postgres, `UPDATE managed_targets SET renewal_privilege_required = ? WHERE id = ?`),
			boolArg(privileged, postgres), obs.TargetID)
		if err != nil {
			// A discovery-only database has no managed_targets table.
			logging.Infof("host files %s: renewal_privilege_required not updated: %v", host, err)
		}
	}
	return nil
}

var postureRank = map[string]int{scanner.PostureRootService: 3, scanner.PosturePrivileged: 2, scanner.PostureUnknown: 1, scanner.PostureStandard: 0}

// attachInstallPosture fills InstallPosture on endpoints whose active served
// leaf lives in a discovered file. It is best-effort: posture is context for
// the row, never a reason to fail the listing.
func attachInstallPosture(ctx context.Context, db *sql.DB, postgres bool, endpoints []DiscoveryEndpoint) {
	byID := map[string]int{}
	var ids []any
	var marks []string
	leaf := map[string]map[string]bool{}
	for i, ep := range endpoints {
		for _, mc := range ep.MappedCerts {
			if mc.ChainCA {
				continue
			}
			if leaf[ep.ID] == nil {
				leaf[ep.ID] = map[string]bool{}
			}
			leaf[ep.ID][mc.Fingerprint] = true
		}
		if leaf[ep.ID] != nil {
			byID[ep.ID] = i
			ids = append(ids, ep.ID)
			marks = append(marks, "?")
		}
	}
	if len(ids) == 0 {
		return
	}
	active := "1"
	if postgres {
		active = "true"
	}
	q := `SELECT ce.endpoint_id, ce.certificate_fingerprint, f.id, f.path, f.host, f.posture, COALESCE(f.owner_name, ''), COALESCE(f.mode, ''),
       COALESCE(f.service_tech, ''), f.findings
FROM certificate_endpoints ce
JOIN certificate_files cf ON cf.certificate_fingerprint = ce.certificate_fingerprint
JOIN discovered_files f ON f.id = cf.file_id
WHERE ce.currently_active = ` + active + ` AND ce.endpoint_id IN (` + strings.Join(marks, ", ") + `)`
	if tenant, filter := discoveryFilterTenant(ctx); filter {
		q += ` AND f.tenant = ?`
		ids = append(ids, tenant)
	}
	rows, err := db.QueryContext(ctx, dialectQuery(postgres, q), ids...)
	if err != nil {
		logging.Infof("install posture join skipped: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var endpointID, fp, findingsJSON string
		var p DiscoveryInstallPosture
		if err := rows.Scan(&endpointID, &fp, &p.FileID, &p.Path, &p.Host, &p.Posture, &p.Owner, &p.Mode, &p.ServiceTech, &findingsJSON); err != nil {
			logging.Infof("install posture join skipped: %v", err)
			return
		}
		if !leaf[endpointID][fp] {
			continue
		}
		p.Findings = parseDiscoveryIssuesJSON(findingsJSON)
		i := byID[endpointID]
		cur := endpoints[i].InstallPosture
		if cur == nil || postureRank[p.Posture] > postureRank[cur.Posture] ||
			(postureRank[p.Posture] == postureRank[cur.Posture] && p.Path < cur.Path) {
			endpoints[i].InstallPosture = &p
		}
	}
	rows.Close()
	markAcceptedFileFindings(ctx, db, postgres, endpoints)
}

// markAcceptedFileFindings sets AcceptedFindings from the active target_file
// exceptions on each endpoint's posture file. Best-effort like the join: a
// hub whose database has no exceptions table just shows nothing accepted.
func markAcceptedFileFindings(ctx context.Context, db *sql.DB, postgres bool, endpoints []DiscoveryEndpoint) {
	q := dialectQuery(postgres, `SELECT finding_code, expires_at FROM finding_exceptions WHERE target_type = 'target_file' AND target_id = ?`)
	now := time.Now()
	cache := map[string][]string{}
	for i := range endpoints {
		p := endpoints[i].InstallPosture
		if p == nil || p.FileID == "" {
			continue
		}
		codes, ok := cache[p.FileID]
		if !ok {
			rows, err := db.QueryContext(ctx, q, p.FileID)
			if err != nil {
				return
			}
			for rows.Next() {
				var code, expires string
				if rows.Scan(&code, &expires) == nil && (FindingException{ExpiresAt: expires}).IsActive(now) {
					codes = append(codes, code)
				}
			}
			rows.Close()
			cache[p.FileID] = codes
		}
		p.AcceptedFindings = codes
	}
}

// recordTargetScanState stores what the scan ran with and could not read on
// its managed target (W34-10). A discovery-only database has no such column.
func recordTargetScanState(ctx context.Context, db *sql.DB, postgres bool, obs *scanner.HostObservations) {
	if obs == nil || obs.TargetID == "" || obs.PrivilegeMode == "" {
		return
	}
	_, err := db.ExecContext(ctx, dialectQuery(postgres,
		`UPDATE managed_targets SET last_privilege_mode = ?, unreadable_count = ?, last_scanned_at = ? WHERE id = ?`),
		obs.PrivilegeMode, obs.UnreadableCount, time.Now().UTC().Format(time.RFC3339), obs.TargetID)
	if err != nil {
		logging.Infof("host scan state %s: not recorded: %v", obs.TargetID, err)
	}
}
