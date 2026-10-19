// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W22-25: one-shot CMDB ownership import. Rules (host / IP / CIDR to team and
// email) are applied once, on POST, to the certificates the caller can see and
// are not stored: a certificate issued later is not auto-assigned.

const (
	maxCMDBBodyBytes = 1 << 20
	maxCMDBRules     = 1000

	cmdbMatchHost        = "host"
	cmdbMatchIP          = "ip"
	cmdbMatchCIDR        = "cidr"
	cmdbMatchFingerprint = "fingerprint"
)

type cmdbRule struct {
	Match      string `json:"match"`       // host | ip | cidr | fingerprint
	Value      string `json:"value"`       // host: DNS name or "*.suffix"; ip: IP; cidr: CIDR; fingerprint: SHA-256 hex
	OwnerTeam  string `json:"owner_team"`  // required
	OwnerEmail string `json:"owner_email"` // optional, must contain "@" if set

	network *net.IPNet // parsed once for cidr rules
	ip      net.IP     // parsed once for ip rules
}

// cmdbRowRejection reports a fingerprint row that was not applied. A
// fingerprint naming another tenant's certificate and one naming no
// certificate at all get the same reason, so the response cannot be used to
// probe for certificates the caller may not see.
type cmdbRowRejection struct {
	Row    int    `json:"row"` // 1-based position in the submitted rules
	Reason string `json:"reason"`
}

type cmdbImportResult struct {
	Rules         int                `json:"rules"`
	Matched       int                `json:"matched"`
	Assigned      int                `json:"assigned"`
	SkippedManual int                `json:"skipped_manual"`
	SkippedOther  int                `json:"skipped_other"`
	Failed        int                `json:"failed"`
	Rejected      []cmdbRowRejection `json:"rejected"`
	DryRun        bool               `json:"dry_run"`
}

// RegisterOwnershipCMDBHandlers mounts POST /api/v1/ownership/cmdb-import.
func RegisterOwnershipCMDBHandlers(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/ownership/cmdb-import", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "ownership.cmdb_import", "ownership", "cmdb", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		// An import reassigns owners across whatever it matches, so it needs
		// the certificate-admin role (a team-scoped principal may only touch
		// its own team's certificates, which a rule file cannot express).
		// Tenant-scoped admins are allowed but only ever reach their own
		// tenant's certificates; see cmdbCertVisible.
		if !isCertificateAdmin(pd) {
			emitAuditEvent(r, auditProvider, pd.ID, "ownership.cmdb_import", "ownership", "cmdb", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCMDBBodyBytes))
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "ownership.cmdb_import", "ownership", "cmdb", AuditOutcomeFailure)
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "request body unreadable")
			return
		}
		rules, err := parseCMDBRules(r.Header.Get("Content-Type"), raw)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "ownership.cmdb_import", "ownership", "cmdb", AuditOutcomeFailure)
			writeBadRequest(w, err.Error())
			return
		}
		dryRun := strings.EqualFold(r.URL.Query().Get("dry_run"), "true")

		result, err := applyCMDBRules(r.Context(), certProvider, pd, rules, dryRun)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "ownership.cmdb_import", "ownership", "cmdb", AuditOutcomeFailure)
			logging.Warnf("cmdb ownership import unavailable: %v", err)
			writeServiceUnavailable(w, "certificate inventory unavailable")
			return
		}

		if !dryRun {
			summary, _ := json.Marshal(result)
			emitAuditEventDetail(r, auditProvider, pd.ID, "ownership.cmdb_import", "ownership", "cmdb", AuditOutcomeSuccess, string(summary))
		}
		writeJSONData(w, result)
	})
}

// parseCMDBRules decodes and validates a rule set from JSON ({"rules":[...]})
// or, for text/csv, a header row of match,value,owner_team[,owner_email].
func parseCMDBRules(contentType string, body []byte) ([]cmdbRule, error) {
	mt, _, _ := mime.ParseMediaType(contentType)
	var rules []cmdbRule
	if mt == "text/csv" {
		parsed, err := parseCMDBCSV(body)
		if err != nil {
			return nil, err
		}
		rules = parsed
	} else {
		var doc struct {
			Rules []cmdbRule `json:"rules"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, errors.New(`body must be JSON {"rules":[...]} or text/csv`)
		}
		rules = doc.Rules
	}
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	if len(rules) > maxCMDBRules {
		return nil, fmt.Errorf("at most %d rules per import", maxCMDBRules)
	}
	for i := range rules {
		if err := normalizeCMDBRule(&rules[i]); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return rules, nil
}

func parseCMDBCSV(body []byte) ([]cmdbRule, error) {
	cr := csv.NewReader(strings.NewReader(string(body)))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	header, err := cr.Read()
	if err != nil {
		return nil, errors.New("csv needs a header row: match,value,owner_team,owner_email")
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, bomPrefix)))] = i
	}
	for _, need := range []string{"match", "value", "owner_team"} {
		if _, ok := col[need]; !ok {
			return nil, errors.New("csv header must include match,value,owner_team (owner_email optional)")
		}
	}
	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	var rules []cmdbRule
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("csv is malformed")
		}
		if len(rules) >= maxCMDBRules {
			return nil, fmt.Errorf("at most %d rules per import", maxCMDBRules)
		}
		rules = append(rules, cmdbRule{
			Match: get(rec, "match"), Value: get(rec, "value"),
			OwnerTeam: get(rec, "owner_team"), OwnerEmail: get(rec, "owner_email"),
		})
	}
	return rules, nil
}

func normalizeCMDBRule(r *cmdbRule) error {
	r.Match = strings.ToLower(strings.TrimSpace(r.Match))
	r.Value = strings.TrimSpace(r.Value)
	r.OwnerTeam = strings.TrimSpace(r.OwnerTeam)
	r.OwnerEmail = strings.TrimSpace(r.OwnerEmail)
	if r.OwnerTeam == "" {
		return errors.New("owner_team is required")
	}
	if len(r.OwnerTeam) > 128 {
		return errors.New("owner_team is too long")
	}
	if r.OwnerEmail != "" && (!strings.Contains(r.OwnerEmail, "@") || len(r.OwnerEmail) > 254) {
		return errors.New("owner_email must be an email address")
	}
	if r.Value == "" || strings.ContainsAny(r.Value, " \t\r\n") {
		return errors.New("value is required and must not contain whitespace")
	}
	switch r.Match {
	case cmdbMatchHost:
		r.Value = strings.ToLower(r.Value)
		// Only a leading "*." wildcard: a bare "*" or "a.*.b" would match
		// far more than any CMDB row intends.
		if strings.Contains(strings.TrimPrefix(r.Value, "*."), "*") || r.Value == "*." {
			return errors.New(`host wildcard must be a leading "*." followed by a suffix`)
		}
	case cmdbMatchIP:
		r.ip = net.ParseIP(r.Value)
		if r.ip == nil {
			return errors.New("value is not a valid IP address")
		}
	case cmdbMatchCIDR:
		_, n, err := net.ParseCIDR(r.Value)
		if err != nil {
			return errors.New("value is not a valid CIDR")
		}
		r.network = n
	case cmdbMatchFingerprint:
		r.Value = strings.ToLower(r.Value)
	default:
		return errors.New("match must be one of host, ip, cidr, fingerprint")
	}
	return nil
}

func matchCMDBRuleIndex(rules []cmdbRule, item CertificateItem) int {
	for i := range rules {
		if cmdbRuleMatches(&rules[i], item) {
			return i
		}
	}
	return -1
}

func cmdbRuleMatches(r *cmdbRule, item CertificateItem) bool {
	switch r.Match {
	case cmdbMatchFingerprint:
		return strings.EqualFold(item.FingerprintSHA256, r.Value)
	case cmdbMatchHost:
		if cmdbHostMatches(r.Value, item.CommonName) {
			return true
		}
		for _, san := range item.SubjectAltNames {
			if cmdbHostMatches(r.Value, san) {
				return true
			}
		}
	case cmdbMatchIP, cmdbMatchCIDR:
		for _, san := range item.SubjectAltNames {
			ip := net.ParseIP(san)
			if ip == nil {
				continue
			}
			if r.Match == cmdbMatchIP && r.ip.Equal(ip) {
				return true
			}
			if r.Match == cmdbMatchCIDR && r.network != nil && r.network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// cmdbHostMatches compares a lowercase rule host (or "*.suffix") with a name.
// "*.suffix" matches one or more labels before the suffix, not the suffix
// itself.
func cmdbHostMatches(rule, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	if suffix, ok := strings.CutPrefix(rule, "*."); ok {
		return strings.HasSuffix(name, "."+suffix) && len(name) > len(suffix)+1
	}
	return name == rule
}

// cmdbCertVisible gates every certificate the import may touch. Unlike the
// shared caVisibleToTenant it also denies when multi-tenancy is on but no
// tenant store is wired, because an import is a bulk write.
func cmdbCertVisible(ctx context.Context, pd AuthPrincipal, item CertificateItem) bool {
	if tenantBypass(pd) {
		return true
	}
	if activeTenantStore == nil {
		return false
	}
	return caVisibleToTenant(ctx, activeTenantStore, pd, item.CAID)
}

type cmdbMatch struct {
	item CertificateItem
	rule int
}

// applyCMDBRules walks the whole inventory once, collects matches the caller
// may see, then mutates after the walk (UpdateOwnership takes the provider
// lock a ForEachCertificate pass must not hold).
func applyCMDBRules(ctx context.Context, p CertificateProvider, pd AuthPrincipal, rules []cmdbRule, dryRun bool) (cmdbImportResult, error) {
	result := cmdbImportResult{Rules: len(rules), Rejected: []cmdbRowRejection{}, DryRun: dryRun}
	fingerprintHit := make([]bool, len(rules))
	var matches []cmdbMatch

	err := ForEachCertificate(ctx, p, CertificateListQuery{}, func(item CertificateItem) error {
		i := matchCMDBRuleIndex(rules, item)
		if i < 0 {
			return nil
		}
		// Invisible certificates are dropped before they are counted, so
		// the totals cannot reveal another tenant's inventory either.
		if !cmdbCertVisible(ctx, pd, item) {
			return nil
		}
		fingerprintHit[i] = true
		matches = append(matches, cmdbMatch{item: item, rule: i})
		return nil
	})
	if err != nil {
		return result, err
	}

	for i, rule := range rules {
		if rule.Match == cmdbMatchFingerprint && !fingerprintHit[i] {
			result.Rejected = append(result.Rejected, cmdbRowRejection{Row: i + 1, Reason: "certificate not found"})
		}
	}

	for _, m := range matches {
		result.Matched++
		switch cmdbOverwriteClass(m.item) {
		case OwnershipSourceManual:
			result.SkippedManual++
			continue
		case OwnershipSourceImport:
			result.SkippedOther++
			continue
		}
		if dryRun {
			result.Assigned++
			continue
		}
		rule := rules[m.rule]
		email := rule.OwnerEmail
		if email == "" {
			email = m.item.OwnerEmail
		}
		// UpdateOwnership overwrites service_name with the request value,
		// so carry the existing one; Labels nil leaves labels untouched.
		_, err := p.UpdateOwnership(ctx, m.item.FingerprintSHA256, CertificateOwnershipRequest{
			OwnerTeam: rule.OwnerTeam, OwnerEmail: email, ServiceName: m.item.ServiceName,
			Source: OwnershipSourceCMDB,
		})
		if err != nil {
			logging.Infof("cmdb ownership import: %s not updated: %v", m.item.FingerprintSHA256, err)
			result.Failed++
			continue
		}
		result.Assigned++
	}
	return result, nil
}

// cmdbOverwriteClass buckets a certificate by whether the import may replace
// its owner: "" (free to assign: unowned, or a previous cmdb value),
// OwnershipSourceManual (a person chose it), or OwnershipSourceImport (bulk
// import or agent). An owner with no recorded source predates ownership_source
// and is treated as manual, so a legacy hand-set owner is never overwritten.
func cmdbOverwriteClass(item CertificateItem) string {
	switch item.OwnershipSource {
	case "", OwnershipSourceCMDB:
		if item.OwnershipSource == "" && item.OwnerTeam != "" {
			return OwnershipSourceManual
		}
		return ""
	case OwnershipSourceManual:
		return OwnershipSourceManual
	default:
		return OwnershipSourceImport
	}
}

// bomPrefix is the UTF-8 byte-order mark spreadsheet exports prepend to CSV.
const bomPrefix = "\xef\xbb\xbf"
