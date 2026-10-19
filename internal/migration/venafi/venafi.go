// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package venafi imports a Venafi TPP policy-folder tree, flattening
// attribute inheritance, as Kryptkeeper templates.
package venafi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/migration"
)

// Source is the importer's registry name.
const Source = "venafi"

// Venafi TPP attribute names, taken from the TPP documentation and NOT checked
// against a real export. A human must confirm them against a real TPP
// Config/ReadAll dump before this importer is advertised; any attribute not
// listed here is reported unmapped, so a wrong name lowers the visible
// percentage instead of silently losing data.
const (
	aKeyAlgorithm   = "Key Algorithm"
	aKeyBitStrength = "Key Bit Strength"
	aEllipticCurve  = "Elliptic Curve"
	aDomainSuffixes = "Domain Suffix Whitelist"
	aProhibitWild   = "Prohibit Wildcard"
	aContact        = "Contact"
	aApprover       = "Approver"
	aDisableRenewal = "Disable Automatic Renewal"
	aRenewalWindow  = "Renewal Window"
	aValidityPeriod = "Validity Period"
	aManagementType = "Management Type"
	aCA             = "Certificate Authority"
)

const policyRoot = `\VED\Policy\`

// Importer implements migration.Importer.
type Importer struct{}

// New returns the Venafi importer.
func New() *Importer { return &Importer{} }

var _ migration.Importer = (*Importer)(nil)

// Source implements migration.Importer.
func (*Importer) Source() string { return Source }

type folder struct {
	Path       string              `json:"path"`
	Attributes map[string][]string `json:"attributes"`
}

// Parse flattens {"folders":[...]} into one SourceObject per folder that sets
// at least one attribute of its own; inherited values go into Raw["effective"].
func (*Importer) Parse(_ context.Context, in migration.Input) ([]migration.SourceObject, error) {
	var doc struct {
		Folders []folder `json:"folders"`
	}
	if err := json.Unmarshal(in.Content, &doc); err != nil {
		return nil, fmt.Errorf("decode export: %w", err)
	}
	fs := doc.Folders
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Path < fs[j].Path })

	effective := make(map[string]map[string][]string, len(fs))
	var out []migration.SourceObject
	for i, f := range fs {
		eff := map[string][]string{}
		// The longest proper prefix sorts before f, so it is already computed.
		for j := i - 1; j >= 0; j-- {
			if strings.HasPrefix(f.Path, fs[j].Path+`\`) {
				for k, v := range effective[fs[j].Path] {
					eff[k] = v
				}
				break
			}
		}
		own := map[string][]string{}
		for k, v := range f.Attributes {
			eff[k] = v
			own[k] = v
		}
		effective[f.Path] = eff
		if len(own) == 0 {
			continue // pure container
		}
		out = append(out, migration.SourceObject{Kind: "folder", SourceKey: "venafi:" + f.Path, Name: folderName(f.Path),
			Raw: map[string]any{"path": f.Path, "own": own, "effective": eff}})
	}
	return out, nil
}

var spaces = regexp.MustCompile(` +`)

func folderName(p string) string {
	n := strings.TrimPrefix(p, policyRoot)
	n = strings.TrimPrefix(n, `\`)
	return spaces.ReplaceAllString(strings.ReplaceAll(n, `\`, "-"), "-")
}

func lastSegment(p string) string {
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func attrMap(v any) map[string][]string {
	m, _ := v.(map[string][]string)
	return m
}

func firstOf(m map[string][]string, k string) string {
	if v := m[k]; len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

func days(m map[string][]string, k string) (int, bool) {
	n, err := strconv.Atoi(firstOf(m, k))
	return n, err == nil && n > 0
}

// Map converts one folder. It is pure and deterministic.
func (*Importer) Map(obj migration.SourceObject) (migration.Mapped, error) {
	own, eff := attrMap(obj.Raw["own"]), attrMap(obj.Raw["effective"])
	if own == nil || eff == nil {
		return migration.Mapped{}, errors.New("folder object lacks own/effective attributes")
	}
	path, _ := obj.Raw["path"].(string)
	var m migration.Mapped
	add := func(field string, st migration.FieldStatus, target, note string) {
		m.Fields = append(m.Fields, migration.FieldReport{Field: field, Status: st, Target: target, Note: note})
	}
	ownHas := func(k string) bool { _, ok := own[k]; return ok }

	t := &m.Template
	t.Name, t.DisplayName, t.EnrolleeType = obj.Name, lastSegment(path), "machine"
	t.KeyUsage = []string{"digitalSignature", "keyEncipherment"}
	t.ExtendedKeyUsage = []string{"clientAuth", "serverAuth"}
	add("(synthesized) keyUsage/extendedKeyUsage", migration.FieldPartial, "key_usage", "defaulted; review before use")

	// Key algorithm and size.
	algo := strings.ToUpper(firstOf(eff, aKeyAlgorithm))
	switch algo {
	case "RSA":
		t.AllowedAlgorithms = []string{"RSA"}
	case "ECC":
		t.AllowedAlgorithms = []string{"ECDSA"}
	case "":
		t.AllowedAlgorithms = []string{"RSA"}
		algo = "RSA"
	default:
		m.Unsupported = "unsupported key algorithm " + strconv.Quote(firstOf(eff, aKeyAlgorithm))
	}
	switch {
	case ownHas(aKeyAlgorithm) && m.Unsupported != "":
		add(aKeyAlgorithm, migration.FieldUnmapped, "", "unsupported key algorithm")
	case ownHas(aKeyAlgorithm):
		add(aKeyAlgorithm, migration.FieldMapped, "allowed_algorithms", "")
	case firstOf(eff, aKeyAlgorithm) == "":
		add("(key_algorithm)", migration.FieldPartial, "allowed_algorithms", "not set in the folder or its parents; defaulted to RSA")
	}
	if n, ok := days(eff, aKeyBitStrength); ok {
		t.MinKeySize = n
		if ownHas(aKeyBitStrength) {
			add(aKeyBitStrength, migration.FieldMapped, "min_key_size", "")
		}
	} else {
		t.MinKeySize = 2048
		if algo == "ECC" {
			t.MinKeySize = 256
		}
		if ownHas(aKeyBitStrength) {
			add(aKeyBitStrength, migration.FieldUnmapped, "min_key_size", "unreadable; defaulted")
		} else {
			add("(key_bit_strength)", migration.FieldPartial, "min_key_size", "not set; defaulted")
		}
	}
	if ownHas(aEllipticCurve) {
		add(aEllipticCurve, migration.FieldPartial, "", "curve is chosen by the CA")
	}

	// Name policy.
	if suffixes := eff[aDomainSuffixes]; len(suffixes) > 0 {
		np := &ca.NamePolicy{}
		for _, s := range suffixes {
			if s = strings.TrimSpace(s); s != "" {
				np.AllowedDNSSuffixes = append(np.AllowedDNSSuffixes, s)
			}
		}
		sort.Strings(np.AllowedDNSSuffixes)
		t.NamePolicy = np
	}
	if ownHas(aDomainSuffixes) {
		add(aDomainSuffixes, migration.FieldMapped, "name_policy.allowed_dns_suffixes", "")
	}
	if ownHas(aProhibitWild) {
		add(aProhibitWild, migration.FieldPartial, "", "name policy has no wildcard switch; enforced by the issuing CA profile")
	}

	// Ownership and approval.
	if contacts := append([]string(nil), eff[aContact]...); len(contacts) > 0 {
		sort.Strings(contacts)
		t.OwnerHint = strings.Join(contacts, ",")
	}
	if ownHas(aContact) {
		add(aContact, migration.FieldPartial, "owner_hint", "no owner field on templates yet; carried on the migration batch item")
	}
	approvers := append([]string(nil), eff[aApprover]...)
	sort.Strings(approvers)
	if len(approvers) > 0 {
		t.RequireApproval = true
	}
	if ownHas(aApprover) {
		add(aApprover, migration.FieldPartial, "require_approval",
			"approvers "+strings.Join(approvers, ", ")+" are not carried; approval roles default to pki-admin")
	}

	// Renewal.
	t.AutoEnroll = firstOf(eff, aDisableRenewal) != "1"
	switch {
	case ownHas(aDisableRenewal):
		add(aDisableRenewal, migration.FieldMapped, "auto_enroll", "")
	case len(eff[aDisableRenewal]) == 0:
		add("(auto_enroll)", migration.FieldPartial, "auto_enroll", "not set; automatic renewal assumed")
	}
	if n, ok := days(eff, aRenewalWindow); ok {
		t.RenewalOverlap = migration.ValidityFromDuration(time.Duration(n) * 24 * time.Hour)
		if ownHas(aRenewalWindow) {
			add(aRenewalWindow, migration.FieldMapped, "renewal_overlap", "")
		}
	} else if ownHas(aRenewalWindow) {
		add(aRenewalWindow, migration.FieldUnmapped, "renewal_overlap", "unreadable")
	}
	if n, ok := days(eff, aValidityPeriod); ok {
		t.ValidityPeriod = migration.ValidityFromDuration(time.Duration(n) * 24 * time.Hour)
		if ownHas(aValidityPeriod) {
			add(aValidityPeriod, migration.FieldMapped, "validity_period", "")
		}
	} else {
		t.ValidityPeriod = "P365D"
		if ownHas(aValidityPeriod) {
			add(aValidityPeriod, migration.FieldUnmapped, "validity_period", "unreadable; defaulted")
		} else {
			add("(validity_period)", migration.FieldPartial, "validity_period", "defaulted; Venafi takes validity from the CA template")
		}
	}

	if ownHas(aManagementType) {
		add(aManagementType, migration.FieldPartial, "", "Kryptkeeper tracks management per certificate; this creates a template only")
	}
	if ownHas(aCA) {
		add(aCA, migration.FieldUnmapped, "", "CA templates are not migrated; select a CA after import")
	}

	known := map[string]bool{aKeyAlgorithm: true, aKeyBitStrength: true, aEllipticCurve: true, aDomainSuffixes: true,
		aProhibitWild: true, aContact: true, aApprover: true, aDisableRenewal: true, aRenewalWindow: true,
		aValidityPeriod: true, aManagementType: true, aCA: true}
	var rest []string
	for k := range own {
		if !known[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k, migration.FieldUnmapped, "", "no equivalent")
	}
	sort.SliceStable(m.Fields, func(i, j int) bool { return m.Fields[i].Field < m.Fields[j].Field })
	return m, nil
}
