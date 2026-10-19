// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package vault imports HashiCorp Vault PKI secrets-engine roles as
// Kryptkeeper templates, listing every role field it cannot carry.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/migration"
)

// Source is the importer's registry name.
const Source = "vault"

// Vault PKI role field names, from the Vault PKI API documentation. A human
// must confirm them against a real `vault read -format=json pki/roles/<name>`
// export before this importer is advertised; unknown fields are reported
// unmapped, so a wrong name lowers the visible percentage rather than losing data.
const (
	fTTL            = "ttl"
	fMaxTTL         = "max_ttl"
	fKeyType        = "key_type"
	fKeyBits        = "key_bits"
	fSignatureBits  = "signature_bits"
	fUsePSS         = "use_pss"
	fServerFlag     = "server_flag"
	fClientFlag     = "client_flag"
	fCodeSigning    = "code_signing_flag"
	fEmailProt      = "email_protection_flag"
	fExtKeyUsage    = "ext_key_usage"
	fExtKeyUsageOID = "ext_key_usage_oids"
	fKeyUsage       = "key_usage"
	fAllowedDomains = "allowed_domains"
	fAllowSubdoms   = "allow_subdomains"
	fAllowBare      = "allow_bare_domains"
	fAllowAnyName   = "allow_any_name"
	fAllowIPSANs    = "allow_ip_sans"
	fAllowedURISANs = "allowed_uri_sans"
	fRequireCN      = "require_cn"
)

// Importer implements migration.Importer.
type Importer struct{}

// New returns the Vault importer.
func New() *Importer { return &Importer{} }

var _ migration.Importer = (*Importer)(nil)

// Source implements migration.Importer.
func (*Importer) Source() string { return Source }

// Parse accepts {"roles":{"name":{fields}}} where each value is either the
// field map or Vault's read response {"data":{fields}}.
func (*Importer) Parse(_ context.Context, in migration.Input) ([]migration.SourceObject, error) {
	dec := json.NewDecoder(bytes.NewReader(in.Content))
	dec.UseNumber()
	var doc struct {
		Roles map[string]map[string]any `json:"roles"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode export: %w", err)
	}
	names := make([]string, 0, len(doc.Roles))
	for n := range doc.Roles {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]migration.SourceObject, 0, len(names))
	for _, n := range names {
		fields := doc.Roles[n]
		if d, ok := fields["data"].(map[string]any); ok { // Vault read response
			fields = d
		}
		out = append(out, migration.SourceObject{Kind: "role", SourceKey: "vault:" + n, Name: n, Raw: fields})
	}
	return out, nil
}

// ---- value coercion (json.Number after Parse; plain types in direct use) ----

func seconds(v any) (time.Duration, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		if err != nil || f < 0 || math.IsInf(f, 0) || f > 1e10 {
			return 0, false
		}
		return time.Duration(f) * time.Second, true
	case float64:
		return seconds(json.Number(strconv.FormatFloat(x, 'f', -1, 64)))
	case int:
		return seconds(json.Number(strconv.Itoa(x)))
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, true
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return seconds(json.Number(strconv.FormatInt(n, 10)))
		}
		if d, err := time.ParseDuration(s); err == nil && d >= 0 {
			return d, true
		}
	case nil:
		return 0, true
	}
	return 0, false
}

func intOf(v any) int {
	d, ok := seconds(v) // reuse numeric parsing; seconds==value
	if !ok {
		return 0
	}
	return int(d / time.Second)
}

func boolOf(v any, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		if b, err := strconv.ParseBool(strings.TrimSpace(x)); err == nil {
			return b
		}
	}
	return def
}

func listOf(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s := strings.TrimSpace(fmt.Sprint(e)); s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, e := range x {
			if s := strings.TrimSpace(e); s != "" {
				out = append(out, s)
			}
		}
	case string:
		for _, e := range strings.Split(x, ",") {
			if s := strings.TrimSpace(e); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

var keyUsageNames = map[string]string{
	"digitalsignature": "digitalSignature", "keyagreement": "keyAgreement", "keyencipherment": "keyEncipherment",
	"contentcommitment": "contentCommitment", "dataencipherment": "dataEncipherment",
}

func dedupSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Map converts one role. It is pure and deterministic.
func (*Importer) Map(obj migration.SourceObject) (migration.Mapped, error) {
	r := obj.Raw
	if r == nil {
		r = map[string]any{}
	}
	var m migration.Mapped
	add := func(field string, st migration.FieldStatus, target, note string) {
		m.Fields = append(m.Fields, migration.FieldReport{Field: field, Status: st, Target: target, Note: note})
	}
	present := func(k string) bool { _, ok := r[k]; return ok }
	handled := map[string]bool{}
	mark := func(ks ...string) {
		for _, k := range ks {
			handled[k] = true
		}
	}

	t := &m.Template
	t.Name, t.DisplayName, t.EnrolleeType = obj.Name, obj.Name, "machine"

	// ---- validity ----
	mark(fTTL, fMaxTTL)
	ttl, ttlOK := seconds(r[fTTL])
	maxTTL, maxOK := seconds(r[fMaxTTL])
	if present(fTTL) && !ttlOK {
		add(fTTL, migration.FieldUnmapped, "", "unreadable duration")
	}
	if present(fMaxTTL) && !maxOK {
		add(fMaxTTL, migration.FieldUnmapped, "", "unreadable duration")
	}
	switch {
	case ttl > 0:
		t.ValidityPeriod = migration.ValidityFromDuration(ttl)
		add(fTTL, migration.FieldMapped, "validity_period", "")
		if maxTTL > 0 {
			add(fMaxTTL, migration.FieldPartial, "validity_period", "template has a single validity; ttl used")
		} else if present(fMaxTTL) && maxOK {
			add(fMaxTTL, migration.FieldPartial, "validity_period", "unset (0)")
		}
	case maxTTL > 0:
		t.ValidityPeriod = migration.ValidityFromDuration(maxTTL)
		if present(fTTL) && ttlOK {
			add(fTTL, migration.FieldPartial, "validity_period", "unset (0)")
		}
		add(fMaxTTL, migration.FieldPartial, "validity_period", "max_ttl used; no ttl")
	default:
		t.ValidityPeriod = "P32D"
		if present(fTTL) && ttlOK {
			add(fTTL, migration.FieldPartial, "validity_period", "unset (0); defaulted to Vault's 768h system default")
		}
		if present(fMaxTTL) && maxOK {
			add(fMaxTTL, migration.FieldPartial, "validity_period", "unset (0)")
		}
		add("(validity_period)", migration.FieldPartial, "validity_period", "no ttl or max_ttl; Vault's 768h system default")
	}

	// ---- key type / size ----
	mark(fKeyType, fKeyBits, fSignatureBits, fUsePSS)
	keyType := strings.ToLower(strings.TrimSpace(fmt.Sprint(r[fKeyType])))
	if !present(fKeyType) || keyType == "" {
		keyType = "rsa"
		add("(key_type)", migration.FieldPartial, "allowed_algorithms", "Vault default is rsa")
	} else {
		switch keyType {
		case "rsa", "ec", "any":
			add(fKeyType, migration.FieldMapped, "allowed_algorithms", "")
		default:
			add(fKeyType, migration.FieldUnmapped, "", "unsupported key type")
		}
	}
	switch keyType {
	case "rsa":
		t.AllowedAlgorithms = []string{"RSA"}
	case "ec":
		t.AllowedAlgorithms = []string{"ECDSA"}
	case "any":
		t.AllowedAlgorithms = []string{"RSA", "ECDSA"}
	case "ed25519":
		m.Unsupported = "Ed25519 roles are not offered by Kryptkeeper templates"
	default:
		m.Unsupported = "unsupported key_type " + strconv.Quote(keyType)
	}
	if bits := intOf(r[fKeyBits]); present(fKeyBits) && bits > 0 {
		t.MinKeySize = bits
		add(fKeyBits, migration.FieldMapped, "min_key_size", "")
	} else {
		t.MinKeySize = 2048
		if keyType == "ec" {
			t.MinKeySize = 256
		}
		if present(fKeyBits) {
			add(fKeyBits, migration.FieldPartial, "min_key_size", "unset (0); defaulted")
		} else {
			add("(key_bits)", migration.FieldPartial, "min_key_size", "defaulted")
		}
	}
	if present(fSignatureBits) {
		add(fSignatureBits, migration.FieldUnmapped, "", "signature hash is chosen by the CA, not the template")
	}
	if present(fUsePSS) {
		add(fUsePSS, migration.FieldUnmapped, "", "signature hash is chosen by the CA, not the template")
	}

	// ---- extended key usage ----
	mark(fServerFlag, fClientFlag, fCodeSigning, fEmailProt, fExtKeyUsage, fExtKeyUsageOID)
	var ekus []string
	if boolOf(r[fServerFlag], true) {
		ekus = append(ekus, "serverAuth")
	}
	if boolOf(r[fClientFlag], true) {
		ekus = append(ekus, "clientAuth")
	}
	if boolOf(r[fCodeSigning], false) {
		ekus = append(ekus, "codeSigning")
	}
	if boolOf(r[fEmailProt], false) {
		ekus = append(ekus, "emailProtection")
	}
	for _, f := range []string{fServerFlag, fClientFlag, fCodeSigning, fEmailProt} {
		if present(f) {
			add(f, migration.FieldMapped, "extended_key_usage", "")
		}
	}
	if present(fExtKeyUsage) {
		add(fExtKeyUsage, migration.FieldMapped, "extended_key_usage", "")
		for _, n := range listOf(r[fExtKeyUsage]) {
			if canon, ok := migration.EKUFromName(n); ok {
				ekus = append(ekus, canon)
			} else {
				add(fExtKeyUsage+"["+n+"]", migration.FieldUnmapped, "", "unknown extended key usage name")
			}
		}
	}
	if present(fExtKeyUsageOID) {
		add(fExtKeyUsageOID, migration.FieldMapped, "extended_key_usage", "")
		for _, o := range listOf(r[fExtKeyUsageOID]) {
			if canon, ok := migration.EKUFromOID(o); ok {
				ekus = append(ekus, canon)
			} else {
				add(fExtKeyUsageOID+"["+o+"]", migration.FieldUnmapped, "", "custom OID")
			}
		}
	}
	t.ExtendedKeyUsage = dedupSorted(ekus)
	if len(t.ExtendedKeyUsage) == 0 && m.Unsupported == "" {
		m.Unsupported = "no extended key usage"
	}

	// ---- key usage ----
	mark(fKeyUsage)
	if present(fKeyUsage) {
		var ku []string
		bad := false
		for _, n := range listOf(r[fKeyUsage]) {
			if canon, ok := keyUsageNames[strings.ToLower(n)]; ok {
				ku = append(ku, canon)
			} else {
				bad = true
				add(fKeyUsage+"["+n+"]", migration.FieldUnmapped, "", "CA usages not allowed in end-entity templates")
			}
		}
		t.KeyUsage = dedupSorted(ku)
		st := migration.FieldMapped
		if bad {
			st = migration.FieldPartial
		}
		add(fKeyUsage, st, "key_usage", "")
		if len(t.KeyUsage) == 0 && m.Unsupported == "" {
			m.Unsupported = "no key usage"
		}
	} else {
		t.KeyUsage = []string{"digitalSignature", "keyAgreement", "keyEncipherment"}
		add("(key_usage)", migration.FieldPartial, "key_usage", "Vault default")
	}

	// ---- name policy ----
	mark(fAllowedDomains, fAllowSubdoms, fAllowBare, fAllowAnyName, fAllowIPSANs, fAllowedURISANs, fRequireCN)
	anyName := boolOf(r[fAllowAnyName], false)
	sub, bare := boolOf(r[fAllowSubdoms], false), boolOf(r[fAllowBare], false)
	for _, f := range []string{fAllowAnyName, fAllowSubdoms, fAllowBare, fAllowIPSANs} {
		if present(f) {
			add(f, migration.FieldMapped, "name_policy", "")
		}
	}
	if !anyName {
		np := &ca.NamePolicy{AllowIPSANs: boolOf(r[fAllowIPSANs], false)}
		domainsNote := ""
		for _, d := range listOf(r[fAllowedDomains]) {
			switch {
			case sub && bare:
				np.AllowedDNSSuffixes = append(np.AllowedDNSSuffixes, d)
			case sub:
				np.AllowedDNSSuffixes = append(np.AllowedDNSSuffixes, "."+d)
			case bare:
				np.AllowedDNSNames = append(np.AllowedDNSNames, d)
			default:
				domainsNote = "domain has no effect without allow_subdomains/allow_bare_domains"
			}
		}
		if present(fAllowedDomains) {
			st := migration.FieldMapped
			if domainsNote != "" {
				st = migration.FieldPartial
			}
			add(fAllowedDomains, st, "name_policy", domainsNote)
		}
		uriBad := false
		for _, u := range listOf(r[fAllowedURISANs]) {
			if strings.HasSuffix(u, "*") && !strings.Contains(strings.TrimSuffix(u, "*"), "*") {
				np.AllowURISANs = true
				np.AllowedURIPrefixes = append(np.AllowedURIPrefixes, strings.TrimSuffix(u, "*"))
			} else {
				uriBad = true
				add(fAllowedURISANs+"["+u+"]", migration.FieldUnmapped, "", "only prefix* patterns are modelled")
			}
		}
		if present(fAllowedURISANs) {
			st := migration.FieldMapped
			if uriBad {
				st = migration.FieldPartial
			}
			add(fAllowedURISANs, st, "name_policy", "")
		}
		if len(np.AllowedDNSSuffixes) == 0 && len(np.AllowedDNSNames) == 0 {
			add("(name_policy)", migration.FieldPartial, "name_policy", "no usable allowed_domains; Vault would refuse every DNS name, the template leaves DNS unrestricted")
		}
		np.AllowedDNSSuffixes = dedupSorted(np.AllowedDNSSuffixes)
		np.AllowedDNSNames = dedupSorted(np.AllowedDNSNames)
		np.AllowedURIPrefixes = dedupSorted(np.AllowedURIPrefixes)
		t.NamePolicy = np
	} else {
		if present(fAllowedDomains) {
			add(fAllowedDomains, migration.FieldPartial, "name_policy", "ignored: allow_any_name is true, so no name policy is set")
		}
		if present(fAllowedURISANs) {
			add(fAllowedURISANs, migration.FieldPartial, "name_policy", "ignored: allow_any_name is true, so no name policy is set")
		}
	}
	if present(fRequireCN) {
		add(fRequireCN, migration.FieldPartial, "", "Kryptkeeper always checks the CN against the SAN rules")
	}

	// ---- everything else ----
	var rest []string
	for k := range r {
		if !handled[k] {
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
