// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package adcs imports Active Directory Certificate Services templates
// (pKICertificateTemplate objects), either from an ldifde-style JSON export
// or by a read-only LDAP search.
package adcs

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/adsync"
	"kryptkeeper/internal/migration"
)

// Source is the importer's registry name.
const Source = "adcs"

// ADCS attribute names. These come from the Microsoft [MS-CRTD] documentation,
// not from a live export: a human must confirm them against a real ldifde dump
// before this importer is trusted in production.
const (
	attrCN             = "cn"
	attrDisplayName    = "displayName"
	attrOID            = "msPKI-Cert-Template-OID"
	attrSchemaVersion  = "msPKI-Template-Schema-Version"
	attrMinKeySize     = "msPKI-Minimal-Key-Size"
	attrExpiration     = "pKIExpirationPeriod"
	attrOverlap        = "pKIOverlapPeriod"
	attrKeyUsage       = "pKIKeyUsage"
	attrEKU            = "pKIExtendedKeyUsage"
	attrCSPs           = "pKIDefaultCSPs"
	attrEnrollmentFlag = "msPKI-Enrollment-Flag"
	attrNameFlag       = "msPKI-Certificate-Name-Flag"
	attrAppPolicy      = "msPKI-Certificate-Application-Policy"
)

// Infrastructure purposes (B5 of the ADCS cutover rehearsal). The importer
// cannot read the template's enrollment ACL, so a template whose EKUs say it
// is for domain controllers, Kerberos or IPsec/RAS servers is not offered to
// general autoenrollment: ADCS grants those to DCs and RAS servers only.
const (
	ekuKDCAuth           = "1.3.6.1.5.2.3.5"
	ekuSmartcardLogon    = "1.3.6.1.4.1.311.20.2.2"
	ekuIKEIntermediate   = "1.3.6.1.5.5.8.2.2"
	ekuDSEmailReplicator = "1.3.6.1.4.1.311.21.19"
	// CA-infrastructure EKUs: only the CA, its OCSP responder, enrollment
	// agents and key recovery agents use these, never ordinary autoenrollment.
	ekuOCSPSigning       = "1.3.6.1.5.5.7.3.9"
	ekuCertRequestAgent  = "1.3.6.1.4.1.311.20.2.1"
	ekuPrivateKeyArchive = "1.3.6.1.4.1.311.21.5"
	ekuKeyRecoveryAgent  = "1.3.6.1.4.1.311.21.6"
)

// infraTemplateNames are the built-in names of such templates. RASAndIASServer
// carries only client+server auth, so its name is the only signal.
var infraTemplateNames = map[string]bool{
	"domaincontroller": true, "domaincontrollerauthentication": true, "kerberosauthentication": true,
	"rasandiasserver": true, "directoryemailreplication": true, "ipsecintermediateoffline": true,
	"ipsecintermediateonline": true,
	// CA infrastructure: some carry no distinguishing EKU (CrossCA, SubCA).
	"ocspresponsesigning": true, "caexchange": true, "crosscertificationauthority": true, "crossca": true,
	"enrollmentagent": true, "enrollmentagentoffline": true, "exchangeenrollmentagentofflinerequest": true,
	"keyrecoveryagent": true, "subca": true, "ca": true, "rootcertificationauthority": true, "cepencryption": true,
}

// restrictedEnrollRoles restrict an infrastructure template to API issuance
// by pki-admin, and protocol:wstep:restricted (wstep.RestrictedRole) makes
// XCEP/WSTEP enforce the list, so no Windows client is offered it until an
// admin adds protocol:wstep:<host fqdn> (one machine such as a DC) or
// protocol:wstep. The literal is kept here: this package does not import wstep.
var restrictedEnrollRoles = []string{"pki-admin", "protocol:wstep:restricted"}

// infrastructurePurpose names why a template is DC/Kerberos/RAS-only, or "".
func infrastructurePurpose(name string, a map[string][]string, user bool) string {
	ekus := map[string]bool{}
	for _, k := range []string{attrEKU, attrAppPolicy} {
		for _, oid := range a[k] {
			ekus[strings.TrimSpace(oid)] = true
		}
	}
	switch {
	case ekus[ekuKDCAuth]:
		return "KDC authentication EKU (domain controllers)"
	case ekus[ekuDSEmailReplicator]:
		return "directory service email replication EKU (domain controllers)"
	case ekus[ekuIKEIntermediate]:
		return "IKE intermediate EKU (IPsec/RAS servers)"
	case ekus[ekuOCSPSigning]:
		return "OCSP response signing EKU (CA infrastructure)"
	case ekus[ekuCertRequestAgent]:
		return "certificate request agent EKU (CA infrastructure)"
	case ekus[ekuPrivateKeyArchive]:
		return "private key archival EKU (CA exchange)"
	case ekus[ekuKeyRecoveryAgent]:
		return "key recovery agent EKU (CA infrastructure)"
	case ekus[ekuSmartcardLogon] && !user:
		return "smart card logon EKU on a machine template (domain controller authentication)"
	case infraTemplateNames[strings.ToLower(name)]:
		return "built-in " + name + " template (domain controllers, Kerberos or RAS servers)"
	}
	return ""
}

// unmappedAttrs are requested over LDAP only so they can be reported as
// having no Kryptkeeper equivalent.
var unmappedAttrs = []string{
	"msPKI-Private-Key-Flag", "msPKI-RA-Signature", "msPKI-Certificate-Policy",
	"msPKI-Certificate-Application-Policy", "pKIDefaultKeySpec", "pKIMaxIssuingDepth",
	"pKICriticalExtensions", "flags", "revision", "msPKI-Template-Minor-Revision",
}

// binaryAttrs carry raw bytes; exports and Read both hold them as base64.
var binaryAttrs = []string{attrExpiration, attrOverlap, attrKeyUsage}

func requestedAttrs() []string {
	return append([]string{attrCN, attrDisplayName, attrOID, attrSchemaVersion, attrMinKeySize,
		attrExpiration, attrOverlap, attrKeyUsage, attrEKU, attrCSPs, attrEnrollmentFlag, attrNameFlag},
		unmappedAttrs...)
}

// Importer implements migration.Importer and migration.LiveReader.
type Importer struct{}

// New returns the ADCS importer.
func New() *Importer { return &Importer{} }

var (
	_ migration.Importer   = (*Importer)(nil)
	_ migration.LiveReader = (*Importer)(nil)
)

// Source implements migration.Importer.
func (*Importer) Source() string { return Source }

// dial is swapped in tests.
var dial = func(url, bindDN, secret string, allowCleartext bool) (adsync.LDAPClient, error) {
	return adsync.DialAndBind(url, bindDN, secret, allowCleartext)
}

type exportEntry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

// Parse accepts {"templates":[...]} or a bare array of the same objects.
func (*Importer) Parse(_ context.Context, in migration.Input) ([]migration.SourceObject, error) {
	var entries []exportEntry
	var wrapped struct {
		Templates []exportEntry `json:"templates"`
	}
	trimmed := strings.TrimSpace(string(in.Content))
	switch {
	case strings.HasPrefix(trimmed, "["):
		if err := json.Unmarshal(in.Content, &entries); err != nil {
			return nil, fmt.Errorf("decode template array: %w", err)
		}
	default:
		if err := json.Unmarshal(in.Content, &wrapped); err != nil {
			return nil, fmt.Errorf("decode export: %w", err)
		}
		entries = wrapped.Templates
	}
	out := make([]migration.SourceObject, 0, len(entries))
	for _, e := range entries {
		out = append(out, toObject(e.DN, e.Attributes))
	}
	return out, nil
}

func toObject(dn string, attrs map[string][]string) migration.SourceObject {
	if attrs == nil {
		attrs = map[string][]string{}
	}
	name := ""
	if v := attrs[attrCN]; len(v) > 0 {
		name = v[0]
	}
	return migration.SourceObject{Kind: "template", SourceKey: dn, Name: name,
		Raw: map[string]any{"dn": dn, "attrs": attrs}}
}

// Read searches o.BaseDN for pKICertificateTemplate objects. It only searches;
// the directory is never modified.
func (*Importer) Read(_ context.Context, o migration.ReadOptions) ([]migration.SourceObject, error) {
	if strings.TrimSpace(o.BaseDN) == "" {
		return nil, errors.New("base_dn required (the CN=Certificate Templates,... container)")
	}
	c, err := dial(o.URL, o.BindDN, o.Secret, o.AllowCleartext)
	if err != nil {
		return nil, fmt.Errorf("connect to directory: %w", err)
	}
	defer func() { _ = c.Close() }()
	entries, err := c.Search(o.BaseDN, "(objectClass=pKICertificateTemplate)", requestedAttrs())
	if err != nil {
		return nil, fmt.Errorf("search templates: %w", err)
	}
	out := make([]migration.SourceObject, 0, len(entries))
	for _, e := range entries {
		attrs := make(map[string][]string, len(e.Attributes))
		for k, v := range e.Attributes {
			attrs[k] = append([]string(nil), v...)
		}
		for _, k := range binaryAttrs {
			for i, v := range attrs[k] {
				// go-ldap hands binary values over as raw bytes in a string.
				attrs[k][i] = base64.StdEncoding.EncodeToString([]byte(v))
			}
		}
		out = append(out, toObject(e.DN, attrs))
	}
	return out, nil
}

func attrsOf(raw map[string]any) map[string][]string {
	switch a := raw["attrs"].(type) {
	case map[string][]string:
		return a
	case map[string]any:
		out := make(map[string][]string, len(a))
		for k, v := range a {
			if list, ok := v.([]any); ok {
				for _, x := range list {
					out[k] = append(out[k], fmt.Sprint(x))
				}
			}
		}
		return out
	}
	return map[string][]string{}
}

func first(a map[string][]string, k string) string {
	if v := a[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// decodeTicks reads a base64 8-byte little-endian negative 100ns tick count.
func decodeTicks(b64 string) (time.Duration, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 8 {
		return 0, false
	}
	v := int64(binary.LittleEndian.Uint64(raw))
	if v >= 0 {
		return 0, false
	}
	secs := -v / 10_000_000
	if secs <= 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

var keyUsageBits = []struct {
	mask byte
	name string
}{
	{0x80, "digitalSignature"}, {0x40, "contentCommitment"}, {0x20, "keyEncipherment"},
	{0x10, "dataEncipherment"}, {0x08, "keyAgreement"}, {0x04, "keyCertSign"}, {0x02, "cRLSign"},
}

func decodeKeyUsage(b64 string) []string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var out []string
	for _, b := range keyUsageBits {
		if raw[0]&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

// Map converts one template. It is pure and deterministic.
func (*Importer) Map(obj migration.SourceObject) (migration.Mapped, error) {
	a := attrsOf(obj.Raw)
	var m migration.Mapped
	add := func(field string, st migration.FieldStatus, target, note string) {
		m.Fields = append(m.Fields, migration.FieldReport{Field: field, Status: st, Target: target, Note: note})
	}
	has := func(k string) bool { return len(a[k]) > 0 }

	// v1 templates are the built-in schema; refuse before mapping anything.
	if v := first(a, attrSchemaVersion); v == "" || v == "1" {
		names := make([]string, 0, len(a))
		for k := range a {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			add(k, migration.FieldUnmapped, "", "v1 template not mapped")
		}
		m.Unsupported = "ADCS v1 template (built-in schema); not mapped"
		return m, nil
	}
	add(attrSchemaVersion, migration.FieldMapped, "", "schema version 2 or later")

	t := &m.Template
	t.Name = first(a, attrCN)
	if t.Name == "" {
		m.Unsupported = "missing cn"
		return m, nil
	}
	add(attrCN, migration.FieldMapped, "name", "")
	if dn := first(a, attrDisplayName); dn != "" {
		t.DisplayName = dn
		add(attrDisplayName, migration.FieldMapped, "display_name", "")
	} else {
		t.DisplayName = t.Name
		add(attrDisplayName, migration.FieldPartial, "display_name", "defaulted to cn")
	}
	if has(attrOID) {
		t.OID = first(a, attrOID)
		add(attrOID, migration.FieldMapped, "oid", "")
	}

	if n, err := strconv.Atoi(first(a, attrMinKeySize)); err == nil && n > 0 {
		t.MinKeySize = n
		add(attrMinKeySize, migration.FieldMapped, "min_key_size", "")
	} else {
		t.MinKeySize = 2048
		add(attrMinKeySize, migration.FieldPartial, "min_key_size", "defaulted to 2048")
	}

	t.AllowedAlgorithms = []string{"RSA"}
	for _, c := range a[attrCSPs] {
		if strings.Contains(strings.ToLower(c), "ecdsa") {
			t.AllowedAlgorithms = []string{"ECDSA"}
		}
	}
	if has(attrCSPs) {
		add(attrCSPs, migration.FieldPartial, "allowed_algorithms", "inferred from CSP")
	} else {
		add("(allowed_algorithms)", migration.FieldPartial, "allowed_algorithms", "no CSP; defaulted to RSA")
	}

	d, ok := decodeTicks(first(a, attrExpiration))
	if !ok {
		add(attrExpiration, migration.FieldUnmapped, "validity_period", "unreadable")
		m.Unsupported = "missing or unreadable pKIExpirationPeriod"
		return m, nil
	}
	t.ValidityPeriod = migration.ValidityFromDuration(d)
	add(attrExpiration, migration.FieldMapped, "validity_period", "")
	if has(attrOverlap) {
		if od, ok := decodeTicks(first(a, attrOverlap)); ok {
			t.RenewalOverlap = migration.ValidityFromDuration(od)
			add(attrOverlap, migration.FieldMapped, "renewal_overlap", "")
		} else {
			add(attrOverlap, migration.FieldUnmapped, "renewal_overlap", "unreadable")
		}
	}

	t.KeyUsage = decodeKeyUsage(first(a, attrKeyUsage))
	if len(t.KeyUsage) == 0 {
		add(attrKeyUsage, migration.FieldUnmapped, "key_usage", "empty")
		m.Unsupported = "no key usage"
		return m, nil
	}
	add(attrKeyUsage, migration.FieldMapped, "key_usage", "")

	for _, oid := range a[attrEKU] {
		if name, ok := migration.EKUFromOID(oid); ok {
			t.ExtendedKeyUsage = append(t.ExtendedKeyUsage, name)
		} else {
			add(attrEKU+"["+oid+"]", migration.FieldUnmapped, "", "custom OID")
		}
	}
	if len(t.ExtendedKeyUsage) == 0 {
		m.Unsupported = "no mappable extended key usage"
		return m, nil
	}
	add(attrEKU, migration.FieldMapped, "extended_key_usage", "")

	if has(attrEnrollmentFlag) {
		f, err := strconv.ParseInt(first(a, attrEnrollmentFlag), 10, 64)
		if err != nil {
			add(attrEnrollmentFlag, migration.FieldUnmapped, "", "unreadable flag")
		} else {
			t.RequireApproval = f&0x2 != 0
			t.AutoEnroll = f&0x20 != 0
			add(attrEnrollmentFlag+"[PEND_ALL_REQUESTS]", migration.FieldMapped, "require_approval", "")
			add(attrEnrollmentFlag+"[AUTO_ENROLLMENT]", migration.FieldMapped, "auto_enroll", "")
			add(attrEnrollmentFlag, migration.FieldPartial, "", "remaining bits not modelled")
		}
	}
	if has(attrNameFlag) {
		f, err := strconv.ParseInt(first(a, attrNameFlag), 10, 64)
		if err != nil {
			add(attrNameFlag, migration.FieldUnmapped, "", "unreadable flag")
		} else {
			t.EnrolleeType = "machine"
			if f&0x02000000 != 0 || f&0x04000000 != 0 {
				t.EnrolleeType = "user"
			}
			note := ""
			if f&0x1 != 0 {
				note = "all Kryptkeeper templates accept a CSR subject"
			}
			add(attrNameFlag, migration.FieldPartial, "enrollee_type", note)
		}
	}

	if why := infrastructurePurpose(t.Name, a, t.EnrolleeType == "user"); why != "" {
		t.AutoEnroll = false
		t.EnrollRoles = append([]string(nil), restrictedEnrollRoles...)
		m.Notes = append(m.Notes, "not offered to general autoenrollment ("+why+"): enrollment restricted to "+
			strings.Join(restrictedEnrollRoles, ", ")+"; add protocol:wstep:<host fqdn> (one machine) or protocol:wstep (every Windows client) "+
			"to the template's enrollment_permissions.enroll to offer it over XCEP")
	}

	known := map[string]bool{attrCN: true, attrDisplayName: true, attrOID: true, attrSchemaVersion: true,
		attrMinKeySize: true, attrExpiration: true, attrOverlap: true, attrKeyUsage: true, attrEKU: true,
		attrCSPs: true, attrEnrollmentFlag: true, attrNameFlag: true}
	var rest []string
	for k := range a {
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
