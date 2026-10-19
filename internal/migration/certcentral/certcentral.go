// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package certcentral imports DigiCert CertCentral product profiles (and
// reports organizations) as Kryptkeeper templates.
package certcentral

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"kryptkeeper/internal/migration"
)

// Source is the importer's registry name.
const Source = "certcentral"

// CertCentral field names, from the CertCentral API documentation. They have
// NOT been checked against a live account export: a human must confirm them
// before this importer is advertised. Unknown product fields are reported
// unmapped, so a wrong name lowers the visible percentage instead of dropping data.
const (
	pNameID    = "name_id"
	pName      = "name"
	pType      = "type"
	pYears     = "allowed_validity_years"
	pSigHashes = "signature_hash_types"
	oID        = "id"
	oName      = "name"
	oStatus    = "status"

	// orgKey is where Parse parks the sorted organization summaries in each
	// product's Raw map; it is not a CertCentral field.
	orgKey = "_organizations"
)

// Importer implements migration.Importer.
type Importer struct{}

// New returns the CertCentral importer.
func New() *Importer { return &Importer{} }

var _ migration.Importer = (*Importer)(nil)

// Source implements migration.Importer.
func (*Importer) Source() string { return Source }

type orgSummary struct{ Name, Status string }

// Parse accepts {"organizations":[...],"products":[...]} and yields one
// object per product. Organizations are not templates; they are attached to
// every product's Raw so each report lists them.
func (*Importer) Parse(_ context.Context, in migration.Input) ([]migration.SourceObject, error) {
	var doc struct {
		Organizations []map[string]any `json:"organizations"`
		Products      []map[string]any `json:"products"`
	}
	dec := json.NewDecoder(bytes.NewReader(in.Content))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode export: %w", err)
	}
	orgs := make([]orgSummary, 0, len(doc.Organizations))
	for _, o := range doc.Organizations {
		n := str(o[oName])
		if n == "" {
			n = str(o[oID])
		}
		orgs = append(orgs, orgSummary{Name: n, Status: str(o[oStatus])})
	}
	sort.SliceStable(orgs, func(i, j int) bool { return orgs[i].Name < orgs[j].Name })

	out := make([]migration.SourceObject, 0, len(doc.Products))
	for _, p := range doc.Products {
		raw := make(map[string]any, len(p)+1)
		for k, v := range p {
			raw[k] = v
		}
		raw[orgKey] = orgs
		id := str(p[pNameID])
		out = append(out, migration.SourceObject{Kind: "product", SourceKey: "certcentral:" + id, Name: "certcentral-" + id, Raw: raw})
	}
	return out, nil
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case json.Number:
		return x.String()
	}
	return fmt.Sprint(v)
}

// Map converts one product profile. It is pure and deterministic.
func (*Importer) Map(obj migration.SourceObject) (m migration.Mapped, _ error) {
	r := obj.Raw
	add := func(field string, st migration.FieldStatus, target, note string) {
		m.Fields = append(m.Fields, migration.FieldReport{Field: field, Status: st, Target: target, Note: note})
	}
	present := func(k string) bool { _, ok := r[k]; return ok }
	defer func() {
		known := map[string]bool{pNameID: true, pName: true, pType: true, pYears: true, pSigHashes: true, orgKey: true}
		var rest []string
		for k := range r {
			if !known[k] {
				rest = append(rest, k)
			}
		}
		sort.Strings(rest)
		for _, k := range rest {
			add(k, migration.FieldUnmapped, "", "no equivalent")
		}
		sort.SliceStable(m.Fields, func(i, j int) bool { return m.Fields[i].Field < m.Fields[j].Field })
	}()

	orgs, _ := r[orgKey].([]orgSummary)
	for _, o := range orgs {
		if o.Status == "active" {
			add("organizations["+o.Name+"]", migration.FieldPartial, "",
				"organization is selected per order by the CertCentral connector (internal/connectors/digicert.go OrganizationID)")
		} else {
			add("organizations["+o.Name+"]", migration.FieldUnmapped, "", "inactive organization")
		}
	}

	id := str(r[pNameID])
	if id == "" {
		m.Unsupported = "missing name_id"
		return m, nil
	}
	t := &m.Template
	t.Name = obj.Name
	t.DisplayName = str(r[pName])
	add(pNameID, migration.FieldMapped, "name", "")
	if t.DisplayName == "" {
		t.DisplayName = id
		add("(display_name)", migration.FieldPartial, "display_name", "no product name; defaulted to name_id")
	} else {
		add(pName, migration.FieldMapped, "display_name", "")
	}
	t.AllowedAlgorithms = []string{"RSA", "ECDSA"}
	t.MinKeySize = 2048
	add("(allowed_algorithms)", migration.FieldPartial, "allowed_algorithms", "CertCentral accepts both")
	add("(min_key_size)", migration.FieldPartial, "min_key_size", "defaulted")
	if present(pSigHashes) {
		add(pSigHashes, migration.FieldUnmapped, "", "chosen by the CA")
	}

	typ := str(r[pType])
	switch typ {
	case "ssl_certificate":
		t.ExtendedKeyUsage, t.KeyUsage = []string{"serverAuth", "clientAuth"}, []string{"digitalSignature", "keyEncipherment"}
		t.EnrolleeType = "machine"
	case "client_certificate":
		t.ExtendedKeyUsage, t.KeyUsage = []string{"clientAuth", "emailProtection"}, []string{"digitalSignature", "keyEncipherment"}
		t.EnrolleeType = "user"
	case "code_signing_certificate":
		t.ExtendedKeyUsage, t.KeyUsage = []string{"codeSigning"}, []string{"digitalSignature"}
		t.EnrolleeType = "machine"
	default:
		add(pType, migration.FieldUnmapped, "", "unsupported product type")
		m.Unsupported = "unsupported product type " + typ
	}
	if m.Unsupported == "" {
		add(pType, migration.FieldMapped, "extended_key_usage", "")
	}

	longest := 0
	if years, ok := r[pYears].([]any); ok {
		for _, y := range years {
			if n, err := strconv.Atoi(str(y)); err == nil && n > longest {
				longest = n
			}
		}
	}
	if longest == 0 {
		if present(pYears) {
			add(pYears, migration.FieldUnmapped, "validity_period", "no usable validity years")
		}
		if m.Unsupported == "" {
			m.Unsupported = "no allowed_validity_years"
		}
		return m, nil
	}
	t.ValidityPeriod = "P" + strconv.Itoa(365*longest) + "D"
	add(pYears, migration.FieldPartial, "validity_period", "longest allowed; CertCentral also caps by order")
	return m, nil
}
