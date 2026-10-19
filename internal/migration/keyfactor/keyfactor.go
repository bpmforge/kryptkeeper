// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package keyfactor imports a Keyfactor Command template export
// (GET /KeyfactorAPI/Templates) as Kryptkeeper templates.
package keyfactor

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
const Source = "keyfactor"

// Keyfactor Command template field names, from the Command API documentation.
// They have NOT been checked against a live export: a human must confirm them
// against a real Templates response before this importer is advertised.
// Unknown fields are reported unmapped, so a wrong name lowers the visible
// percentage instead of dropping data.
const (
	fID                 = "Id"
	fCommonName         = "CommonName"
	fTemplateName       = "TemplateName"
	fOID                = "Oid"
	fKeySize            = "KeySize"
	fKeyType            = "KeyType"
	fCurve              = "Curve"
	fKeyUsage           = "KeyUsage"
	fEKUs               = "ExtendedKeyUsages"
	fAllowedEnrollTypes = "AllowedEnrollmentTypes"
	fUseAllowedReq      = "UseAllowedRequesters"
	fAllowedRequesters  = "AllowedRequesters"
)

// noEquivalent lists fields that are known and deliberately unmodelled.
var noEquivalent = map[string]string{
	"ForestRoot": "no equivalent", "ConfigurationTenant": "no equivalent", "EnrollmentFields": "no equivalent",
	"RFCEnforcement": "no equivalent", "KeyRetention": "no equivalent", "KeyRetentionDays": "no equivalent",
	"TemplateRegexes":  "no equivalent",
	fUseAllowedReq:     "no equivalent; requester ACLs are not modelled",
	fAllowedRequesters: "no equivalent; requester ACLs are not modelled",
}

// Importer implements migration.Importer.
type Importer struct{}

// New returns the Keyfactor importer.
func New() *Importer { return &Importer{} }

var _ migration.Importer = (*Importer)(nil)

// Source implements migration.Importer.
func (*Importer) Source() string { return Source }

// Parse accepts a JSON array of templates or {"templates":[...]}.
func (*Importer) Parse(_ context.Context, in migration.Input) ([]migration.SourceObject, error) {
	var list []map[string]any
	dec := json.NewDecoder(bytes.NewReader(in.Content))
	dec.UseNumber()
	if strings.HasPrefix(strings.TrimSpace(string(in.Content)), "[") {
		if err := dec.Decode(&list); err != nil {
			return nil, fmt.Errorf("decode template array: %w", err)
		}
	} else {
		var doc struct {
			Templates []map[string]any `json:"templates"`
		}
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode export: %w", err)
		}
		list = doc.Templates
	}
	out := make([]migration.SourceObject, 0, len(list))
	for _, r := range list {
		name := str(r[fTemplateName])
		if name == "" {
			name = str(r[fCommonName])
		}
		out = append(out, migration.SourceObject{Kind: "template", SourceKey: "keyfactor:" + str(r[fID]), Name: name, Raw: r})
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
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

func intOf(v any) (int, bool) {
	n, err := strconv.Atoi(str(v))
	return n, err == nil
}

var keyUsageBits = []struct {
	bit  int
	name string
}{
	{128, "digitalSignature"}, {64, "contentCommitment"}, {32, "keyEncipherment"}, {16, "dataEncipherment"}, {8, "keyAgreement"},
}

// Map converts one template. It is pure and deterministic.
func (*Importer) Map(obj migration.SourceObject) (m migration.Mapped, _ error) {
	r := obj.Raw
	add := func(field string, st migration.FieldStatus, target, note string) {
		m.Fields = append(m.Fields, migration.FieldReport{Field: field, Status: st, Target: target, Note: note})
	}
	present := func(k string) bool { _, ok := r[k]; return ok }
	defer func() {
		known := map[string]bool{fID: true, fCommonName: true, fTemplateName: true, fOID: true, fKeySize: true, fKeyType: true,
			fCurve: true, fKeyUsage: true, fEKUs: true, fAllowedEnrollTypes: true}
		var rest []string
		for k := range r {
			if !known[k] {
				rest = append(rest, k)
			}
		}
		sort.Strings(rest)
		for _, k := range rest {
			note, ok := noEquivalent[k]
			if !ok {
				note = "no equivalent"
			}
			add(k, migration.FieldUnmapped, "", note)
		}
		sort.SliceStable(m.Fields, func(i, j int) bool { return m.Fields[i].Field < m.Fields[j].Field })
	}()

	t := &m.Template
	t.Name = obj.Name
	t.DisplayName = str(r[fCommonName])
	if t.DisplayName == "" {
		t.DisplayName = t.Name
	}
	t.OID = str(r[fOID])
	t.ValidityPeriod = "P365D"
	t.EnrolleeType = "machine"
	add("(synthesized) validityPeriod", migration.FieldPartial, "validity_period", "taken from the CA template in Keyfactor; defaulted")
	if present(fID) {
		add(fID, migration.FieldMapped, "source_key", "")
	}
	if present(fTemplateName) {
		add(fTemplateName, migration.FieldMapped, "name", "")
	}
	if present(fCommonName) {
		add(fCommonName, migration.FieldMapped, "display_name", "")
	}
	if present(fOID) {
		add(fOID, migration.FieldMapped, "oid", "")
	}
	if present(fAllowedEnrollTypes) {
		add(fAllowedEnrollTypes, migration.FieldPartial, "", "enrollment methods are not modelled per template")
	}
	if t.Name == "" {
		m.Unsupported = "missing TemplateName and CommonName"
		return m, nil
	}

	if n, ok := intOf(r[fKeySize]); ok && n > 0 {
		t.MinKeySize = n
		add(fKeySize, migration.FieldMapped, "min_key_size", "")
	} else {
		t.MinKeySize = 2048
		if present(fKeySize) {
			add(fKeySize, migration.FieldPartial, "min_key_size", "non-numeric; defaulted to 2048")
		} else {
			add("(key_size)", migration.FieldPartial, "min_key_size", "absent; defaulted to 2048")
		}
	}
	switch strings.ToUpper(str(r[fKeyType])) {
	case "RSA":
		t.AllowedAlgorithms = []string{"RSA"}
		add(fKeyType, migration.FieldMapped, "allowed_algorithms", "")
	case "ECC":
		t.AllowedAlgorithms = []string{"ECDSA"}
		add(fKeyType, migration.FieldMapped, "allowed_algorithms", "")
	default:
		if present(fKeyType) {
			add(fKeyType, migration.FieldUnmapped, "", "unsupported key type")
		}
		m.Unsupported = "unsupported key type " + strconv.Quote(str(r[fKeyType]))
	}
	if present(fCurve) {
		add(fCurve, migration.FieldPartial, "", "chosen by the CA")
	}

	ku, kuOK := intOf(r[fKeyUsage])
	if kuOK {
		for _, b := range keyUsageBits {
			if ku&b.bit != 0 {
				t.KeyUsage = append(t.KeyUsage, b.name)
			}
		}
		if ku&4 != 0 {
			add(fKeyUsage+"[keyCertSign]", migration.FieldUnmapped, "", "CA usage")
		}
		if ku&2 != 0 {
			add(fKeyUsage+"[cRLSign]", migration.FieldUnmapped, "", "CA usage")
		}
	}
	if present(fKeyUsage) {
		add(fKeyUsage, migration.FieldMapped, "key_usage", "")
	}
	if len(t.KeyUsage) == 0 && m.Unsupported == "" {
		m.Unsupported = "no mappable key usage"
	}

	if list, ok := r[fEKUs].([]any); ok {
		for _, e := range list {
			em, _ := e.(map[string]any)
			oid := str(em["Oid"])
			if name, ok := migration.EKUFromOID(oid); ok {
				t.ExtendedKeyUsage = append(t.ExtendedKeyUsage, name)
			} else {
				add(fEKUs+"["+oid+"]", migration.FieldUnmapped, "", "custom OID")
			}
		}
	}
	if present(fEKUs) {
		add(fEKUs, migration.FieldMapped, "extended_key_usage", "")
	}
	t.ExtendedKeyUsage = uniqSorted(t.ExtendedKeyUsage)
	if len(t.ExtendedKeyUsage) == 0 && m.Unsupported == "" {
		m.Unsupported = "no mappable extended key usage"
	}
	return m, nil
}

func uniqSorted(in []string) []string {
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
