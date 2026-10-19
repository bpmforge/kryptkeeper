// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/logging"
)

// W6-05 (D-052/FR-P14): the cryptographic bill of materials. The export
// is CycloneDX 1.6 — field names grounded in the official
// CycloneDX/specification bom-1.6.schema.json, hand-built (no new
// dependency). Built from the LIVE providers on every call: always
// current, never cached.

// --- CycloneDX 1.6 subset (cryptographic assets) ---

type cbomDocument struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cbomMetadata    `json:"metadata"`
	Components   []cbomComponent `json:"components"`
}

type cbomMetadata struct {
	Timestamp string `json:"timestamp"`
}

type cbomComponent struct {
	Type             string                `json:"type"` // always "cryptographic-asset"
	BOMRef           string                `json:"bom-ref"`
	Name             string                `json:"name"`
	CryptoProperties *cbomCryptoProperties `json:"cryptoProperties"`
	Properties       []cbomProperty        `json:"properties,omitempty"`
}

// cbomProperty is a CycloneDX name/value property (Kryptkeeper-namespaced).
type cbomProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cbomCryptoProperties struct {
	AssetType             string                     `json:"assetType"`
	CertificateProperties *cbomCertificateProperties `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterial *cbomRelatedCryptoMaterial `json:"relatedCryptoMaterialProperties,omitempty"`
	AlgorithmProperties   *cbomAlgorithmProperties   `json:"algorithmProperties,omitempty"`
	ProtocolProperties    *cbomProtocolProperties    `json:"protocolProperties,omitempty"`
}

type cbomCertificateProperties struct {
	SubjectName       string `json:"subjectName,omitempty"`
	IssuerName        string `json:"issuerName,omitempty"`
	NotValidBefore    string `json:"notValidBefore,omitempty"`
	NotValidAfter     string `json:"notValidAfter,omitempty"`
	CertificateFormat string `json:"certificateFormat,omitempty"`
	// SignatureAlgorithmRef points at the algorithm component's bom-ref.
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
}

type cbomRelatedCryptoMaterial struct {
	Type         string `json:"type"` // "private-key"
	ID           string `json:"id,omitempty"`
	Size         int    `json:"size,omitempty"`
	CreationDate string `json:"creationDate,omitempty"`
}

type cbomAlgorithmProperties struct {
	Primitive                string `json:"primitive,omitempty"`
	Curve                    string `json:"curve,omitempty"`
	ParameterSetIdentifier   string `json:"parameterSetIdentifier,omitempty"`
	NISTQuantumSecurityLevel int    `json:"nistQuantumSecurityLevel,omitempty"`
}

type cbomProtocolProperties struct {
	Type    string `json:"type"` // tls | ssh | ...
	Version string `json:"version,omitempty"`
}

func newCBOMSerialNumber() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "urn:uuid:00000000-0000-4000-8000-000000000000"
	}
	// RFC 4122 v4 shape.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// algorithmAsset maps an observed algorithm name to its CBOM algorithm
// component. ML-DSA parameter sets carry their FIPS 204 NIST quantum
// security levels (44→2, 65→3, 87→5).
func algorithmAsset(name string) cbomComponent {
	props := &cbomAlgorithmProperties{Primitive: "signature"}
	switch {
	case strings.HasPrefix(name, "ML-DSA"):
		props.ParameterSetIdentifier = name
		switch name {
		case "ML-DSA-44":
			props.NISTQuantumSecurityLevel = 2
		case "ML-DSA-65":
			props.NISTQuantumSecurityLevel = 3
		case "ML-DSA-87":
			props.NISTQuantumSecurityLevel = 5
		}
	case strings.HasPrefix(name, "ECDSA-P256") || name == "ECDSA":
		props.Curve = "P-256"
	case strings.HasPrefix(name, "ECDSA-P384"):
		props.Curve = "P-384"
	}
	return cbomComponent{
		Type:   "cryptographic-asset",
		BOMRef: "algorithm:" + name,
		Name:   name,
		CryptoProperties: &cbomCryptoProperties{
			AssetType:           "algorithm",
			AlgorithmProperties: props,
		},
	}
}

// cbomProtocolType maps a discovery protocol string onto the CBOM
// protocolProperties.type enum (tls, ssh, ipsec, ike, sstp, wpa, other,
// unknown). STARTTLS-style protocols are TLS-carrying.
func cbomProtocolType(protocol string) string {
	switch protocol {
	case "tls", "ldaps", "imaps", "smtps", "pop3s", "https":
		return "tls"
	case "ssh":
		return "ssh"
	case "":
		return "unknown"
	default:
		return "other"
	}
}

// BuildCBOM assembles the CBOM from the live inventory. Absent providers
// (nil) contribute nothing; a provider ERROR fails the export — a
// silently partial BOM would misrepresent the inventory.
func BuildCBOM(ctx context.Context, certs CertificateProvider, keys keystore.Store, discovery DiscoveryProvider) (cbomDocument, error) {
	return buildCBOMFor(ctx, AuthPrincipal{SuperAdmin: true}, certs, keys, discovery)
}

// buildCBOMFor is BuildCBOM scoped to a principal.
//
// pd scopes the inventory: a tenant-scoped principal gets only the certificates
// of its own tenant's CAs. Keys and discovered endpoints carry no tenant yet, so
// they are withheld from scoped callers (deny by default) instead of leaking
// other tenants' assets.
func buildCBOMFor(ctx context.Context, pd AuthPrincipal, certs CertificateProvider, keys keystore.Store, discovery DiscoveryProvider) (cbomDocument, error) {
	doc := cbomDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: newCBOMSerialNumber(),
		Version:      1,
		Metadata:     cbomMetadata{Timestamp: time.Now().UTC().Format(time.RFC3339)},
		Components:   []cbomComponent{},
	}
	algorithms := map[string]bool{}
	// The schema cannot enforce bom-ref uniqueness; a repeated row (e.g. the
	// same fingerprint listed twice) is skipped rather than emitted twice.
	seenRefs := map[string]bool{}
	add := func(c cbomComponent) bool {
		if seenRefs[c.BOMRef] {
			return false
		}
		seenRefs[c.BOMRef] = true
		doc.Components = append(doc.Components, c)
		return true
	}

	if certs != nil {
		list, err := listAllCertificates(ctx, certs, CertificateListQuery{})
		if err != nil {
			return cbomDocument{}, fmt.Errorf("cbom: certificate inventory: %w", err)
		}
		for _, c := range filterCertificatesByTenant(ctx, activeTenantStore, pd, list.Items) {
			name := c.CommonName
			if name == "" {
				name = c.FingerprintSHA256
			}
			sigRef := ""
			if c.SignatureAlgorithm != "" {
				sigRef = "algorithm:" + c.SignatureAlgorithm
			}
			if !add(cbomComponent{
				Type:   "cryptographic-asset",
				BOMRef: "certificate:" + c.FingerprintSHA256,
				Name:   name,
				CryptoProperties: &cbomCryptoProperties{
					AssetType: "certificate",
					CertificateProperties: &cbomCertificateProperties{
						SubjectName:       c.SubjectDN,
						IssuerName:        c.IssuerDN,
						NotValidBefore:    c.ValidFrom,
						NotValidAfter:     c.ValidUntil,
						CertificateFormat: "X.509",

						SignatureAlgorithmRef: sigRef,
					},
				},
				Properties: []cbomProperty{
					{Name: "kryptkeeper:public-key-algorithm", Value: orUnknown(c.PublicKeyAlgorithm)},
					{Name: "kryptkeeper:signature-algorithm", Value: orUnknown(c.SignatureAlgorithm)},
					{Name: "kryptkeeper:key-size-bits", Value: strconv.Itoa(c.KeySizeBits)},
					{Name: "kryptkeeper:pqc-readiness", Value: orUnknown(c.PQCReadiness)},
				},
			}) {
				continue
			}
			if c.SignatureAlgorithm != "" {
				algorithms[c.SignatureAlgorithm] = true
			}
			if c.PublicKeyAlgorithm != "" {
				algorithms[c.PublicKeyAlgorithm] = true
			}
		}
	}

	if keys != nil && tenantBypass(pd) {
		metas, err := keys.List()
		if err != nil {
			return cbomDocument{}, fmt.Errorf("cbom: key inventory: %w", err)
		}
		for _, m := range metas {
			size := 0
			switch m.Algorithm {
			case keystore.RSA2048:
				size = 2048
			case keystore.RSA3072:
				size = 3072
			case keystore.RSA4096:
				size = 4096
			}
			// Metadata only — never key material.
			add(cbomComponent{
				Type:   "cryptographic-asset",
				BOMRef: "key:" + m.ID,
				Name:   m.ID,
				CryptoProperties: &cbomCryptoProperties{
					AssetType: "related-crypto-material",
					RelatedCryptoMaterial: &cbomRelatedCryptoMaterial{
						Type:         "private-key",
						ID:           m.ID,
						Size:         size,
						CreationDate: m.CreatedAt,
					},
				},
			})
			algorithms[string(m.Algorithm)] = true
		}
	}

	if discovery != nil {
		eps, err := discovery.ListEndpoints(withDiscoveryScope(ctx, pd), DiscoveryEndpointQuery{})
		if err != nil {
			return cbomDocument{}, fmt.Errorf("cbom: discovery inventory: %w", err)
		}
		for _, ep := range eps.Endpoints {
			add(cbomComponent{
				Type:   "cryptographic-asset",
				BOMRef: fmt.Sprintf("protocol:%s:%d", ep.Hostname, ep.Port),
				Name:   fmt.Sprintf("%s:%d", ep.Hostname, ep.Port),
				CryptoProperties: &cbomCryptoProperties{
					AssetType: "protocol",
					ProtocolProperties: &cbomProtocolProperties{
						Type: cbomProtocolType(ep.Protocol),
					},
				},
			})
		}
	}

	for name := range algorithms {
		add(algorithmAsset(name))
	}
	return doc, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// writeCBOM encodes doc to w one component at a time (json.Marshal per element,
// comma-separated, 64 KiB buffer, flush every 500 components when w is an
// http.Flusher) so a 10k-cert export never builds one giant buffer. Output is
// semantically equal to json.Marshal(doc).
func writeCBOM(w io.Writer, doc cbomDocument) error {
	bw := bufio.NewWriterSize(w, 64*1024)
	flusher, _ := w.(http.Flusher)
	head := func(v any) ([]byte, error) { return json.Marshal(v) }
	writeField := func(prefix, key string, v any) error {
		b, err := head(v)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(bw, "%s%q:%s", prefix, key, b)
		return err
	}
	if _, err := bw.WriteString("{"); err != nil {
		return err
	}
	fields := []struct {
		key string
		val any
	}{
		{"bomFormat", doc.BOMFormat}, {"specVersion", doc.SpecVersion},
		{"serialNumber", doc.SerialNumber}, {"version", doc.Version}, {"metadata", doc.Metadata},
	}
	for i, f := range fields {
		prefix := ","
		if i == 0 {
			prefix = ""
		}
		if err := writeField(prefix, f.key, f.val); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString(`,"components":[`); err != nil {
		return err
	}
	for i := range doc.Components {
		b, err := json.Marshal(doc.Components[i])
		if err != nil {
			return err
		}
		if i > 0 {
			if err := bw.WriteByte(','); err != nil {
				return err
			}
		}
		if _, err := bw.Write(b); err != nil {
			return err
		}
		if (i+1)%500 == 0 {
			if err := bw.Flush(); err != nil {
				return err
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
	if _, err := bw.WriteString("]}\n"); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if flusher != nil {
		flusher.Flush()
	}
	return nil
}

// RegisterCBOMHandlers mounts GET /api/v1/cbom — the always-current
// CycloneDX export.
func RegisterCBOMHandlers(mux *http.ServeMux, auth *Authenticator, certs CertificateProvider, keys keystore.Store, discovery DiscoveryProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/cbom", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "cbom.export", "cbom", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		doc, err := buildCBOMFor(r.Context(), pd, certs, keys, discovery)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "cbom.export", "cbom", "-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "cbom export failed")
			return
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, "cbom.export", "cbom", doc.SerialNumber, AuditOutcomeSuccess,
			fmt.Sprintf(`{"components":%d}`, len(doc.Components)))
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		w.WriteHeader(http.StatusOK)
		if err := writeCBOM(w, doc); err != nil {
			// Header already sent: the audit row above stands; no second status.
			logging.Infof("cbom: write after header failed: %v", err)
		}
	})
}
