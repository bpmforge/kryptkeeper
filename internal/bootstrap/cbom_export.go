// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
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
	doc := cbomDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: newCBOMSerialNumber(),
		Version:      1,
		Metadata:     cbomMetadata{Timestamp: time.Now().UTC().Format(time.RFC3339)},
		Components:   []cbomComponent{},
	}
	algorithms := map[string]bool{}

	if certs != nil {
		list, err := listAllCertificates(ctx, certs, CertificateListQuery{})
		if err != nil {
			return cbomDocument{}, fmt.Errorf("cbom: certificate inventory: %w", err)
		}
		for _, c := range list.Items {
			name := c.CommonName
			if name == "" {
				name = c.FingerprintSHA256
			}
			doc.Components = append(doc.Components, cbomComponent{
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
					},
				},
			})
			if c.SignatureAlgorithm != "" {
				algorithms[c.SignatureAlgorithm] = true
			}
			if c.PublicKeyAlgorithm != "" {
				algorithms[c.PublicKeyAlgorithm] = true
			}
		}
	}

	if keys != nil {
		metas, err := keys.List()
		if err != nil {
			return cbomDocument{}, fmt.Errorf("cbom: key inventory: %w", err)
		}
		for _, m := range metas {
			size := 0
			switch m.Algorithm {
			case keystore.RSA2048:
				size = 2048
			case keystore.RSA4096:
				size = 4096
			}
			// Metadata only — never key material.
			doc.Components = append(doc.Components, cbomComponent{
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
		eps, err := discovery.ListEndpoints(ctx, DiscoveryEndpointQuery{})
		if err != nil {
			return cbomDocument{}, fmt.Errorf("cbom: discovery inventory: %w", err)
		}
		for _, ep := range eps.Endpoints {
			doc.Components = append(doc.Components, cbomComponent{
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
		doc.Components = append(doc.Components, algorithmAsset(name))
	}
	return doc, nil
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
		doc, err := BuildCBOM(r.Context(), certs, keys, discovery)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "cbom.export", "cbom", "-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "cbom export failed")
			return
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, "cbom.export", "cbom", doc.SerialNumber, AuditOutcomeSuccess,
			fmt.Sprintf(`{"components":%d}`, len(doc.Components)))
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(doc)
	})
}
