// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package certmanagerissuer implements a cert-manager external issuer that
// delegates certificate signing to the Kryptkeeper Hub API.
//
// The controller watches CertificateRequest resources where
// issuerRef.group == "certmanager.kryptkeeper.io" and patches their status
// with the issued certificate returned by Kryptkeeper.
//
// No controller-runtime or cert-manager SDK dependency — all k8s interaction
// is done via raw HTTP calls to the API server, keeping the binary small.
package certmanagerissuer

import "time"

const (
	// IssuerGroup is the cert-manager issuerRef group for Kryptkeeper.
	IssuerGroup = "certmanager.kryptkeeper.io"

	// CertManagerGroup is the cert-manager API group.
	CertManagerGroup = "cert-manager.io"
)

// CertificateRequest is a minimal representation of a cert-manager CertificateRequest resource.
type CertificateRequest struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       CRSpec   `json:"spec"`
	Status     CRStatus `json:"status,omitempty"`
}

// Metadata holds k8s object metadata.
type Metadata struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

// CRSpec is the CertificateRequest spec.
type CRSpec struct {
	// Request is the base64-encoded DER CSR.
	Request   string    `json:"request"`
	IssuerRef IssuerRef `json:"issuerRef"`
	Duration  string    `json:"duration,omitempty"`
	IsCA      bool      `json:"isCA,omitempty"`
}

// IssuerRef identifies the issuer.
type IssuerRef struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Group string `json:"group"`
}

// CRStatus is the CertificateRequest status.
type CRStatus struct {
	// Certificate is the base64-encoded issued certificate PEM.
	Certificate []byte      `json:"certificate,omitempty"`
	CA          []byte      `json:"ca,omitempty"`
	Conditions  []Condition `json:"conditions,omitempty"`
}

// Condition is a cert-manager status condition.
type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
}

// CertificateRequestList is the list type for CertificateRequests.
type CertificateRequestList struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Metadata   ListMeta             `json:"metadata"`
	Items      []CertificateRequest `json:"items"`
}

// ListMeta holds list metadata including the resource version for watches.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion"`
	Continue        string `json:"continue,omitempty"`
}

// IssuerConfig is the Kryptkeeper-side configuration for an issuer instance.
// In simple mode these come from environment variables; in CRD mode they are
// read from a KryptKeeperIssuer custom resource.
type IssuerConfig struct {
	HubURL     string
	APIToken   string
	CAID       string
	TemplateID string
}

// StatusPatch is the PATCH body for updating CertificateRequest status.
type StatusPatch struct {
	Status CRStatus `json:"status"`
}

// isReady returns true if the CertificateRequest already has a Ready=True condition.
func (cr *CertificateRequest) isReady() bool {
	for _, c := range cr.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			return true
		}
	}
	return false
}

// isDenied returns true if the CertificateRequest has been denied.
func (cr *CertificateRequest) isDenied() bool {
	for _, c := range cr.Status.Conditions {
		if c.Type == "Denied" && c.Status == "True" {
			return true
		}
	}
	return false
}

// needsIssuance returns true if this request is targeted at our issuer
// and has not yet been processed.
func (cr *CertificateRequest) needsIssuance() bool {
	return cr.Spec.IssuerRef.Group == IssuerGroup &&
		!cr.isReady() &&
		!cr.isDenied() &&
		len(cr.Status.Certificate) == 0
}
