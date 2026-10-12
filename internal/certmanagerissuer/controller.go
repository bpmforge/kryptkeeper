// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certmanagerissuer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Controller polls the k8s API for pending CertificateRequests and issues
// certificates via the Kryptkeeper Hub.
type Controller struct {
	K8sClient    *K8sClient
	Issuer       IssuerConfig
	Namespaces   []string // empty = all namespaces
	PollInterval time.Duration
}

// NewController returns a Controller with sensible defaults.
func NewController(k8s *K8sClient, issuer IssuerConfig, namespaces []string) *Controller {
	return &Controller{
		K8sClient:    k8s,
		Issuer:       issuer,
		Namespaces:   namespaces,
		PollInterval: 15 * time.Second,
	}
}

// Run starts the reconciliation loop. Blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	log.Printf("certmanager-issuer: starting; hub=%s ca=%s template=%s",
		c.Issuer.HubURL, c.Issuer.CAID, c.Issuer.TemplateID)
	for {
		if err := c.reconcileAll(ctx); err != nil {
			log.Printf("certmanager-issuer: reconcile error: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.PollInterval):
		}
	}
}

// reconcileAll lists all pending CertificateRequests in the configured
// namespaces and issues certificates for those targeting our issuer.
func (c *Controller) reconcileAll(ctx context.Context) error {
	namespaces := c.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{""}
	}

	for _, ns := range namespaces {
		list, err := c.K8sClient.ListCertificateRequests(ctx, ns)
		if err != nil {
			log.Printf("certmanager-issuer: list CertificateRequests (ns=%q): %v", ns, err)
			continue
		}
		for i := range list.Items {
			cr := &list.Items[i]
			if !cr.needsIssuance() {
				continue
			}
			if err := c.reconcile(ctx, cr); err != nil {
				log.Printf("certmanager-issuer: reconcile %s/%s: %v",
					cr.Metadata.Namespace, cr.Metadata.Name, err)
			}
		}
	}
	return nil
}

// reconcile processes a single CertificateRequest.
func (c *Controller) reconcile(ctx context.Context, cr *CertificateRequest) error {
	log.Printf("certmanager-issuer: issuing for %s/%s (issuer %s/%s)",
		cr.Metadata.Namespace, cr.Metadata.Name,
		cr.Spec.IssuerRef.Kind, cr.Spec.IssuerRef.Name)

	// Decode the DER CSR from base64 and re-encode as PEM.
	csrDER, err := base64.StdEncoding.DecodeString(cr.Spec.Request)
	if err != nil {
		return c.failCR(ctx, cr, "InvalidCSR", fmt.Sprintf("base64 decode CSR: %v", err))
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Issue via Kryptkeeper.
	certPEM, err := issueCertificate(ctx, c.Issuer, string(csrPEM))
	if err != nil {
		return c.failCR(ctx, cr, "IssuanceFailed", err.Error())
	}

	// Patch CertificateRequest status with the issued certificate.
	return c.K8sClient.PatchCRStatus(ctx, cr, certPEM, nil)
}

// failCR patches the CertificateRequest with a Failed condition.
func (c *Controller) failCR(ctx context.Context, cr *CertificateRequest, reason, message string) error {
	log.Printf("certmanager-issuer: failing %s/%s: %s: %s",
		cr.Metadata.Namespace, cr.Metadata.Name, reason, message)
	return c.K8sClient.PatchCRStatus(ctx, cr, nil, &Condition{
		Type:               "Ready",
		Status:             "False",
		LastTransitionTime: time.Now().UTC(),
		Reason:             reason,
		Message:            message,
	})
}

// issueCertificate calls the Kryptkeeper Hub to issue a certificate for the CSR.
func issueCertificate(ctx context.Context, cfg IssuerConfig, csrPEM string) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"ca_id":       cfg.CAID,
		"template_id": cfg.TemplateID,
		"csr_pem":     csrPEM,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(cfg.HubURL, "/")+"/api/v1/certificates",
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kryptkeeper issue request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read kryptkeeper response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kryptkeeper returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result struct {
		Data struct {
			CertificatePEM string `json:"certificate_pem"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode kryptkeeper response: %w", err)
	}
	if result.Data.CertificatePEM == "" {
		return nil, fmt.Errorf("kryptkeeper returned empty certificate_pem")
	}
	return []byte(result.Data.CertificatePEM), nil
}
