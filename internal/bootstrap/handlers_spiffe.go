// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

// spiffeEngine is the CA engine used to mint SVIDs and build the trust bundle.
// Set from main via SetSPIFFEEngine; nil means SPIFFE is disabled (no CA engine,
// e.g. file-provider mode). Mirrors the renewal-status holder pattern.
var spiffeEngine ca.Service

// SetSPIFFEEngine wires the CA engine for SPIFFE SVID issuance.
func SetSPIFFEEngine(e ca.Service) { spiffeEngine = e }

// spiffeTrustDomain returns the configured SPIFFE trust domain (empty = disabled).
func spiffeTrustDomain() string {
	return strings.TrimSpace(os.Getenv("SPIFFE_TRUST_DOMAIN"))
}

// spiffeSVIDTTL returns the SVID validity (SPIFFE_SVID_TTL, default 1h).
func spiffeSVIDTTL() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("SPIFFE_SVID_TTL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// validateSPIFFEID checks an ID is spiffe://<trust-domain>/<path>.
func validateSPIFFEID(id, trustDomain string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(id))
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}
	if u.Scheme != "spiffe" {
		return nil, fmt.Errorf("SPIFFE ID must use the spiffe:// scheme")
	}
	if u.Host != trustDomain {
		return nil, fmt.Errorf("SPIFFE ID trust domain %q does not match configured %q", u.Host, trustDomain)
	}
	if u.Path == "" || u.Path == "/" {
		return nil, fmt.Errorf("SPIFFE ID must include a workload path")
	}
	if strings.Contains(u.Path, "..") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("SPIFFE ID must not contain query, fragment, or '..'")
	}
	return u, nil
}

// caChainPEM encodes a CA chain (leaf-CA → root) as concatenated PEM.
func caChainPEM(chain []*ca.CA) []byte {
	var b strings.Builder
	for _, c := range chain {
		if c == nil || c.Certificate == nil {
			continue
		}
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw}))
	}
	return []byte(b.String())
}

// registerSPIFFEHandlers mounts the SVID mint and trust-bundle endpoints.
// SPIFFE is enabled only when a CA engine is wired and SPIFFE_TRUST_DOMAIN is set.
func registerSPIFFEHandlers(mux *http.ServeMux, auth *Authenticator, caProvider CAProvider, auditProvider AuditProvider) {
	// GET /api/v1/spiffe/status — report SPIFFE configuration for the dashboard.
	mux.HandleFunc("/api/v1/spiffe/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if _, err := auth.AuthenticatePrincipalDetails(r, time.Now()); err != nil {
			writeUnauthorized(w)
			return
		}
		td := spiffeTrustDomain()
		signingCA := strings.TrimSpace(os.Getenv("SPIFFE_SIGNING_CA_ID"))
		enabled := td != "" && signingCA != "" && spiffeEngine != nil
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Data struct {
				Enabled        bool   `json:"enabled"`
				TrustDomain    string `json:"trust_domain"`
				SigningCAID    string `json:"signing_ca_id"`
				SVIDTTLSeconds int    `json:"svid_ttl_seconds"`
			} `json:"data"`
		}{Data: struct {
			Enabled        bool   `json:"enabled"`
			TrustDomain    string `json:"trust_domain"`
			SigningCAID    string `json:"signing_ca_id"`
			SVIDTTLSeconds int    `json:"svid_ttl_seconds"`
		}{
			Enabled:        enabled,
			TrustDomain:    td,
			SigningCAID:    signingCA,
			SVIDTTLSeconds: int(spiffeSVIDTTL().Seconds()),
		}})
	})

	// POST /api/v1/spiffe/svid — mint a short-lived SVID for a SPIFFE ID.
	mux.HandleFunc("/api/v1/spiffe/svid", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if !canApproveActions(pd.Role) {
			writeForbidden(w, "your role is not authorized to mint SVIDs")
			return
		}
		// D-203: one global signing CA and trust domain, no tenant mapping.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "spiffe.svid_issue", "spiffe", "-") {
			return
		}
		td := spiffeTrustDomain()
		if td == "" || spiffeEngine == nil {
			writeServiceUnavailable(w, "SPIFFE not configured (set SPIFFE_TRUST_DOMAIN and run with a CA engine)")
			return
		}
		signingCA := strings.TrimSpace(os.Getenv("SPIFFE_SIGNING_CA_ID"))
		if signingCA == "" {
			writeServiceUnavailable(w, "SPIFFE_SIGNING_CA_ID not set")
			return
		}

		var req struct {
			SPIFFEID string `json:"spiffe_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequest(w, "invalid JSON")
			return
		}
		spiffeURI, err := validateSPIFFEID(req.SPIFFEID, td)
		if err != nil {
			writeBadRequest(w, err.Error())
			return
		}

		// Generate the workload keypair and a CSR carrying the SPIFFE ID.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			writeServiceUnavailable(w, "key generation failed")
			return
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{}, URIs: []*url.URL{spiffeURI},
		}, key)
		if err != nil {
			writeServiceUnavailable(w, "csr generation failed")
			return
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			writeServiceUnavailable(w, "csr parse failed")
			return
		}

		issued, err := spiffeEngine.IssueCertificate(signingCA, ca.IssuanceRequest{
			CSR:         csr,
			Validity:    spiffeSVIDTTL(),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			URIs:        []*url.URL{spiffeURI},
		})
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "spiffe.svid_issue", "spiffe", spiffeURI.String(), AuditOutcomeFailure)
			logging.Warnf("spiffe svid issuance failed for %s: %v", spiffeURI, err)
			writeServiceUnavailable(w, "svid issuance failed")
			return
		}

		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			writeServiceUnavailable(w, "key encode failed")
			return
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

		var bundlePEM []byte
		if chain, cerr := spiffeEngine.GetCAChain(signingCA); cerr == nil {
			bundlePEM = caChainPEM(chain)
		}

		emitAuditEvent(r, auditProvider, pd.ID, "spiffe.svid_issue", "spiffe", spiffeURI.String(), AuditOutcomeSuccess)
		setNoStore(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(struct {
			Data struct {
				SPIFFEID  string `json:"spiffe_id"`
				SVIDPEM   string `json:"svid_pem"`
				KeyPEM    string `json:"key_pem"`
				BundlePEM string `json:"bundle_pem"`
				ExpiresAt string `json:"expires_at"`
			} `json:"data"`
		}{Data: struct {
			SPIFFEID  string `json:"spiffe_id"`
			SVIDPEM   string `json:"svid_pem"`
			KeyPEM    string `json:"key_pem"`
			BundlePEM string `json:"bundle_pem"`
			ExpiresAt string `json:"expires_at"`
		}{
			SPIFFEID:  spiffeURI.String(),
			SVIDPEM:   string(issued.CertPEM),
			KeyPEM:    string(keyPEM),
			BundlePEM: string(bundlePEM),
			ExpiresAt: time.Now().UTC().Add(spiffeSVIDTTL()).Format(time.RFC3339),
		}})
	})

	// GET /api/v1/spiffe/bundle — the trust domain's CA bundle (PEM).
	mux.HandleFunc("/api/v1/spiffe/bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if spiffeTrustDomain() == "" || spiffeEngine == nil {
			writeServiceUnavailable(w, "SPIFFE not configured")
			return
		}
		signingCA := strings.TrimSpace(os.Getenv("SPIFFE_SIGNING_CA_ID"))
		if signingCA == "" {
			writeServiceUnavailable(w, "SPIFFE_SIGNING_CA_ID not set")
			return
		}
		chain, err := spiffeEngine.GetCAChain(signingCA)
		if err != nil || len(chain) == 0 {
			writeServiceUnavailable(w, "trust bundle unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "spiffe.bundle_get", "spiffe", signingCA, AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caChainPEM(chain))
	})
}
