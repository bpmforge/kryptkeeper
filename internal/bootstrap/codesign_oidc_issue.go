// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/logging"
)

// W29-12 (D-152): short-lived code-signing certificates for CI jobs. The
// hub never sees or mints the subject key: CI sends a CSR, the verified OIDC
// token decides who the certificate is bound to, and the CSR only proves
// possession of the key.

const (
	// codesignBackdate keeps a runner whose clock trails the hub's from seeing
	// a not-yet-valid certificate. Validity + backdate must stay <= 15 min.
	codesignBackdate = 1 * time.Minute
	codesignTTLMin   = 30 * time.Second
	codesignTTLMax   = 14 * time.Minute
	codesignTTLEnv   = "KRYPTKEEPER_CODESIGN_TTL"
	codesignOrg      = "Kryptkeeper CI"
	// certificates.source is CHECK-constrained to a closed vocabulary; "api" is the
	// value an issuance through the hub API carries. The codesign origin is
	// recoverable from the codesign.issue audit row and the URI SAN.
	codesignSource = "api"
	codesignCNMax  = 64
	// Fulcio-style identity: github tokens are bound under this host.
	codesignGitHubBase = "https://github.com"
)

var (
	errCodesignBadCSR   = errors.New("invalid csr")
	errCodesignWeakKey  = errors.New("unsupported key")
	errCodesignRecord   = errors.New("issued certificate could not be recorded")
	errCodesignNoEngine = errors.New("code-signing issuance unavailable")
)

// codesignTTL reads KRYPTKEEPER_CODESIGN_TTL, clamped to [30s, 14m]. The floor
// lets the live test wait out expiry quickly; the ceiling keeps validity plus
// backdate under 15 minutes.
func codesignTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv(codesignTTLEnv))
	if raw == "" {
		return codesignTTLMax
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		logging.Infof("warning: %s=%q is not a duration; using %s", codesignTTLEnv, raw, codesignTTLMax)
		return codesignTTLMax
	}
	switch {
	case d < codesignTTLMin:
		logging.Infof("warning: %s=%s is below the %s floor; using the floor", codesignTTLEnv, d, codesignTTLMin)
		return codesignTTLMin
	case d > codesignTTLMax:
		logging.Infof("warning: %s=%s is above the %s ceiling; using the ceiling", codesignTTLEnv, d, codesignTTLMax)
		return codesignTTLMax
	}
	return d
}

// CodesignIssuer turns a verified CI token plus a CSR into a bound,
// short-lived, inventory-recorded code-signing certificate.
type CodesignIssuer struct {
	verifier *CodesignOIDCVerifier
	engine   ca.Service
	rec      ca.IssuedCertificateRecorder
	ttl      time.Duration
}

func NewCodesignIssuer(verifier *CodesignOIDCVerifier, engine ca.Service, rec ca.IssuedCertificateRecorder) *CodesignIssuer {
	return &CodesignIssuer{verifier: verifier, engine: engine, rec: rec, ttl: codesignTTL()}
}

// parseCodesignCSR parses and key-checks a CSR. ECDSA P-256/P-384/P-521 or
// RSA >= 3072 only (the inventory policy-check families); anything else,
// Ed25519 and ML-DSA included, is refused before the token is consumed.
func parseCodesignCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", errCodesignBadCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCodesignBadCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature does not verify", errCodesignBadCSR)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if n := k.Curve.Params().BitSize; n != 256 && n != 384 && n != 521 {
			return nil, fmt.Errorf("%w: ECDSA curve P-%d", errCodesignWeakKey, n)
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 3072 {
			return nil, fmt.Errorf("%w: RSA-%d (need >= 3072)", errCodesignWeakKey, k.N.BitLen())
		}
	default:
		return nil, fmt.Errorf("%w: %T (ECDSA P-256/384/521 or RSA >= 3072)", errCodesignWeakKey, csr.PublicKey)
	}
	return csr, nil
}

// codesignIdentityURI is the Fulcio-style subject URI "<base>/<repo>@<ref>"
// that verifiers match with cosign --certificate-identity.
func codesignIdentityURI(rule CodesignTrustRule, repo, ref string) (*url.URL, error) {
	if repo == "" || ref == "" || strings.ContainsAny(repo+ref, " \t\r\n%?#\\") {
		return nil, &CodesignRefusal{Issuer: rule.Issuer, Reason: ReasonMalformed, Detail: "repo or ref claim unusable"}
	}
	base := codesignGitHubBase
	if rule.Provider != "github" {
		base = rule.Issuer
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" {
		return nil, &CodesignRefusal{Issuer: rule.Issuer, Reason: ReasonMalformed, Detail: "identity base unusable"}
	}
	u.Path += "/" + repo + "@" + ref
	return u, nil
}

// Issue verifies rawToken, then signs csrPEM. The CSR is checked first so a
// malformed request cannot burn a single-use token. Token problems come back
// as *CodesignRefusal; the issuer chain is returned as PEM (leaf CA first).
func (c *CodesignIssuer) Issue(ctx context.Context, rawToken, csrPEM string) (*ca.IssuedCertificate, CodesignIdentity, []byte, error) {
	if c == nil || c.verifier == nil || c.engine == nil {
		return nil, CodesignIdentity{}, nil, errCodesignNoEngine
	}
	csr, err := parseCodesignCSR(csrPEM)
	if err != nil {
		return nil, CodesignIdentity{}, nil, err
	}
	id, err := c.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, CodesignIdentity{}, nil, err
	}
	uri, err := codesignIdentityURI(id.Rule, id.Repo, id.Ref)
	if err != nil {
		return nil, id, nil, err
	}
	subject := pkix.Name{Organization: []string{codesignOrg}, CommonName: codesignTruncate(id.Repo, codesignCNMax)}
	issued, err := c.engine.IssueCertificate(id.Rule.CAID, ca.IssuanceRequest{
		CSR:             csr,
		Subject:         &subject,
		URIs:            []*url.URL{uri},
		CallerNamesOnly: true,
		Validity:        c.ttl,
		Backdate:        codesignBackdate,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return nil, id, nil, err
	}
	// Recording is fatal here, unlike EST: an unrecorded certificate cannot be
	// revoked from the hub or seen by policy-check, so it must not be handed out.
	if c.rec == nil {
		logging.Infof("ERROR codesign: no inventory recorder; withholding serial=%s", issued.SerialNumber.Text(16))
		return nil, id, nil, errCodesignRecord
	}
	if rerr := c.rec.RecordIssuedCertificate(ctx, id.Rule.CAID, issued.Certificate, issued.CertPEM, codesignSource); rerr != nil {
		logging.Infof("ERROR codesign: certificate serial=%s signed but not recorded (withheld): %v", issued.SerialNumber.Text(16), rerr)
		return nil, id, nil, errCodesignRecord
	}
	return issued, id, c.chainPEM(id.Rule.CAID), nil
}

// chainPEM is the issuing CA chain, leaf CA to root, excluding the leaf cert.
func (c *CodesignIssuer) chainPEM(caID string) []byte {
	chain, err := c.engine.GetCAChain(caID)
	if err != nil {
		logging.Infof("codesign: CA chain for %s unavailable: %v", caID, err)
		return nil
	}
	var out []byte
	for _, k := range chain {
		if k != nil && len(k.CertPEM) > 0 {
			out = append(out, k.CertPEM...)
		}
	}
	return out
}
