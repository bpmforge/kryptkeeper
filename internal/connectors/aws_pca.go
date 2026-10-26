// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	pcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/smithy-go"

	"kryptkeeper/internal/egress"
)

// W36-06: AWS Private CA as an upstream issuer. Request shapes follow
// https://docs.aws.amazon.com/privateca/latest/APIReference/API_IssueCertificate.html
// (issue), .../API_GetCertificate.html (fetch),
// .../API_RevokeCertificate.html (revoke) and
// .../API_DescribeCertificateAuthority.html (health), through aws-sdk-go-v2
// service/acmpca.

// AWSPCAConfig locates and authenticates one AWS Private CA.
type AWSPCAConfig struct {
	// CertificateAuthorityARN is the issuing private CA (required).
	CertificateAuthorityARN string
	Region                  string
	// SigningAlgorithm (e.g. SHA256WITHECDSA) is optional. When empty the
	// CA's own configured signing algorithm is read once with
	// DescribeCertificateAuthority: the API requires the family (RSA or
	// ECDSA) to match the CA key, and the CA already records one that does.
	SigningAlgorithm string
	// ValidityDays defaults to 90.
	ValidityDays int64
	// TemplateARN is an optional certificate template; AWS defaults to
	// EndEntityCertificate/V1.
	TemplateARN string
	// EndpointURL overrides the service endpoint (tests, VPC endpoints).
	EndpointURL string
	// Auth is "ambient" to use the AWS default credential chain (instance
	// role, workload identity, env); otherwise static keys are required.
	Auth            string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// Poll pacing while the CA finishes issuing; tests shrink these.
	PollAttempts int
	PollInterval time.Duration
}

// AWSPCAConnector is an IssuerConnector (and RevokingConnector) backed by
// AWS Private CA.
type AWSPCAConnector struct {
	id         string
	cfg        AWSPCAConfig
	httpClient *http.Client

	mu        sync.Mutex
	api       *acmpca.Client
	sigAlg    pcatypes.SigningAlgorithm
	lastError string
}

var _ RevokingConnector = (*AWSPCAConnector)(nil)

// NewAWSPCAConnector builds the connector. Credentials are resolved lazily on
// first use so a bad ambient chain surfaces as a visible Health/Issue error,
// not a constructor failure. client may be nil.
func NewAWSPCAConnector(id string, cfg AWSPCAConfig, client *http.Client) *AWSPCAConnector {
	if cfg.ValidityDays <= 0 {
		cfg.ValidityDays = 90
	}
	if cfg.PollAttempts <= 0 {
		cfg.PollAttempts = 10
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	if client == nil {
		client = egress.NewClient(egress.Policy{RequireHTTPS: true, MaxRedirects: 0})
	}
	return &AWSPCAConnector{id: id, cfg: cfg, httpClient: client}
}

func (c *AWSPCAConnector) ID() string     { return c.id }
func (c *AWSPCAConnector) Type() string   { return "aws_pca" }
func (c *AWSPCAConnector) Origin() string { return "synced" }

func (c *AWSPCAConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

// client builds the SDK client once. Static keys never touch the shared
// config files; ambient defers to the default chain.
func (c *AWSPCAConnector) client(ctx context.Context) (*acmpca.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.api != nil {
		return c.api, nil
	}
	if strings.TrimSpace(c.cfg.CertificateAuthorityARN) == "" {
		return nil, fmt.Errorf("aws_pca %s: certificate_authority_arn is required", c.id)
	}
	opts := []func(*config.LoadOptions) error{}
	if c.cfg.Region != "" {
		opts = append(opts, config.WithRegion(c.cfg.Region))
	}
	if c.httpClient != nil {
		opts = append(opts, config.WithHTTPClient(c.httpClient))
	}
	switch {
	case c.cfg.AccessKeyID != "" || c.cfg.SecretAccessKey != "":
		if c.cfg.AccessKeyID == "" || c.cfg.SecretAccessKey == "" {
			return nil, fmt.Errorf("aws_pca %s: access_key_id and secret_access_key must be set together", c.id)
		}
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.cfg.AccessKeyID, c.cfg.SecretAccessKey, c.cfg.SessionToken)))
		// Static keys must not silently pick up a profile from the host.
		opts = append(opts, config.WithSharedConfigFiles(nil), config.WithSharedCredentialsFiles(nil))
	case c.cfg.Auth == "ambient":
	default:
		return nil, fmt.Errorf("aws_pca %s: credentials required (access key pair, or auth \"ambient\")", c.id)
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws_pca %s: load aws config: %w", c.id, err)
	}
	c.api = acmpca.NewFromConfig(awsCfg, func(o *acmpca.Options) {
		if c.cfg.EndpointURL != "" {
			o.BaseEndpoint = aws.String(c.cfg.EndpointURL)
		}
		// The hub's throttle owns backoff; SDK-internal retries would hide a
		// throttle from it and stack delays on top of its window.
		o.RetryMaxAttempts = 1
	})
	return c.api, nil
}

// pcaThrottleCodes lists the error codes AWS uses for "slow down".
var pcaThrottleCodes = map[string]bool{
	"ThrottlingException":      true,
	"TooManyRequestsException": true,
	"LimitExceededException":   true,
	"Throttling":               true,
	"RequestLimitExceeded":     true,
}

// mapErr turns throttling into a RateLimitError (the AWS API exposes no
// retry-after, so 0 and the throttle's own backoff floor applies) and wraps
// everything else with the operation name. SDK errors carry the API message,
// never request credentials.
func (c *AWSPCAConnector) mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var ae smithy.APIError
	if errors.As(err, &ae) && pcaThrottleCodes[ae.ErrorCode()] {
		return &RateLimitError{ConnectorID: c.id, Reason: "upstream_429",
			Err: fmt.Errorf("aws_pca %s: %s: rate limited (%s)", c.id, op, ae.ErrorCode())}
	}
	return fmt.Errorf("aws_pca %s: %s: %s", c.id, op, truncate([]byte(err.Error())))
}

// Health reads the CA and also carries the last issue-path error.
func (c *AWSPCAConnector) Health(ctx context.Context) Health {
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	h := c.probe(ctx)
	if last != "" {
		h.Status = "degraded"
		if h.Detail != "" {
			h.Detail += "; "
		}
		h.Detail += "last issue error: " + last
	}
	return h
}

func (c *AWSPCAConnector) probe(ctx context.Context) Health {
	api, err := c.client(ctx)
	if err != nil {
		return Health{Status: "degraded", Detail: err.Error()}
	}
	out, err := api.DescribeCertificateAuthority(ctx, &acmpca.DescribeCertificateAuthorityInput{
		CertificateAuthorityArn: aws.String(c.cfg.CertificateAuthorityARN)})
	if err != nil {
		return Health{Status: "degraded", Detail: c.mapErr("describe certificate authority", err).Error()}
	}
	if out.CertificateAuthority == nil {
		return Health{Status: "degraded", Detail: "describe certificate authority returned no CA"}
	}
	if out.CertificateAuthority.Status != pcatypes.CertificateAuthorityStatusActive {
		return Health{Status: "degraded", Detail: "CA status " + string(out.CertificateAuthority.Status)}
	}
	return Health{Status: "healthy"}
}

// signingAlgorithm returns the configured algorithm or the CA's own.
func (c *AWSPCAConnector) signingAlgorithm(ctx context.Context, api *acmpca.Client) (pcatypes.SigningAlgorithm, error) {
	if c.cfg.SigningAlgorithm != "" {
		return pcatypes.SigningAlgorithm(c.cfg.SigningAlgorithm), nil
	}
	c.mu.Lock()
	cached := c.sigAlg
	c.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	out, err := api.DescribeCertificateAuthority(ctx, &acmpca.DescribeCertificateAuthorityInput{
		CertificateAuthorityArn: aws.String(c.cfg.CertificateAuthorityARN)})
	if err != nil {
		return "", c.mapErr("describe certificate authority", err)
	}
	if out.CertificateAuthority == nil || out.CertificateAuthority.CertificateAuthorityConfiguration == nil ||
		out.CertificateAuthority.CertificateAuthorityConfiguration.SigningAlgorithm == "" {
		return "", fmt.Errorf("aws_pca %s: CA reports no signing algorithm; set signing_algorithm in the connector config", c.id)
	}
	alg := out.CertificateAuthority.CertificateAuthorityConfiguration.SigningAlgorithm
	c.mu.Lock()
	c.sigAlg = alg
	c.mu.Unlock()
	return alg, nil
}

// Issue submits the CSR, waits for the CA to finish, and returns the leaf
// followed by its chain.
func (c *AWSPCAConnector) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	res, err := c.issue(ctx, req)
	c.recordError(err)
	return res, err
}

func (c *AWSPCAConnector) issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("aws_pca %s: CSRPEM is not a PEM certificate request", c.id)
	}
	api, err := c.client(ctx)
	if err != nil {
		return IssueResult{}, err
	}
	alg, err := c.signingAlgorithm(ctx, api)
	if err != nil {
		return IssueResult{}, err
	}

	// A retry of the same CSR within AWS's 5 minute window must not mint a
	// second certificate. The token field allows 36 characters.
	sum := sha256.Sum256([]byte(req.CSRPEM))
	in := &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(c.cfg.CertificateAuthorityARN),
		Csr:                     []byte(req.CSRPEM),
		SigningAlgorithm:        alg,
		Validity:                &pcatypes.Validity{Type: pcatypes.ValidityPeriodTypeDays, Value: aws.Int64(c.cfg.ValidityDays)},
		IdempotencyToken:        aws.String(hex.EncodeToString(sum[:])[:36]),
	}
	if c.cfg.TemplateARN != "" {
		in.TemplateArn = aws.String(c.cfg.TemplateARN)
	}
	issued, err := api.IssueCertificate(ctx, in)
	if err != nil {
		return IssueResult{}, c.mapErr("issue certificate", err)
	}
	if issued.CertificateArn == nil || *issued.CertificateArn == "" {
		return IssueResult{}, fmt.Errorf("aws_pca %s: issue response carried no certificate ARN", c.id)
	}

	// The SDK waiter retries RequestInProgressException until the cert exists.
	waiter := acmpca.NewCertificateIssuedWaiter(api, func(o *acmpca.CertificateIssuedWaiterOptions) {
		o.MinDelay, o.MaxDelay = c.cfg.PollInterval, c.cfg.PollInterval
	})
	got, err := waiter.WaitForOutput(ctx, &acmpca.GetCertificateInput{
		CertificateArn:          issued.CertificateArn,
		CertificateAuthorityArn: aws.String(c.cfg.CertificateAuthorityARN),
	}, time.Duration(c.cfg.PollAttempts)*c.cfg.PollInterval)
	if err != nil {
		if ctx.Err() != nil {
			return IssueResult{}, ctx.Err()
		}
		return IssueResult{}, c.mapErr("get certificate", err)
	}
	return c.assemble(got)
}

// assemble refuses anything that is not parseable PEM certificates and
// returns leaf first, then the chain.
func (c *AWSPCAConnector) assemble(got *acmpca.GetCertificateOutput) (IssueResult, error) {
	leafPEM := strings.TrimSpace(aws.ToString(got.Certificate))
	leaf, _ := pem.Decode([]byte(leafPEM))
	if leaf == nil || leaf.Type != "CERTIFICATE" {
		return IssueResult{}, fmt.Errorf("aws_pca %s: issued certificate is not PEM", c.id)
	}
	cert, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("aws_pca %s: issued certificate unparseable: %w", c.id, err)
	}
	var b strings.Builder
	b.WriteString(leafPEM + "\n")
	rest := []byte(strings.TrimSpace(aws.ToString(got.CertificateChain)))
	for len(rest) > 0 {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return IssueResult{}, fmt.Errorf("aws_pca %s: certificate chain is not PEM", c.id)
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return IssueResult{}, fmt.Errorf("aws_pca %s: chain certificate unparseable: %w", c.id, err)
		}
		b.Write(pem.EncodeToMemory(blk))
	}
	fp := sha256.Sum256(cert.Raw)
	return IssueResult{FingerprintSHA256: hex.EncodeToString(fp[:]), CertificatePEM: b.String()}, nil
}

// pcaRevocationReason maps RFC 5280 CRLReason codes to the AWS enum. Codes
// AWS has no value for (certificateHold 6, removeFromCRL 8, unknown) become
// UNSPECIFIED.
func pcaRevocationReason(code int) pcatypes.RevocationReason {
	switch code {
	case 1:
		return pcatypes.RevocationReasonKeyCompromise
	case 2:
		return pcatypes.RevocationReasonCertificateAuthorityCompromise
	case 3:
		return pcatypes.RevocationReasonAffiliationChanged
	case 4:
		return pcatypes.RevocationReasonSuperseded
	case 5:
		return pcatypes.RevocationReasonCessationOfOperation
	case 9:
		return pcatypes.RevocationReasonPrivilegeWithdrawn
	case 10:
		return pcatypes.RevocationReasonAACompromise
	}
	return pcatypes.RevocationReasonUnspecified
}

// Revoke revokes by serial. The API wants hexadecimal; we send lower-case hex
// with no separators (the form in the IssueCertificate response ARN).
func (c *AWSPCAConnector) Revoke(ctx context.Context, req RevokeRequest) error {
	serial := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.SerialHex), ":", ""))
	if serial == "" {
		return fmt.Errorf("aws_pca %s: revoke needs a serial", c.id)
	}
	for _, r := range serial {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return fmt.Errorf("aws_pca %s: serial is not hexadecimal", c.id)
		}
	}
	api, err := c.client(ctx)
	if err != nil {
		return err
	}
	_, err = api.RevokeCertificate(ctx, &acmpca.RevokeCertificateInput{
		CertificateAuthorityArn: aws.String(c.cfg.CertificateAuthorityARN),
		CertificateSerial:       aws.String(serial),
		RevocationReason:        pcaRevocationReason(req.Reason),
	})
	return c.mapErr("revoke certificate", err)
}
