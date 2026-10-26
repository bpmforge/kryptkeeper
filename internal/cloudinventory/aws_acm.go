// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
)

// ACMConnector lists certificates from AWS Certificate Manager.
//
// Configuration (env vars or IAM role):
//
//	AWS_REGION          - AWS region (default: us-east-1)
//	AWS_ACCESS_KEY_ID   - AWS credentials (optional if using IAM role / instance profile)
//	AWS_SECRET_ACCESS_KEY
type ACMConnector struct {
	client acmAPI
	region string
}

// acmAPI is the slice of *acm.Client the connector uses; a seam for tests.
type acmAPI interface {
	ListCertificates(ctx context.Context, in *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	GetCertificate(ctx context.Context, in *acm.GetCertificateInput, optFns ...func(*acm.Options)) (*acm.GetCertificateOutput, error)
}

// NewACMConnector creates an ACM connector using the default AWS credential chain
// (env vars, ~/.aws/credentials, IAM role, EC2 instance profile).
func NewACMConnector(ctx context.Context) (*ACMConnector, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	return NewACMConnectorForScope(ctx, Scope{Provider: ProviderAWSACM, Region: region})
}

// NewACMConnectorForScope connects to one account (shared-config profile) and
// region; an empty profile uses the default credential chain.
func NewACMConnectorForScope(ctx context.Context, sc Scope) (*ACMConnector, error) {
	region := sc.Region
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if sc.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(sc.Profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws acm: load config: %w", err)
	}

	return &ACMConnector{
		client: acm.NewFromConfig(cfg),
		region: region,
	}, nil
}

// ListCertificates returns all ACM certificates in the configured region.
func (c *ACMConnector) ListCertificates(ctx context.Context) ([]CloudCertificate, error) {
	var certs []CloudCertificate
	var nextToken *string

	for {
		out, err := c.client.ListCertificates(ctx, &acm.ListCertificatesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("aws acm: list certificates: %w", err)
		}

		for _, summary := range out.CertificateSummaryList {
			cert := CloudCertificate{
				Provider:   "aws-acm",
				Region:     c.region,
				ResourceID: aws.ToString(summary.CertificateArn),
				CommonName: aws.ToString(summary.DomainName),
				Status:     string(summary.Status),
				InUse:      summary.InUse != nil && *summary.InUse,
			}
			if len(summary.SubjectAlternativeNameSummaries) > 0 {
				cert.DNSNames = summary.SubjectAlternativeNameSummaries
			}
			if summary.KeyAlgorithm != "" {
				cert.KeyAlgorithm = string(summary.KeyAlgorithm)
			}
			if summary.NotBefore != nil {
				cert.NotBefore = *summary.NotBefore
			}
			if summary.NotAfter != nil {
				cert.NotAfter = *summary.NotAfter
			}
			cert.CertificatePEM = c.fetchPEM(ctx, summary.CertificateArn, summary.Status)
			certs = append(certs, cert)
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return certs, nil
}

// fetchPEM returns the issued certificate's PEM, or "" when it cannot be had.
// Only ISSUED certificates have a body; a denied or failed call (the role may
// lack acm:GetCertificate) leaves the row metadata-only rather than failing
// the whole scan.
// https://docs.aws.amazon.com/acm/latest/APIReference/API_GetCertificate.html
func (c *ACMConnector) fetchPEM(ctx context.Context, arn *string, status acmtypes.CertificateStatus) string {
	if arn == nil || status != acmtypes.CertificateStatusIssued {
		return ""
	}
	out, err := c.client.GetCertificate(ctx, &acm.GetCertificateInput{CertificateArn: arn})
	if err != nil {
		return ""
	}
	return aws.ToString(out.Certificate)
}

// acmStatusToString converts an ACM status to a normalized string.
func acmStatusToString(s acmtypes.CertificateStatus) string {
	return strings.ToLower(string(s))
}
