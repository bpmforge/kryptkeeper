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
	client *acm.Client
	region string
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

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
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
			certs = append(certs, cert)
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return certs, nil
}

// acmStatusToString converts an ACM status to a normalized string.
func acmStatusToString(s acmtypes.CertificateStatus) string {
	return strings.ToLower(string(s))
}
