// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keyinventory

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// awsKMSAPI is the slice of the KMS client this source uses. An
// interface so tests inject a fake — no live AWS.
type awsKMSAPI interface {
	ListKeys(ctx context.Context, in *kms.ListKeysInput, opts ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, opts ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// AWSKeySource inventories AWS KMS keys.
type AWSKeySource struct {
	api    awsKMSAPI
	region string
}

// NewAWSKeySource wires the real KMS client via the default credential
// chain (the SDK is already a dependency).
func NewAWSKeySource(ctx context.Context, region string) (*AWSKeySource, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws kms: load config: %w", err)
	}
	return &AWSKeySource{api: kms.NewFromConfig(cfg), region: region}, nil
}

func newAWSKeySourceWithAPI(api awsKMSAPI, region string) *AWSKeySource {
	return &AWSKeySource{api: api, region: region}
}

func (s *AWSKeySource) Provider() string { return "aws-kms" }

func (s *AWSKeySource) ListKeys(ctx context.Context) ([]Key, error) {
	var keys []Key
	var marker *string
	for {
		out, err := s.api.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		for _, entry := range out.Keys {
			id := aws.ToString(entry.KeyId)
			k := Key{Provider: "aws-kms", Location: s.region, KeyID: id}
			if desc, err := s.api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: entry.KeyId}); err == nil && desc.KeyMetadata != nil {
				m := desc.KeyMetadata
				k.Algorithm = string(m.KeySpec)
				k.Usage = string(m.KeyUsage)
				k.State = string(m.KeyState)
				if m.CreationDate != nil {
					k.CreatedAt = m.CreationDate.UTC().Format("2006-01-02T15:04:05Z07:00")
				}
			}
			// Rotation status is a separate call; a failure (e.g. on an
			// asymmetric key that cannot rotate) just leaves it false.
			if rot, err := s.api.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: entry.KeyId}); err == nil {
				k.RotationEnabled = rot.KeyRotationEnabled
			}
			k.PQCReadiness = scoreKeyPQC(k.Algorithm)
			keys = append(keys, k)
		}
		if out.NextMarker == nil {
			return keys, nil
		}
		marker = out.NextMarker
	}
}
