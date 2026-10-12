// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// W17-12: concrete KMSImportTarget adapters.
//
// Only AWS is implemented. Azure Key Vault and GCP KMS both support BYOK
// but with DIFFERENT wrapping envelopes and key-exchange dances (Azure's
// BYOK blob is a signed JWE-like structure with a KEK ceremony; GCP wraps
// against a per-import-job public key). ExportEscrowedKeyToKMS builds the
// AWS RSA_AES_KEY_WRAP_SHA_256 layout specifically, so pointing it at
// either of the others would produce a blob they reject — or worse,
// appear to work in a test double. They therefore REFUSE explicitly
// rather than pretending, and say what is missing.

// awsKMSAPI is the slice of the KMS client this adapter needs, so tests
// substitute a fake and CI needs no AWS credentials.
type awsKMSImportAPI interface {
	GetParametersForImport(ctx context.Context, in *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	ImportKeyMaterial(ctx context.Context, in *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
}

// AWSKMSImportTarget imports wrapped key material into an AWS KMS key.
type AWSKMSImportTarget struct {
	api   awsKMSImportAPI
	keyID string
}

// NewAWSKMSImportTarget wires the real KMS client via the default
// credential chain (the SDK is already a dependency).
func NewAWSKMSImportTarget(ctx context.Context, region, keyID string) (*AWSKMSImportTarget, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, fmt.Errorf("aws kms import: key id is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws kms import: load config: %w", err)
	}
	return &AWSKMSImportTarget{api: kms.NewFromConfig(cfg), keyID: keyID}, nil
}

func newAWSKMSImportTargetWithAPI(api awsKMSImportAPI, keyID string) *AWSKMSImportTarget {
	return &AWSKMSImportTarget{api: api, keyID: keyID}
}

func (t *AWSKMSImportTarget) Provider() string { return "aws-kms" }
func (t *AWSKMSImportTarget) KeyID() string    { return t.keyID }

// ImportParameters requests the wrapping public key and import token for
// RSA_AES_KEY_WRAP_SHA_256 — the algorithm ExportEscrowedKeyToKMS builds
// for. Asking for a different spec would hand back a key the wrap does
// not match, so it is pinned here rather than made configurable.
func (t *AWSKMSImportTarget) ImportParameters(ctx context.Context) ([]byte, []byte, error) {
	out, err := t.api.GetParametersForImport(ctx, &kms.GetParametersForImportInput{
		KeyId:             aws.String(t.keyID),
		WrappingAlgorithm: types.AlgorithmSpecRsaAesKeyWrapSha256,
		WrappingKeySpec:   types.WrappingKeySpecRsa4096,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("aws kms GetParametersForImport %s: %w", t.keyID, err)
	}
	if len(out.PublicKey) == 0 || len(out.ImportToken) == 0 {
		return nil, nil, fmt.Errorf("aws kms GetParametersForImport %s: empty public key or import token", t.keyID)
	}
	return out.PublicKey, out.ImportToken, nil
}

// Import uploads the wrapped material. Key material is imported WITHOUT
// an expiry: an expiring import silently disables the CA key when it
// lapses, which for a certificate authority is an outage disguised as a
// policy setting.
func (t *AWSKMSImportTarget) Import(ctx context.Context, encryptedKeyMaterial, importToken []byte) error {
	_, err := t.api.ImportKeyMaterial(ctx, &kms.ImportKeyMaterialInput{
		KeyId:                aws.String(t.keyID),
		EncryptedKeyMaterial: encryptedKeyMaterial,
		ImportToken:          importToken,
		ExpirationModel:      types.ExpirationModelTypeKeyMaterialDoesNotExpire,
	})
	if err != nil {
		return fmt.Errorf("aws kms ImportKeyMaterial %s: %w", t.keyID, err)
	}
	return nil
}

// NewKMSImportTarget builds the adapter for a provider.
//
// Azure and GCP refuse explicitly. Their BYOK envelopes differ from AWS's
// RSA_AES_KEY_WRAP_SHA_256, so silently accepting them would build a blob
// they reject at best, and at worst look correct until a real import.
func NewKMSImportTarget(ctx context.Context, provider, region, keyID string) (KMSImportTarget, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws", "aws-kms":
		return NewAWSKMSImportTarget(ctx, region, keyID)
	case "azure", "azure-kv":
		return nil, fmt.Errorf("byok: Azure Key Vault import is not implemented — its BYOK blob is a signed transfer structure with its own KEK ceremony, not AWS's RSA_AES_KEY_WRAP_SHA_256 layout, so this refuses rather than sending material Azure would reject")
	case "gcp", "gcp-kms":
		return nil, fmt.Errorf("byok: GCP KMS import is not implemented — it wraps against a per-import-job public key rather than AWS's RSA_AES_KEY_WRAP_SHA_256 layout, so this refuses rather than sending material GCP would reject")
	default:
		return nil, fmt.Errorf("byok: unknown provider %q (supported: aws)", provider)
	}
}
