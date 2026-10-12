// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// signAWS calls AWS KMS Sign API via aws-sdk-go-v2.
// The key URI stored in CloudKMSConfig is used as the KMS key ID (ARN, alias, or key ID).
func (s *CloudKMSSigner) signAWS(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cloudKMSCallTimeout)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws kms: load config: %w", err)
	}

	client := kms.NewFromConfig(cfg)

	signingAlgo, err := awsSigningAlgorithm(s.publicKey, opts)
	if err != nil {
		return nil, fmt.Errorf("aws kms: unsupported key/hash combination: %w", err)
	}

	out, err := client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.config.KeyURI,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlgo,
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: sign key %s: %w", s.keyID, err)
	}

	return out.Signature, nil
}

// awsSigningAlgorithm maps a Go public key + hash options to an AWS KMS signing algorithm.
func awsSigningAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	hash := opts.HashFunc()
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		}
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			_ = pss
			switch hash {
			case crypto.SHA256:
				return types.SigningAlgorithmSpecRsassaPssSha256, nil
			case crypto.SHA384:
				return types.SigningAlgorithmSpecRsassaPssSha384, nil
			case crypto.SHA512:
				return types.SigningAlgorithmSpecRsassaPssSha512, nil
			}
		}
		switch hash {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		}
	}
	return "", fmt.Errorf("no matching algorithm for key type %T hash %v", pub, hash)
}
