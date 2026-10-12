// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// destroyCloudKey is the real provider-side destruction dispatch (W9-07).
// Each path mirrors the auth/URL conventions the corresponding sign path in
// this package already uses — nothing invented.
func destroyCloudKey(ctx context.Context, cfg CloudKMSConfig) error {
	switch cfg.Provider {
	case "aws":
		return destroyAWSKey(ctx, cfg)
	case "gcp":
		return destroyGCPKey(ctx, cfg)
	case "azure":
		return destroyAzureKey(ctx, cfg)
	default:
		return fmt.Errorf("unsupported KMS provider: %s", cfg.Provider)
	}
}

// destroyAWSKey schedules deletion with the minimum 7-day pending window —
// AWS KMS has no immediate destroy, by design; the window is the recovery
// period.
func destroyAWSKey(ctx context.Context, cfg CloudKMSConfig) error {
	awscfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("aws kms: load config: %w", err)
	}
	client := kms.NewFromConfig(awscfg)
	window := int32(7)
	if _, err := client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               &cfg.KeyURI,
		PendingWindowInDays: &window,
	}); err != nil {
		return fmt.Errorf("aws kms: schedule key deletion %s: %w", cfg.KeyURI, err)
	}
	return nil
}

// destroyGCPKey destroys the crypto key version (cryptoKeyVersions.destroy).
// KeyURI is the full version resource name, same as the sign path uses.
func destroyGCPKey(ctx context.Context, cfg CloudKMSConfig) error {
	token, err := gcpKMSToken(ctx)
	if err != nil {
		return fmt.Errorf("gcp kms: get token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		gcpKMSBase+"/"+cfg.KeyURI+":destroy", strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("gcp kms: destroy %s: %w", cfg.KeyURI, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("gcp kms: destroy %s returned %d: %s", cfg.KeyURI, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// destroyAzureKey deletes the Key Vault key (it enters the vault's
// soft-delete retention, Azure's equivalent of a pending window).
// KeyURI is the key's vault URL, same as the sign path uses.
func destroyAzureKey(ctx context.Context, cfg CloudKMSConfig) error {
	token, err := azureKVToken(ctx)
	if err != nil {
		return fmt.Errorf("azure kv: get token: %w", err)
	}
	// KeyURI looks like https://{vault}.vault.azure.net/keys/{name}[/{version}];
	// deletion targets the key name, not a version.
	base := cfg.KeyURI
	if idx := strings.Index(base, "/keys/"); idx >= 0 {
		rest := base[idx+len("/keys/"):]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			base = base[:idx+len("/keys/")] + rest[:slash]
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		base+"?api-version="+azureKVAPIVersion, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("azure kv: delete %s: %w", cfg.KeyURI, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("azure kv: delete %s returned %d: %s", cfg.KeyURI, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
