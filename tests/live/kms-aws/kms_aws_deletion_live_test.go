// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package kmsaws_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"kryptkeeper/internal/keystore"
)

// Scheduling deletion must park the key in PendingDeletion with the 7-day
// window, and the product cancel must return it to Enabled (AWS leaves a
// cancelled key Disabled, so a raw CancelKeyDeletion alone would not).
// A bare key id is used throughout: moto answers ScheduleKeyDeletion with a
// 500 when handed an ARN. Scheduling is done with the SDK directly, so what is
// proven end to end is the emulator wiring plus the product cancel wrapper,
// not CloudKMSStore.Delete's own schedule call.
func TestAWSKMSDeletionPendingAndCancel(t *testing.T) {
	if os.Getenv("KK_LIVE_KMS_AWS") != "1" {
		t.Skip("set KK_LIVE_KMS_AWS=1 (see run.sh) to run against a KMS emulator")
	}
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Fatal("AWS_ENDPOINT_URL must point at the emulator; refusing to fall through to real AWS")
	}
	ctx := context.Background()
	awscfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := kms.NewFromConfig(awscfg)

	created, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  types.KeySpecEccNistP256,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyID := aws.ToString(created.KeyMetadata.KeyId)
	state := func() *types.KeyMetadata {
		t.Helper()
		d, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
		if err != nil {
			t.Fatalf("DescribeKey: %v", err)
		}
		return d.KeyMetadata
	}

	const windowDays = 7
	if _, err := client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId: &keyID, PendingWindowInDays: aws.Int32(windowDays),
	}); err != nil {
		t.Fatalf("ScheduleKeyDeletion: %v", err)
	}
	md := state()
	if md.KeyState != types.KeyStatePendingDeletion {
		t.Fatalf("state after schedule = %s, want PendingDeletion", md.KeyState)
	}
	if md.DeletionDate == nil {
		t.Log("emulator returned no DeletionDate; window not asserted")
	} else if d := time.Until(*md.DeletionDate) - windowDays*24*time.Hour; d < -24*time.Hour || d > 24*time.Hour {
		t.Fatalf("DeletionDate %v is not within 24h of now+%d days", *md.DeletionDate, windowDays)
	}

	cfg := keystore.CloudKMSConfig{Provider: "aws", KeyURI: keyID}
	if err := keystore.CancelCloudKeyDeletion(ctx, cfg); err != nil {
		t.Fatalf("CancelCloudKeyDeletion: %v", err)
	}
	if got := state().KeyState; got != types.KeyStateEnabled {
		t.Fatalf("state after cancel = %s, want Enabled", got)
	}
	if err := keystore.CancelCloudKeyDeletion(ctx, cfg); err == nil {
		t.Fatal("cancelling an Enabled key must error")
	}
}
