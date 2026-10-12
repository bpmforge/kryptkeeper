// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// CLOUD-002 / CLOUD-003 / CLOUD-008: what the hub stamps on, and demands of,
// the cloud keys it creates.
//
// Every key carries a managed marker so provider IAM can be scoped to
// hub-created keys (AWS aws:ResourceTag/kryptkeeper:managed, GCP IAM
// conditions on resource.labels, Azure tag-based policy) instead of
// account-wide Sign / ScheduleKeyDeletion.

const (
	envKMSTags       = "KRYPTKEEPER_KMS_TAGS"           // JSON object of extra tags/labels
	envGCPProtection = "KRYPTKEEPER_GCP_KMS_PROTECTION" // hsm (default) | software
	envAzureKeyHSM   = "KRYPTKEEPER_AZURE_KEY_HSM"      // true (default) | false

	tagManagedKey      = "kryptkeeper:managed" // AWS tag key
	tagKeyIDKey        = "kryptkeeper:key-id"  // AWS tag key
	tagManagedKeyLabel = "kryptkeeper_managed" // GCP label / Azure tag
	tagKeyIDLabel      = "kryptkeeper_key_id"  // GCP label / Azure tag
	tagReservedPrefix  = "kryptkeeper"         // operator tags may not use it
)

// cloudKeyIDPattern is the intersection that is safe in a GCP query string
// and an Azure path segment. Provider charsets are narrower (Azure has no
// underscore); the provider rejects what this lets through.
var cloudKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

func validateCloudKeyID(id string) error {
	if !cloudKeyIDPattern.MatchString(id) {
		return fmt.Errorf("invalid key id %q: must match %s", id, cloudKeyIDPattern)
	}
	return nil
}

// operatorTags parses KRYPTKEEPER_KMS_TAGS. A malformed value is an error,
// not a silent drop: an operator who relies on an extra tag for IAM scoping
// must not get untagged keys.
func operatorTags() (map[string]string, error) {
	raw := strings.TrimSpace(os.Getenv(envKMSTags))
	if raw == "" {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("%s must be a JSON object of string values: %w", envKMSTags, err)
	}
	for k := range m {
		if strings.HasPrefix(strings.ToLower(k), tagReservedPrefix) {
			return nil, fmt.Errorf("%s: tag %q uses the reserved %q prefix", envKMSTags, k, tagReservedPrefix)
		}
	}
	return m, nil
}

// awsKeyTags is the tag set for a hub-created AWS KMS key.
func awsKeyTags(id string) ([]types.Tag, error) {
	extra, err := operatorTags()
	if err != nil {
		return nil, err
	}
	tags := []types.Tag{
		{TagKey: strPtr(tagManagedKey), TagValue: strPtr("true")},
		{TagKey: strPtr(tagKeyIDKey), TagValue: strPtr(id)},
	}
	for k, v := range extra {
		tags = append(tags, types.Tag{TagKey: strPtr(k), TagValue: strPtr(v)})
	}
	return tags, nil
}

func awsCreateKeyInput(id string, spec types.KeySpec) (*kms.CreateKeyInput, error) {
	tags, err := awsKeyTags(id)
	if err != nil {
		return nil, err
	}
	return &kms.CreateKeyInput{
		Description: &id,
		KeyUsage:    types.KeyUsageTypeSignVerify,
		KeySpec:     spec,
		Tags:        tags,
	}, nil
}

// gcpKeyLabels: GCP labels are lowercase [a-z0-9_-], at most 63 chars.
func gcpKeyLabels(id string) (map[string]string, error) {
	extra, err := operatorTags()
	if err != nil {
		return nil, err
	}
	labels := map[string]string{}
	for k, v := range extra {
		labels[strings.ToLower(k)] = strings.ToLower(v)
	}
	labels[tagManagedKeyLabel] = "true"
	labels[tagKeyIDLabel] = strings.ToLower(id)
	return labels, nil
}

// azureKeyTags: Key Vault key tags are free-form strings.
func azureKeyTags(id string) (map[string]string, error) {
	extra, err := operatorTags()
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for k, v := range extra {
		tags[k] = v
	}
	tags[tagManagedKeyLabel] = "true"
	tags[tagKeyIDLabel] = id
	return tags, nil
}

// gcpProtectionLevel defaults to HSM for CA keys (CLOUD-003).
func gcpProtectionLevel() (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(envGCPProtection))); v {
	case "", "hsm":
		return "HSM", nil
	case "software":
		return "SOFTWARE", nil
	default:
		return "", fmt.Errorf("%s must be hsm or software, got %q", envGCPProtection, v)
	}
}

// azureUseHSM defaults to true: EC-HSM / RSA-HSM need a Premium vault or a
// Managed HSM, and a Standard vault rejects them with a clear error.
func azureUseHSM() (bool, error) {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(envAzureKeyHSM))); v {
	case "", "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false, got %q", envAzureKeyHSM, v)
	}
}

func strPtr(s string) *string { return &s }
