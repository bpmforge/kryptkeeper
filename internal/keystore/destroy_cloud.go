// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"kryptkeeper/internal/logging"
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
	// Same client as the create/sign paths so one transport (and the test fake)
	// covers the whole GCP surface; ctx carries the deadline.
	resp, err := gcpHTTPClient.Do(req)
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

// Provider recovery windows after a successful destroyCloudKey. AWS is the
// 7-day PendingWindowInDays destroyAWSKey requests; GCP's default
// destroy-scheduled duration is 24h; Azure soft-delete retention defaults to 90d.
const (
	awsDeletionWindow   = 7 * 24 * time.Hour
	gcpDeletionWindow   = 24 * time.Hour
	azureDeletionWindow = 90 * 24 * time.Hour
)

func deletionWindow(provider string) time.Duration {
	switch provider {
	case "aws":
		return awsDeletionWindow
	case "gcp":
		return gcpDeletionWindow
	case "azure":
		return azureDeletionWindow
	}
	return 0
}

// cloudKMSTombstone is what survives Delete: enough to restore the reference
// (public key only) and to address the key at the provider.
type cloudKMSTombstone struct {
	id          string
	config      CloudKMSConfig
	meta        KeyMetadata
	pubKey      crypto.PublicKey
	scheduledAt time.Time
	window      time.Duration
}

func (t *cloudKMSTombstone) cancellableAt(now time.Time) bool {
	return t.window > 0 && now.Before(t.scheduledAt.Add(t.window))
}

// cloudKMSPendingDeletionSchema mirrors migration 000123 (stores self-heal,
// like cloudKMSRefSchema).
const cloudKMSPendingDeletionSchema = `
CREATE TABLE IF NOT EXISTS cloud_kms_pending_deletions (
    id             TEXT PRIMARY KEY,
    provider       TEXT NOT NULL CHECK (provider IN ('aws', 'gcp', 'azure')),
    key_uri        TEXT NOT NULL,
    region         TEXT,
    project_id     TEXT,
    scheduled_at   TEXT NOT NULL,
    window_hours   INTEGER NOT NULL,
    algorithm      TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at     TEXT NOT NULL
);`

func (s *CloudKMSStore) ensureTombstoneSchema() error {
	_, err := s.db.Exec(cloudKMSPendingDeletionSchema)
	return err
}

func (s *CloudKMSStore) loadTombstones() error {
	rows, err := s.db.Query(fmt.Sprintf(`SELECT id, key_uri, COALESCE(region,''), COALESCE(project_id,''),
		scheduled_at, window_hours, algorithm, public_key_pem, created_at
		FROM cloud_kms_pending_deletions WHERE provider = %s`, s.ph(1)), s.provider)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, keyURI, region, projectID, scheduled, algo, pubPEM, createdAt string
		var windowHours int64
		if err := rows.Scan(&id, &keyURI, &region, &projectID, &scheduled, &windowHours, &algo, &pubPEM, &createdAt); err != nil {
			return err
		}
		at, err := time.Parse(time.RFC3339, scheduled)
		block, _ := pem.Decode([]byte(pubPEM))
		if err != nil || block == nil {
			logging.Warnf("cloud kms: pending deletion %q is unreadable; it cannot be cancelled", id)
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			logging.Warnf("cloud kms: pending deletion %q public key unparseable; it cannot be cancelled", id)
			continue
		}
		s.tombstones[id] = &cloudKMSTombstone{
			id:          id,
			config:      CloudKMSConfig{Provider: s.provider, KeyURI: keyURI, Region: region, ProjectID: projectID},
			meta:        KeyMetadata{ID: id, Algorithm: Algorithm(algo), CreatedAt: createdAt},
			pubKey:      pub,
			scheduledAt: at,
			window:      time.Duration(windowHours) * time.Hour,
		}
	}
	return rows.Err()
}

// recordTombstone notes a scheduled deletion; caller holds s.mu. Failure to
// persist is logged, not fatal: the provider destroy already happened, and
// losing the cancel option must not also block dropping the reference.
func (s *CloudKMSStore) recordTombstone(entry *cloudKMSKeyEntry) {
	t := &cloudKMSTombstone{
		id: entry.meta.ID, config: entry.config, meta: entry.meta, pubKey: entry.pubKey,
		scheduledAt: time.Now().UTC(), window: deletionWindow(s.provider),
	}
	s.tombstones[t.id] = t
	if s.db == nil {
		return
	}
	pubDER, err := x509.MarshalPKIXPublicKey(entry.pubKey)
	if err != nil {
		logging.Infof("cloud kms: pending deletion of %s not persisted: %v", t.id, err)
		return
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if _, err := s.db.Exec(fmt.Sprintf(`DELETE FROM cloud_kms_pending_deletions WHERE id = %s`, s.ph(1)), t.id); err != nil {
		logging.Infof("cloud kms: pending deletion of %s not persisted: %v", t.id, err)
		return
	}
	q := fmt.Sprintf(`INSERT INTO cloud_kms_pending_deletions
		(id, provider, key_uri, region, project_id, scheduled_at, window_hours, algorithm, public_key_pem, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10))
	if _, err := s.db.Exec(q, t.id, s.provider, t.config.KeyURI, t.config.Region, t.config.ProjectID,
		t.scheduledAt.Format(time.RFC3339), int64(t.window/time.Hour), string(t.meta.Algorithm), string(pubPEM), t.meta.CreatedAt); err != nil {
		logging.Infof("cloud kms: pending deletion of %s not persisted: %v", t.id, err)
	}
}

// PendingDeletions implements PendingDeletionLister: cancellable tombstones,
// sorted by id, flagged pending_deletion with the provider purge time.
func (s *CloudKMSStore) PendingDeletions(now time.Time) []KeyMetadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []KeyMetadata
	for id, t := range s.tombstones {
		if !s.cancellableLocked(id, now) {
			continue
		}
		m := t.meta
		m.State = "pending_deletion"
		m.DeletionScheduledAt = t.scheduledAt.Add(t.window).UTC().Format(time.RFC3339)
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CanCancelDeletion implements DeletionCanceller.
func (s *CloudKMSStore) CanCancelDeletion(id string, now time.Time) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cancellableLocked(id, now), nil
}

func (s *CloudKMSStore) cancellableLocked(id string, now time.Time) bool {
	t, ok := s.tombstones[id]
	if !ok {
		return false
	}
	// A key re-created under the same id owns the name; do not shadow it.
	_, live := s.keys[id]
	return !live && t.cancellableAt(now)
}

// CancelDeletion implements DeletionCanceller. The provider is asked first;
// only after it has restored the key to Enabled is the local reference
// brought back, so the store never claims a key the provider still holds
// pending deletion.
func (s *CloudKMSStore) CancelDeletion(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cancellableLocked(id, time.Now()) {
		return ErrNotCancellable
	}
	t := s.tombstones[id]
	cancel := s.cancelDestroy
	if cancel == nil {
		cancel = cancelCloudKeyDeletion
	}
	if err := cancel(ctx, t.config); err != nil {
		return fmt.Errorf("cloud key deletion cancel refused for %s: %w", t.config.KeyURI, err)
	}
	entry := &cloudKMSKeyEntry{meta: t.meta, config: t.config, pubKey: t.pubKey}
	s.keys[id] = entry
	delete(s.tombstones, id)
	if err := s.persistRef(id, entry); err != nil {
		logging.Infof("CLOUD KMS KEY RESTORED BUT REFERENCE NOT PERSISTED: %s (%s): %v", t.config.KeyURI, id, err)
		return fmt.Errorf("key restored at the provider but its reference could not be recorded: %w", err)
	}
	if s.db != nil {
		if _, err := s.db.Exec(fmt.Sprintf(`DELETE FROM cloud_kms_pending_deletions WHERE id = %s`, s.ph(1)), id); err != nil {
			logging.Infof("cloud kms: pending-deletion row for %s not removed: %v", id, err)
		}
	}
	return nil
}

// CancelCloudKeyDeletion exposes the provider-side reversal to the live
// emulator harness (tests/live), which sits outside this package.
func CancelCloudKeyDeletion(ctx context.Context, cfg CloudKMSConfig) error {
	return cancelCloudKeyDeletion(ctx, cfg)
}

// cancelCloudKeyDeletion is the real provider-side reversal. Each provider
// leaves the key Disabled after un-scheduling, so a second call enables it.
func cancelCloudKeyDeletion(ctx context.Context, cfg CloudKMSConfig) error {
	switch cfg.Provider {
	case "aws":
		return cancelAWSKeyDeletion(ctx, cfg)
	case "gcp":
		return cancelGCPKeyDeletion(ctx, cfg)
	case "azure":
		return cancelAzureKeyDeletion(ctx, cfg)
	default:
		return fmt.Errorf("unsupported KMS provider: %s", cfg.Provider)
	}
}

// awsDeletionAPI is the slice of the KMS client the cancel needs, so the
// cancel-then-enable order is testable without AWS.
type awsDeletionAPI interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	CancelKeyDeletion(ctx context.Context, in *kms.CancelKeyDeletionInput, opts ...func(*kms.Options)) (*kms.CancelKeyDeletionOutput, error)
	EnableKey(ctx context.Context, in *kms.EnableKeyInput, opts ...func(*kms.Options)) (*kms.EnableKeyOutput, error)
}

func cancelAWSKeyDeletion(ctx context.Context, cfg CloudKMSConfig) error {
	awscfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("aws kms: load config: %w", err)
	}
	return cancelAWSKeyDeletionWith(ctx, kms.NewFromConfig(awscfg), cfg.KeyURI)
}

// cancelAWSKeyDeletionWith un-schedules the deletion and then enables the key:
// CancelKeyDeletion leaves it Disabled, and "back to Enabled" needs both.
// It is idempotent across a partial failure: if an earlier attempt cancelled
// but EnableKey failed, the key is Disabled and a retry only enables it,
// rather than failing forever at the (already done) cancel step.
func cancelAWSKeyDeletionWith(ctx context.Context, api awsDeletionAPI, keyID string) error {
	d, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return fmt.Errorf("aws kms: describe key %s: %w", keyID, err)
	}
	if d == nil || d.KeyMetadata == nil {
		return fmt.Errorf("aws kms: describe key %s: empty response", keyID)
	}
	switch state := d.KeyMetadata.KeyState; state {
	case types.KeyStatePendingDeletion:
		if _, err := api.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: &keyID}); err != nil {
			return fmt.Errorf("aws kms: cancel key deletion %s: %w", keyID, err)
		}
	case types.KeyStateDisabled:
		// Cancelled earlier; only the enable is outstanding.
	default:
		return fmt.Errorf("aws kms: key %s is %s, not pending deletion", keyID, state)
	}
	if _, err := api.EnableKey(ctx, &kms.EnableKeyInput{KeyId: &keyID}); err != nil {
		return fmt.Errorf("aws kms: enable key %s after cancel: %w", keyID, err)
	}
	return nil
}

func cancelGCPKeyDeletion(ctx context.Context, cfg CloudKMSConfig) error {
	token, err := gcpKMSToken(ctx)
	if err != nil {
		return fmt.Errorf("gcp kms: get token: %w", err)
	}
	do := func(method, url, body string) error {
		req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := gcpHTTPClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return fmt.Errorf("returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		return nil
	}
	if err := do(http.MethodPost, gcpKMSBase+"/"+cfg.KeyURI+":restore", "{}"); err != nil {
		return fmt.Errorf("gcp kms: restore %s: %w", cfg.KeyURI, err)
	}
	if err := do(http.MethodPatch, gcpKMSBase+"/"+cfg.KeyURI+"?updateMask=state", `{"state":"ENABLED"}`); err != nil {
		return fmt.Errorf("gcp kms: enable %s after restore: %w", cfg.KeyURI, err)
	}
	return nil
}

func cancelAzureKeyDeletion(ctx context.Context, cfg CloudKMSConfig) error {
	token, err := azureKVToken(ctx)
	if err != nil {
		return fmt.Errorf("azure kv: get token: %w", err)
	}
	vault, name := azureVaultAndKeyName(cfg.KeyURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		vault+"/deletedkeys/"+name+"/recover?api-version="+azureKVAPIVersion, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := azureHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("azure kv: recover %s: %w", cfg.KeyURI, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("azure kv: recover %s returned %d: %s", cfg.KeyURI, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// azureVaultAndKeyName splits https://{vault}/keys/{name}[/{version}] into the
// vault base URL and the key name, the same way destroyAzureKey addresses it.
func azureVaultAndKeyName(keyURI string) (vault, name string) {
	idx := strings.Index(keyURI, "/keys/")
	if idx < 0 {
		return keyURI, ""
	}
	rest := keyURI[idx+len("/keys/"):]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		rest = rest[:slash]
	}
	return keyURI[:idx], rest
}
