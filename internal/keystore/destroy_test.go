// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// W9-07: destruction wipes what it claims to wipe, and cloud deletion
// destroys upstream BEFORE dropping the reference.

func TestZeroizeSignerWipesECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if key.D.Sign() == 0 {
		t.Fatal("test setup: D already zero")
	}
	if !ZeroizeSigner(key) {
		t.Fatal("ecdsa key not recognized")
	}
	if key.D.Sign() != 0 {
		t.Fatal("ecdsa D not wiped")
	}
}

func TestZeroizeSignerWipesRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if !ZeroizeSigner(key) {
		t.Fatal("rsa key not recognized")
	}
	if key.D.Sign() != 0 {
		t.Fatal("rsa D not wiped")
	}
	for i, prime := range key.Primes {
		if prime.Sign() != 0 {
			t.Fatalf("rsa prime %d not wiped", i)
		}
	}
}

func TestZeroizeSignerWipesEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if !ZeroizeSigner(priv) {
		t.Fatal("ed25519 key not recognized")
	}
	for i, b := range priv {
		if b != 0 {
			t.Fatalf("ed25519 byte %d not wiped", i)
		}
	}
}

type unknownSigner struct{ ecdsa.PrivateKey }

func TestZeroizeSignerLeavesUnknownTypesAlone(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrapped := &unknownSigner{*key}
	if ZeroizeSigner(wrapped) {
		t.Fatal("unknown wrapper type must not claim a wipe")
	}
}

// The software store's Delete wipes the CACHED decrypted signer — the exact
// material os.Remove alone left live in memory.
func TestSoftwareDeleteZeroizesCachedSigner(t *testing.T) {
	store, err := NewSoftwareStore(t.TempDir(), []byte("destroy-test-passphrase-32bytes!"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()

	if _, err := store.GenerateKey("doomed", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := store.Signer("doomed") // decrypts + caches
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ecdsaKey, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected signer type %T", signer)
	}
	before := new(big.Int).Set(ecdsaKey.D)
	if before.Sign() == 0 {
		t.Fatal("test setup: D already zero")
	}

	if err := store.Delete("doomed"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ecdsaKey.D.Sign() != 0 {
		t.Fatal("cached signer material survived Delete un-wiped")
	}
}

func TestSoftwareEvictSignerZeroizes(t *testing.T) {
	store, err := NewSoftwareStore(t.TempDir(), []byte("destroy-test-passphrase-32bytes!"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	if _, err := store.GenerateKey("evicted", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, _ := store.Signer("evicted")
	ecdsaKey := signer.(*ecdsa.PrivateKey)

	store.EvictSigner("evicted")
	if ecdsaKey.D.Sign() != 0 {
		t.Fatal("evicted signer material not wiped")
	}
}

// Cloud delete destroys upstream FIRST; a provider refusal retains the
// reference — never lose the pointer to a live cloud key.
func TestCloudKMSDeleteDestroysUpstreamFirst(t *testing.T) {
	db := newCloudKMSTestDB(t)
	store, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fabricateEntry(t, store, "cloud-doomed", "arn:aws:kms:us-east-1:1:key/doomed")

	var destroyedURI string
	store.destroyKey = func(_ context.Context, cfg CloudKMSConfig) error {
		destroyedURI = cfg.KeyURI
		return nil
	}
	if err := store.Delete("cloud-doomed"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if destroyedURI != "arn:aws:kms:us-east-1:1:key/doomed" {
		t.Fatalf("provider destruction not invoked with the key URI: %q", destroyedURI)
	}
	if _, err := store.Metadata("cloud-doomed"); err == nil {
		t.Fatal("reference survived a successful destroy+delete")
	}
}

func TestCloudKMSDeleteRetainsReferenceWhenDestroyRefused(t *testing.T) {
	db := newCloudKMSTestDB(t)
	store, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fabricateEntry(t, store, "cloud-sticky", "arn:aws:kms:us-east-1:1:key/sticky")
	store.destroyKey = func(context.Context, CloudKMSConfig) error {
		return errors.New("kms says no")
	}

	if err := store.Delete("cloud-sticky"); err == nil {
		t.Fatal("delete must fail when the provider refuses destruction")
	}
	// The reference survives in memory AND on the row.
	if _, err := store.Metadata("cloud-sticky"); err != nil {
		t.Fatalf("reference lost despite refused destruction: %v", err)
	}
	reloaded, _ := NewCloudKMSStoreWithDB("aws", db, false)
	if _, err := reloaded.Metadata("cloud-sticky"); err != nil {
		t.Fatal("reference row lost despite refused destruction")
	}
}

// --- W23-22: cancelling a scheduled deletion ---

// deletedCloudStore returns an aws store over db whose key "k1" has been
// deleted through the stubbed provider, i.e. only the tombstone remains.
func deletedCloudStore(t *testing.T, db *sql.DB) *CloudKMSStore {
	t.Helper()
	store, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fabricateEntry(t, store, "k1", "arn:aws:kms:us-east-1:1:key/k1")
	store.destroyKey = func(context.Context, CloudKMSConfig) error { return nil }
	if err := store.Delete("k1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	return store
}

func TestCloudKMSDeleteRecordsTombstone(t *testing.T) {
	db := newCloudKMSTestDB(t)
	store := deletedCloudStore(t, db)
	if _, err := store.Metadata("k1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("reference must be gone after delete, got %v", err)
	}
	var uri, at string
	var hours int
	if err := db.QueryRow(`SELECT key_uri, scheduled_at, window_hours FROM cloud_kms_pending_deletions WHERE id = 'k1'`).Scan(&uri, &at, &hours); err != nil {
		t.Fatalf("tombstone row missing: %v", err)
	}
	if uri != "arn:aws:kms:us-east-1:1:key/k1" || hours != 7*24 {
		t.Fatalf("tombstone = %q window %dh, want the key ARN and 168h", uri, hours)
	}
	if ok, _ := store.CanCancelDeletion("k1", time.Now()); !ok {
		t.Fatal("a just-deleted key must be cancellable")
	}
}

func TestCancelDeletionRestoresKeyToEnabled(t *testing.T) {
	db := newCloudKMSTestDB(t)
	store := deletedCloudStore(t, db)
	var cancelledURI string
	store.cancelDestroy = func(_ context.Context, cfg CloudKMSConfig) error {
		cancelledURI = cfg.KeyURI
		return nil
	}
	if err := store.CancelDeletion(context.Background(), "k1"); err != nil {
		t.Fatalf("CancelDeletion: %v", err)
	}
	if cancelledURI != "arn:aws:kms:us-east-1:1:key/k1" {
		t.Fatalf("provider cancel got %q", cancelledURI)
	}
	if meta, err := store.Metadata("k1"); err != nil || meta.Algorithm != ECDSAP256 {
		t.Fatalf("Metadata after cancel = %+v, %v", meta, err)
	}
	if _, err := store.Signer("k1"); err != nil {
		t.Fatalf("Signer after cancel: %v", err)
	}
	if ok, _ := store.CanCancelDeletion("k1", time.Now()); ok {
		t.Fatal("tombstone must be gone after a cancel")
	}
	// The restored reference is durable.
	reloaded, _ := NewCloudKMSStoreWithDB("aws", db, false)
	if _, err := reloaded.Metadata("k1"); err != nil {
		t.Fatalf("restored reference not persisted: %v", err)
	}
	if err := store.CancelDeletion(context.Background(), "k1"); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("second cancel = %v, want ErrNotCancellable", err)
	}
}

// recordingKMS models the AWS key state machine: CancelKeyDeletion moves
// PendingDeletion to Disabled, EnableKey moves Disabled to Enabled.
type recordingKMS struct {
	calls     []string
	state     types.KeyState
	enableErr error // returned (once, then cleared) by EnableKey
}

func (r *recordingKMS) DescribeKey(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{KeyState: r.state}}, nil
}

func (r *recordingKMS) CancelKeyDeletion(_ context.Context, in *kms.CancelKeyDeletionInput, _ ...func(*kms.Options)) (*kms.CancelKeyDeletionOutput, error) {
	r.calls = append(r.calls, "cancel:"+*in.KeyId)
	if r.state != types.KeyStatePendingDeletion {
		return nil, errors.New("KMSInvalidStateException: not pending deletion")
	}
	r.state = types.KeyStateDisabled
	return &kms.CancelKeyDeletionOutput{}, nil
}

func (r *recordingKMS) EnableKey(_ context.Context, in *kms.EnableKeyInput, _ ...func(*kms.Options)) (*kms.EnableKeyOutput, error) {
	r.calls = append(r.calls, "enable:"+*in.KeyId)
	if err := r.enableErr; err != nil {
		r.enableErr = nil
		return nil, err
	}
	r.state = types.KeyStateEnabled
	return &kms.EnableKeyOutput{}, nil
}

// AWS leaves a cancelled key Disabled, so enable must follow, in that order.
func TestAWSCancelIsCancelThenEnable(t *testing.T) {
	api := &recordingKMS{state: types.KeyStatePendingDeletion}
	if err := cancelAWSKeyDeletionWith(context.Background(), api, "arn:k"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(api.calls, ","); got != "cancel:arn:k,enable:arn:k" {
		t.Fatalf("call order = %s", got)
	}
	if api.state != types.KeyStateEnabled {
		t.Fatalf("final state = %s", api.state)
	}
}

// A cancel whose EnableKey failed leaves the key Disabled; the retry must not
// fail at the already-done cancel step.
func TestAWSCancelRetryAfterEnableFailure(t *testing.T) {
	api := &recordingKMS{state: types.KeyStatePendingDeletion, enableErr: errors.New("throttled")}
	if err := cancelAWSKeyDeletionWith(context.Background(), api, "k"); err == nil {
		t.Fatal("first attempt must report the enable failure")
	}
	if api.state != types.KeyStateDisabled {
		t.Fatalf("after failed enable state = %s, want Disabled", api.state)
	}
	if err := cancelAWSKeyDeletionWith(context.Background(), api, "k"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if api.state != types.KeyStateEnabled {
		t.Fatalf("after retry state = %s, want Enabled", api.state)
	}
	if got := strings.Join(api.calls, ","); got != "cancel:k,enable:k,enable:k" {
		t.Fatalf("calls = %s (retry must skip the cancel)", got)
	}
}

func TestAWSCancelRefusesEnabledKey(t *testing.T) {
	api := &recordingKMS{state: types.KeyStateEnabled}
	if err := cancelAWSKeyDeletionWith(context.Background(), api, "k"); err == nil {
		t.Fatal("cancel of an Enabled key must error")
	}
	if len(api.calls) != 0 {
		t.Fatalf("no mutating call expected, got %v", api.calls)
	}
}

func TestCancelDeletionOutsideWindowIsErrNotCancellable(t *testing.T) {
	store := deletedCloudStore(t, newCloudKMSTestDB(t))
	scheduled := store.tombstones["k1"].scheduledAt
	for _, c := range []struct {
		at   time.Time
		want bool
	}{
		{scheduled.Add(6 * 24 * time.Hour), true},
		{scheduled.Add(8 * 24 * time.Hour), false},
	} {
		if got, _ := store.CanCancelDeletion("k1", c.at); got != c.want {
			t.Errorf("CanCancelDeletion at +%v = %v, want %v", c.at.Sub(scheduled), got, c.want)
		}
	}
	// Expire the window for real and confirm CancelDeletion refuses without
	// ever calling the provider.
	store.tombstones["k1"].scheduledAt = time.Now().Add(-8 * 24 * time.Hour)
	store.cancelDestroy = func(context.Context, CloudKMSConfig) error {
		t.Fatal("provider must not be called outside the window")
		return nil
	}
	if err := store.CancelDeletion(context.Background(), "k1"); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("CancelDeletion = %v, want ErrNotCancellable", err)
	}
}

func TestCancelDeletionKeepsTombstoneWhenProviderRefuses(t *testing.T) {
	store := deletedCloudStore(t, newCloudKMSTestDB(t))
	store.cancelDestroy = func(context.Context, CloudKMSConfig) error { return errors.New("kms says no") }
	if err := store.CancelDeletion(context.Background(), "k1"); err == nil || errors.Is(err, ErrNotCancellable) {
		t.Fatalf("CancelDeletion = %v, want a provider error", err)
	}
	if _, err := store.Metadata("k1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatal("a refused cancel must not resurrect the reference")
	}
	if ok, _ := store.CanCancelDeletion("k1", time.Now()); !ok {
		t.Fatal("a refused cancel must keep the tombstone for a retry")
	}
}

func TestSoftwareStoreIsNotACanceller(t *testing.T) {
	store, err := NewSoftwareStore(t.TempDir(), []byte("destroy-test-passphrase-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var s Store = store
	if _, ok := s.(DeletionCanceller); ok {
		t.Fatal("software keys have no provider recovery window and must not be cancellable")
	}
}

func TestTombstoneSurvivesRestart(t *testing.T) {
	db := newCloudKMSTestDB(t)
	deletedCloudStore(t, db)
	second, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := second.CanCancelDeletion("k1", time.Now()); !ok {
		t.Fatal("tombstone lost across a restart")
	}
	second.cancelDestroy = func(context.Context, CloudKMSConfig) error { return nil }
	if err := second.CancelDeletion(context.Background(), "k1"); err != nil {
		t.Fatalf("cancel after restart: %v", err)
	}
	if _, err := second.Signer("k1"); err != nil {
		t.Fatalf("signer after restart+cancel: %v", err)
	}
}

// Real GCP wire path: restore, then PATCH state=ENABLED, in that order.
func TestGCPCancelDeletionRestoresThenEnables(t *testing.T) {
	var calls []string
	installFakeGCPKMS(t)
	prev := gcpHTTPClient
	gcpHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+string(body))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})}
	t.Cleanup(func() { gcpHTTPClient = prev })
	cfg := CloudKMSConfig{Provider: "gcp", KeyURI: fakeGCPKeyRing + "/cryptoKeys/k/cryptoKeyVersions/1"}
	if err := cancelGCPKeyDeletion(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /v1/" + cfg.KeyURI + ":restore? {}",
		"PATCH /v1/" + cfg.KeyURI + "?updateMask=state {\"state\":\"ENABLED\"}",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls =\n%s\nwant\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
}

// W23-23: a key in its provider recovery window is listed (flagged) by
// PendingDeletions but never by List, so rotation/signing cannot see it.
func TestCloudKMSPendingDeletionsListsTombstoneOnly(t *testing.T) {
	db := newCloudKMSTestDB(t)
	store := deletedCloudStore(t, db)
	now := time.Now()
	got := store.PendingDeletions(now)
	if len(got) != 1 || got[0].ID != "k1" || got[0].State != "pending_deletion" {
		t.Fatalf("PendingDeletions = %+v, want k1 flagged pending_deletion", got)
	}
	purge, err := time.Parse(time.RFC3339, got[0].DeletionScheduledAt)
	if err != nil || purge.Before(now.Add(6*24*time.Hour)) || purge.After(now.Add(8*24*time.Hour)) {
		t.Fatalf("DeletionScheduledAt = %q (%v), want ~7 days out", got[0].DeletionScheduledAt, err)
	}
	if live, _ := store.List(); len(live) != 0 {
		t.Fatalf("List must not include a pending-deletion key, got %+v", live)
	}
	if past := store.PendingDeletions(now.Add(8 * 24 * time.Hour)); len(past) != 0 {
		t.Fatalf("a key past its window must not be listed, got %+v", past)
	}
}
