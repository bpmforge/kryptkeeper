// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// CloudKMSConfig holds configuration for a cloud KMS backend.
type CloudKMSConfig struct {
	Provider  string // aws, gcp, azure
	KeyURI    string // provider-specific key URI
	Region    string // AWS region or GCP location
	ProjectID string // GCP project ID
}

// cloudKMSCallTimeout bounds each AWS call; Signer.Sign carries no context
// and the SDK default client has no overall timeout (CLOUD-005).
const cloudKMSCallTimeout = 30 * time.Second

var ErrCloudKMSNotConfigured = errors.New("cloud KMS not configured")

// CloudKMSSigner wraps a cloud KMS key reference as a crypto.Signer.
// The private key never leaves the KMS boundary — Sign() calls the remote API.
type CloudKMSSigner struct {
	config    CloudKMSConfig
	keyID     string
	publicKey crypto.PublicKey
}

func (s *CloudKMSSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *CloudKMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Production: dispatch to AWS KMS SignAsync, GCP KMS AsymmetricSign, or Azure Key Vault Sign.
	// For MVP, this is a pluggable interface point — real SDK calls are wired per provider.
	switch s.config.Provider {
	case "aws":
		return s.signAWS(digest, opts)
	case "gcp":
		return s.signGCP(digest, opts)
	case "azure":
		return s.signAzure(digest, opts)
	default:
		return nil, fmt.Errorf("unsupported KMS provider: %s", s.config.Provider)
	}
}

// CloudKMSStore implements the Store interface for cloud KMS backends.
// Keys are created and managed in the cloud KMS — this store only holds
// references and public keys. Private key material never touches disk.
// With a DB attached (W9-02), the id -> key-URI references persist in
// cloud_kms_keys and survive restarts; without one they are memory-only,
// which orphans cloud keys on restart — the exact G-34 bug.
type CloudKMSStore struct {
	provider string
	db       *sql.DB
	postgres bool
	mu       sync.RWMutex
	keys     map[string]*cloudKMSKeyEntry
	// destroyKey performs the provider-side destruction (W9-07). Injectable
	// so tests assert the call without touching a cloud; nil uses the real
	// per-provider dispatch.
	destroyKey func(ctx context.Context, cfg CloudKMSConfig) error
}

type cloudKMSKeyEntry struct {
	meta   KeyMetadata
	config CloudKMSConfig
	pubKey crypto.PublicKey
}

// NewCloudKMSStore creates a memory-only cloud KMS store. Prefer
// NewCloudKMSStoreWithDB in any process that restarts (W9-02).
func NewCloudKMSStore(provider string) (*CloudKMSStore, error) {
	return NewCloudKMSStoreWithDB(provider, nil, false)
}

// NewCloudKMSStoreWithDB creates a cloud KMS store whose key references
// persist in cloud_kms_keys (migration 000037). Loading parses the stored
// PKIX public keys — zero KMS calls at boot.
func NewCloudKMSStoreWithDB(provider string, db *sql.DB, postgres bool) (*CloudKMSStore, error) {
	switch provider {
	case "aws", "gcp", "azure":
	default:
		return nil, fmt.Errorf("unsupported KMS provider: %s", provider)
	}
	s := &CloudKMSStore{
		provider: provider,
		db:       db,
		postgres: postgres,
		keys:     make(map[string]*cloudKMSKeyEntry),
	}
	if db != nil {
		if err := s.ensureRefSchema(); err != nil {
			return nil, fmt.Errorf("cloud kms ref table: %w", err)
		}
		if err := s.loadRefsFromDB(); err != nil {
			// S-50 discipline: a failed load must not silently present an
			// empty keystore over a table full of key references.
			return nil, fmt.Errorf("cloud kms refs unloadable: %w", err)
		}
	}
	return s, nil
}

// cloudKMSRefSchema mirrors migration 000037 — stores self-heal (G-33).
const cloudKMSRefSchema = `
CREATE TABLE IF NOT EXISTS cloud_kms_keys (
    id             TEXT PRIMARY KEY,
    provider       TEXT NOT NULL CHECK (provider IN ('aws', 'gcp', 'azure')),
    key_uri        TEXT NOT NULL,
    region         TEXT,
    project_id     TEXT,
    algorithm      TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at     TEXT NOT NULL
);`

func (s *CloudKMSStore) ensureRefSchema() error {
	_, err := s.db.Exec(cloudKMSRefSchema)
	return err
}

func (s *CloudKMSStore) ph(n int) string {
	if s.postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *CloudKMSStore) loadRefsFromDB() error {
	rows, err := s.db.Query(fmt.Sprintf(`SELECT id, key_uri, COALESCE(region,''), COALESCE(project_id,''), algorithm, public_key_pem, created_at
		FROM cloud_kms_keys WHERE provider = %s`, s.ph(1)), s.provider)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, keyURI, region, projectID, algo, pubPEM, createdAt string
		if err := rows.Scan(&id, &keyURI, &region, &projectID, &algo, &pubPEM, &createdAt); err != nil {
			return err
		}
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			log.Printf("cloud kms: key %q has an unparseable stored public key; skipping (it will be missing from the keystore)", id)
			continue
		}
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Printf("cloud kms: key %q public key unparseable: %v; skipping", id, err)
			continue
		}
		s.keys[id] = &cloudKMSKeyEntry{
			meta: KeyMetadata{ID: id, Algorithm: Algorithm(algo), CreatedAt: createdAt},
			config: CloudKMSConfig{
				Provider: s.provider, KeyURI: keyURI, Region: region, ProjectID: projectID,
			},
			pubKey: pubKey,
		}
	}
	return rows.Err()
}

// persistRef writes one entry's reference row. Called after the cloud
// provider has created the key.
func (s *CloudKMSStore) persistRef(id string, entry *cloudKMSKeyEntry) error {
	if s.db == nil {
		return nil
	}
	pubDER, err := x509.MarshalPKIXPublicKey(entry.pubKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	q := fmt.Sprintf(`INSERT INTO cloud_kms_keys (id, provider, key_uri, region, project_id, algorithm, public_key_pem, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8))
	_, err = s.db.Exec(q, id, s.provider, entry.config.KeyURI, entry.config.Region, entry.config.ProjectID,
		string(entry.meta.Algorithm), string(pubPEM), entry.meta.CreatedAt)
	return err
}

func (s *CloudKMSStore) GenerateKey(id string, algo Algorithm) (KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[id]; exists {
		return KeyMetadata{}, ErrKeyExists
	}
	// CLOUD-008: gcp interpolates the id into a query string, azure into a
	// path. AWS uses it only as a Description.
	if s.provider == "gcp" || s.provider == "azure" {
		if err := validateCloudKeyID(id); err != nil {
			return KeyMetadata{}, err
		}
	}

	var meta KeyMetadata
	var err error
	switch s.provider {
	case "aws":
		meta, err = s.generateKeyAWS(id, algo)
	case "gcp":
		meta, err = s.generateKeyGCP(id, algo)
	case "azure":
		meta, err = s.generateKeyAzure(id, algo)
	default:
		return KeyMetadata{}, fmt.Errorf("unsupported KMS provider: %s", s.provider)
	}
	if err != nil {
		return KeyMetadata{}, err
	}
	// W9-02: persist the reference or fail the operation. Succeeding with an
	// unpersisted ref recreates the orphan-on-restart bug this fixes. The
	// cloud key ALREADY EXISTS at this point, so log its URI loudly for
	// manual reaping before reporting failure.
	if entry := s.keys[id]; entry != nil {
		if perr := s.persistRef(id, entry); perr != nil {
			delete(s.keys, id)
			log.Printf("CLOUD KMS KEY ORPHANED: created %s (%s) but its reference could not be persisted — reap it manually: %v",
				entry.config.KeyURI, id, perr)
			return KeyMetadata{}, fmt.Errorf("kms key created (%s) but its reference could not be recorded: %w", entry.config.KeyURI, perr)
		}
	}
	return meta, nil
}

func (s *CloudKMSStore) generateKeyAWS(id string, algo Algorithm) (KeyMetadata, error) {
	keySpec, err := awsKeySpec(algo)
	if err != nil {
		return KeyMetadata{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cloudKMSCallTimeout)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return KeyMetadata{}, fmt.Errorf("aws kms: load config: %w", err)
	}
	client := kms.NewFromConfig(cfg)

	input, err := awsCreateKeyInput(id, keySpec)
	if err != nil {
		return KeyMetadata{}, fmt.Errorf("aws kms: %w", err)
	}
	createOut, err := client.CreateKey(ctx, input)
	if err != nil {
		return KeyMetadata{}, fmt.Errorf("aws kms: create key %s: %w", id, err)
	}
	arn := *createOut.KeyMetadata.Arn

	pubOut, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &arn,
	})
	if err != nil {
		return KeyMetadata{}, fmt.Errorf("aws kms: get public key %s: %w", arn, err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubOut.PublicKey)
	if err != nil {
		return KeyMetadata{}, fmt.Errorf("aws kms: parse public key %s: %w", arn, err)
	}

	meta := KeyMetadata{
		ID:        id,
		Algorithm: algo,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.keys[id] = &cloudKMSKeyEntry{
		meta:   meta,
		pubKey: pubKey,
		config: CloudKMSConfig{
			Provider: s.provider,
			KeyURI:   arn,
		},
	}
	return meta, nil
}

func awsKeySpec(algo Algorithm) (types.KeySpec, error) {
	switch algo {
	case ECDSAP256:
		return types.KeySpecEccNistP256, nil
	case ECDSAP384:
		return types.KeySpecEccNistP384, nil
	case RSA2048:
		return types.KeySpecRsa2048, nil
	case RSA4096:
		return types.KeySpecRsa4096, nil
	default:
		return "", fmt.Errorf("aws kms: unsupported algorithm %s", algo)
	}
}

func (s *CloudKMSStore) Signer(id string) (crypto.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return &CloudKMSSigner{
		config:    entry.config,
		keyID:     id,
		publicKey: entry.pubKey,
	}, nil
}

func (s *CloudKMSStore) PublicKey(id string) (crypto.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return entry.pubKey, nil
}

func (s *CloudKMSStore) Metadata(id string) (KeyMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.keys[id]
	if !ok {
		return KeyMetadata{}, ErrKeyNotFound
	}
	return entry.meta, nil
}

func (s *CloudKMSStore) List() ([]KeyMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]KeyMetadata, 0, len(s.keys))
	for _, entry := range s.keys {
		result = append(result, entry.meta)
	}
	return result, nil
}

func (s *CloudKMSStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keys[id]; !ok {
		return ErrKeyNotFound
	}
	// W9-07: destroy the provider-side key FIRST; only then drop our
	// reference. If the provider refuses, keep the reference — losing the
	// pointer to a live cloud key is the G-34 orphan all over again.
	entry := s.keys[id]
	destroy := s.destroyKey
	if destroy == nil {
		destroy = destroyCloudKey
	}
	if err := destroy(context.Background(), entry.config); err != nil {
		return fmt.Errorf("cloud key destruction refused for %s — reference retained: %w", entry.config.KeyURI, err)
	}
	if s.db != nil {
		q := fmt.Sprintf(`DELETE FROM cloud_kms_keys WHERE id = %s AND provider = %s`, s.ph(1), s.ph(2))
		if _, err := s.db.Exec(q, id, s.provider); err != nil {
			return fmt.Errorf("kms key reference could not be removed: %w", err)
		}
	}
	delete(s.keys, id)
	return nil
}

// Ensure interfaces are satisfied at compile time.
var _ Store = (*CloudKMSStore)(nil)
var _ crypto.Signer = (*CloudKMSSigner)(nil)

// RotateKey is not supported for cloud KMS — key rotation is handled by the KMS provider.
func (s *CloudKMSStore) RotateKey(_ string, _ Algorithm) (KeyRotateResult, error) {
	return KeyRotateResult{}, fmt.Errorf("cloud KMS: key rotation must be performed through the cloud provider console or API")
}

// ExportEncryptedKey is not supported for cloud KMS — private keys never leave the HSM boundary.
func (s *CloudKMSStore) ExportEncryptedKey(_ string, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("cloud KMS: private key export is not permitted — keys are non-extractable")
}

// ImportEncryptedKey is not supported for cloud KMS — use the provider's import key API.
func (s *CloudKMSStore) ImportEncryptedKey(_ string, _ []byte, _ []byte) error {
	return fmt.Errorf("cloud KMS: key import must be performed through the cloud provider API")
}
