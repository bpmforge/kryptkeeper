// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — OWASP recommended minimum for key derivation.
const (
	argon2Time    = 2         // OWASP minimum for Argon2id at 64MB memory
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32 // AES-256
	saltLen       = 16
	nonceLen      = 12 // AES-GCM standard nonce
)

// signerEntry is a cache entry holding a decrypted signer and its TTL.
type signerEntry struct {
	signer    crypto.Signer
	expiresAt time.Time
}

// SoftwareStore stores encrypted PKCS#8 PEM keys on the filesystem.
type SoftwareStore struct {
	dir        string
	passphrase []byte
	ttl        time.Duration // how long a decrypted signer stays in memory
	mu         sync.RWMutex
	signers    map[string]*signerEntry // cached decrypted signers with TTL
	stopSweep  chan struct{}
}

// defaultSignerTTL is how long a decrypted signer lives in memory before eviction.
// Configurable via KEYSTORE_SIGNER_TTL_MINUTES. Default 60 minutes.
const defaultSignerTTL = 60 * time.Minute

// NewSoftwareStore creates a file-backed key store.
// passphrase is used with Argon2id to derive AES-256 encryption keys.
// dir must exist and should have restrictive permissions (0700).
// Signer TTL is read from KEYSTORE_SIGNER_TTL_MINUTES (default 60).
func NewSoftwareStore(dir string, passphrase []byte) (*SoftwareStore, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("key store directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("key store path is not a directory: %s", dir)
	}

	ttl := defaultSignerTTL
	if raw := strings.TrimSpace(os.Getenv("KEYSTORE_SIGNER_TTL_MINUTES")); raw != "" {
		if mins, err2 := strconv.Atoi(raw); err2 == nil && mins > 0 {
			ttl = time.Duration(mins) * time.Minute
		}
	}

	s := &SoftwareStore{
		dir:        dir,
		passphrase: passphrase,
		ttl:        ttl,
		signers:    make(map[string]*signerEntry),
		stopSweep:  make(chan struct{}),
	}
	go s.sweepLoop()
	return s, nil
}

// sweepLoop runs a background goroutine that evicts expired signer cache entries.
func (s *SoftwareStore) sweepLoop() {
	ticker := time.NewTicker(s.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.evictExpired()
		case <-s.stopSweep:
			return
		}
	}
}

func (s *SoftwareStore) evictExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.signers {
		if now.After(entry.expiresAt) {
			// W9-07: an expired cache entry is the same key material.
			ZeroizeSigner(entry.signer)
			delete(s.signers, id)
		}
	}
}

// EvictSigner forcibly removes a key from the in-memory signer cache.
// The encrypted key file on disk is not affected.
func (s *SoftwareStore) EvictSigner(id string) {
	s.mu.Lock()
	if entry, ok := s.signers[id]; ok {
		ZeroizeSigner(entry.signer) // W9-07
	}
	delete(s.signers, id)
	s.mu.Unlock()
}

// Close stops the background sweep goroutine.
func (s *SoftwareStore) Close() {
	select {
	case <-s.stopSweep:
	default:
		close(s.stopSweep)
	}
}

func (s *SoftwareStore) GenerateKey(id string, algo Algorithm) (KeyMetadata, error) {
	// Hybrid keys generate two component keypairs. We check for an existing
	// hybrid metadata file WITHOUT holding the outer lock so the recursive calls
	// to GenerateKey for each component can acquire the lock independently.
	if isHybrid(algo) {
		if s.isHybridID(id) {
			return KeyMetadata{}, ErrKeyExists
		}
		pair, err := s.generateHybridKey(id, algo)
		if err != nil {
			return KeyMetadata{}, err
		}
		return KeyMetadata{ID: id, Algorithm: pair.Algo, CreatedAt: time.Now().UTC().Format(time.RFC3339)}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.keyPath(id)
	if _, err := os.Stat(path); err == nil {
		return KeyMetadata{}, ErrKeyExists
	}

	// ML-DSA keys use a separate generation and storage path because Go's x509
	// package only supports RSA/ECDSA/Ed25519 for PKCS#8 marshaling.
	if isMLDSA(algo) {
		privBytes, _, signer, err := generateMLDSAKey(rand.Reader, algo)
		if err != nil {
			return KeyMetadata{}, err
		}
		if err := s.encryptAndPersistRaw(id, algo, privBytes); err != nil {
			return KeyMetadata{}, fmt.Errorf("persist ML-DSA key: %w", err)
		}
		s.signers[id] = &signerEntry{signer: signer, expiresAt: time.Now().Add(s.ttl)}
		return KeyMetadata{ID: id, Algorithm: algo, CreatedAt: time.Now().UTC().Format(time.RFC3339)}, nil
	}

	privKey, err := generatePrivateKey(algo)
	if err != nil {
		return KeyMetadata{}, err
	}

	if err := s.encryptAndPersist(id, privKey); err != nil {
		return KeyMetadata{}, fmt.Errorf("persist key: %w", err)
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return KeyMetadata{}, fmt.Errorf("generated key does not implement crypto.Signer")
	}
	s.signers[id] = &signerEntry{signer: signer, expiresAt: time.Now().Add(s.ttl)}

	return KeyMetadata{
		ID:        id,
		Algorithm: algo,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *SoftwareStore) Signer(id string) (crypto.Signer, error) {
	s.mu.RLock()
	if entry, ok := s.signers[id]; ok && time.Now().Before(entry.expiresAt) {
		s.mu.RUnlock()
		return entry.signer, nil
	}
	s.mu.RUnlock()

	// Hybrid keys return the primary (ECDSA) signer.
	// Use LoadHybridKeyPair to get both if needed via separate call.
	if s.isHybridID(id) {
		pair, err := s.loadHybridKeyPair(id)
		if err != nil {
			return nil, err
		}
		return pair.Primary, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock.
	if entry, ok := s.signers[id]; ok && time.Now().Before(entry.expiresAt) {
		return entry.signer, nil
	}

	privKey, err := s.loadAndDecrypt(id)
	if err != nil {
		return nil, err
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key %s does not implement crypto.Signer", id)
	}
	s.signers[id] = &signerEntry{signer: signer, expiresAt: time.Now().Add(s.ttl)}
	return signer, nil
}

// LoadHybridKeyPair returns both signers for a hybrid key.
// Returns ErrKeyNotFound if id is not a hybrid key.
func (s *SoftwareStore) LoadHybridKeyPair(id string) (HybridKeyPair, error) {
	if !s.isHybridID(id) {
		return HybridKeyPair{}, ErrKeyNotFound
	}
	return s.loadHybridKeyPair(id)
}

func (s *SoftwareStore) PublicKey(id string) (crypto.PublicKey, error) {
	signer, err := s.Signer(id)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

func (s *SoftwareStore) Metadata(id string) (KeyMetadata, error) {
	// Hybrid keys use the metadata JSON file.
	if s.isHybridID(id) {
		algo, err := s.hybridMetaAlgo(id)
		if err != nil {
			return KeyMetadata{}, err
		}
		info, _ := os.Stat(s.hybridMetaPath(id))
		createdAt := time.Now().UTC().Format(time.RFC3339)
		if info != nil {
			createdAt = info.ModTime().UTC().Format(time.RFC3339)
		}
		return KeyMetadata{ID: id, Algorithm: algo, CreatedAt: createdAt}, nil
	}

	path := s.keyPath(id)
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return KeyMetadata{}, ErrKeyNotFound
	}
	if err != nil {
		return KeyMetadata{}, err
	}

	algo, err := s.detectAlgorithm(id)
	if err != nil {
		return KeyMetadata{}, err
	}

	return KeyMetadata{
		ID:        id,
		Algorithm: algo,
		CreatedAt: info.ModTime().UTC().Format(time.RFC3339),
	}, nil
}

func (s *SoftwareStore) List() ([]KeyMetadata, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var result []KeyMetadata

	// Include hybrid keys first.
	for _, hybridID := range s.listHybridIDs() {
		meta, err := s.Metadata(hybridID)
		if err != nil {
			continue
		}
		result = append(result, meta)
		seen[hybridID] = true
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key.enc") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".key.enc")
		// Skip component keys of hybrid pairs (e.g. "mykey-primary", "mykey-secondary").
		if strings.HasSuffix(id, "-primary") || strings.HasSuffix(id, "-secondary") {
			continue
		}
		if seen[id] {
			continue
		}
		meta, err := s.Metadata(id)
		if err != nil {
			continue
		}
		result = append(result, meta)
	}
	return result, nil
}

func (s *SoftwareStore) Delete(id string) error {
	// Hybrid delete removes both component keys and the metadata file.
	if s.isHybridID(id) {
		return s.deleteHybridKey(id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.keyPath(id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ErrKeyNotFound
	}
	// W9-07: wipe the cached decrypted signer before dropping the reference —
	// os.Remove alone left live key material in memory for the cache TTL.
	if entry, ok := s.signers[id]; ok {
		ZeroizeSigner(entry.signer)
	}
	delete(s.signers, id)
	return os.Remove(path)
}

// RotateKey generates a new key pair for id, retires the old file as
// {id}-retired-{unix}.key.enc, and persists the new key as {id}.key.enc.
// The signer cache for id is evicted so the next Signer() call loads the new key.
func (s *SoftwareStore) RotateKey(id string, algo Algorithm) (KeyRotateResult, error) {
	if isHybrid(algo) {
		return KeyRotateResult{}, fmt.Errorf("hybrid key rotation not yet supported — rotate each component separately")
	}

	// Retire the existing key file under a timestamped name.
	currentPath := s.keyPath(id)
	retiredID := fmt.Sprintf("%s-retired-%d", filepath.Base(id), time.Now().UnixMilli())
	retiredPath := filepath.Join(s.dir, retiredID+".key.enc")

	s.mu.Lock()

	if _, err := os.Stat(currentPath); os.IsNotExist(err) {
		s.mu.Unlock()
		return KeyRotateResult{}, ErrKeyNotFound
	}

	if err := os.Rename(currentPath, retiredPath); err != nil {
		s.mu.Unlock()
		return KeyRotateResult{}, fmt.Errorf("retire old key: %w", err)
	}

	// Evict the old signer from cache.
	delete(s.signers, id)
	s.mu.Unlock()

	// Generate the new key (reuses the normal generation path which acquires its own lock).
	meta, err := s.GenerateKey(id, algo)
	if err != nil {
		// Attempt rollback: restore retired file.
		_ = os.Rename(retiredPath, currentPath) // best-effort rollback restore; generate error above is already returned
		return KeyRotateResult{}, fmt.Errorf("generate new key: %w", err)
	}

	return KeyRotateResult{New: meta, PreviousID: retiredID}, nil
}

// ExportEncryptedKey re-encrypts the key's private bytes under backupPassphrase
// (a separate Argon2id + AES-256-GCM envelope) and returns the PEM bytes. RSA/
// ECDSA/Ed25519 keys are marshaled as PKCS#8; ML-DSA keys use their own raw
// MarshalBinary form (x509.MarshalPKCS8PrivateKey rejects them — W9-03/G-31).
// A hybrid ID has no single private key of its own (see hybrid.go) — both
// components are exported and concatenated behind a hybrid-meta PEM block.
// The passphrase is never stored — the caller must keep it safe.
func (s *SoftwareStore) ExportEncryptedKey(id string, backupPassphrase []byte) ([]byte, error) {
	if len(backupPassphrase) == 0 {
		return nil, fmt.Errorf("backup passphrase must not be empty")
	}

	if s.isHybridID(id) {
		return s.exportHybridEncryptedKey(id, backupPassphrase)
	}

	// Decrypt with the store passphrase.
	s.mu.Lock()
	privKey, err := s.loadAndDecrypt(id)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}

	return s.exportSingleEncryptedKey(id, privKey, backupPassphrase)
}

// exportSingleEncryptedKey marshals one already-decrypted private key (never a
// hybrid composite) and wraps it in the backup passphrase envelope.
func (s *SoftwareStore) exportSingleEncryptedKey(id string, privKey crypto.PrivateKey, backupPassphrase []byte) ([]byte, error) {
	if algo, raw, ok := marshalMLDSAPrivateKey(privKey); ok {
		return encryptForBackup("KRYPTKEEPER BACKUP MLDSA KEY", map[string]string{"Algo": string(algo)}, id, raw, backupPassphrase)
	}

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("export marshal: %w", err)
	}
	return encryptForBackup("KRYPTKEEPER BACKUP KEY", nil, id, pkcs8DER, backupPassphrase)
}

// encryptForBackup wraps plaintext key bytes in the Argon2id + AES-256-GCM
// backup envelope shared by every exported key type (classical and ML-DSA).
func encryptForBackup(pemType string, extraHeaders map[string]string, id string, plaintext []byte, backupPassphrase []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("export salt: %w", err)
	}
	derivedKey := argon2.IDKey(backupPassphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("export cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("export gcm: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("export nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	headers := map[string]string{
		"Key-ID": id,
		"Salt":   fmt.Sprintf("%x", salt),
		"Nonce":  fmt.Sprintf("%x", nonce),
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}

	pemBlock := &pem.Block{Type: pemType, Headers: headers, Bytes: ciphertext}
	return pem.EncodeToMemory(pemBlock), nil
}

// decryptBackupBlock reverses encryptForBackup and reconstructs the private
// key, dispatching on the PEM block type set at export time.
func decryptBackupBlock(pemBlock *pem.Block, backupPassphrase []byte) (crypto.PrivateKey, error) {
	saltHex, ok := pemBlock.Headers["Salt"]
	if !ok {
		return nil, fmt.Errorf("missing Salt header in backup PEM")
	}
	nonceHex, ok := pemBlock.Headers["Nonce"]
	if !ok {
		return nil, fmt.Errorf("missing Nonce header in backup PEM")
	}
	salt, err := hexDecode(saltHex, saltLen)
	if err != nil {
		return nil, fmt.Errorf("decode backup salt: %w", err)
	}
	nonce, err := hexDecode(nonceHex, nonceLen)
	if err != nil {
		return nil, fmt.Errorf("decode backup nonce: %w", err)
	}

	derivedKey := argon2.IDKey(backupPassphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("import cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("import gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, pemBlock.Bytes, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	switch pemBlock.Type {
	case "KRYPTKEEPER BACKUP KEY":
		privKey, err := x509.ParsePKCS8PrivateKey(plaintext)
		if err != nil {
			return nil, fmt.Errorf("import parse PKCS#8: %w", err)
		}
		return privKey, nil
	case "KRYPTKEEPER BACKUP MLDSA KEY":
		algo := Algorithm(pemBlock.Headers["Algo"])
		signer, err := reconstructMLDSASigner(algo, plaintext)
		if err != nil {
			return nil, fmt.Errorf("import reconstruct ML-DSA key: %w", err)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported backup key type: %s", pemBlock.Type)
	}
}

// ImportEncryptedKey decrypts a backup PEM envelope and stores the key under
// id. A hybrid-meta PEM block (see exportHybridEncryptedKey) is expanded back
// into two component keys plus the hybrid metadata sidecar.
func (s *SoftwareStore) ImportEncryptedKey(id string, data []byte, backupPassphrase []byte) error {
	if len(backupPassphrase) == 0 {
		return fmt.Errorf("backup passphrase must not be empty")
	}

	pemBlock, rest := pem.Decode(data)
	if pemBlock == nil {
		return fmt.Errorf("invalid backup PEM data")
	}

	if pemBlock.Type == "KRYPTKEEPER BACKUP HYBRID META" {
		return s.importHybridEncryptedKey(id, pemBlock, rest, backupPassphrase)
	}

	privKey, err := decryptBackupBlock(pemBlock, backupPassphrase)
	if err != nil {
		return err
	}
	return s.persistImportedSingleKey(id, privKey)
}

// persistImportedSingleKey stores an already-decrypted, already-reconstructed
// private key under id (never a hybrid composite), refusing if id is taken —
// mirrors GenerateKey's own classical/ML-DSA persistence branch.
func (s *SoftwareStore) persistImportedSingleKey(id string, privKey crypto.PrivateKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	destPath := s.keyPath(id)
	if _, err := os.Stat(destPath); err == nil {
		return ErrKeyExists
	}

	if algo, raw, ok := marshalMLDSAPrivateKey(privKey); ok {
		if err := s.encryptAndPersistRaw(id, algo, raw); err != nil {
			return fmt.Errorf("import persist: %w", err)
		}
	} else if err := s.encryptAndPersist(id, privKey); err != nil {
		return fmt.Errorf("import persist: %w", err)
	}

	if signer, ok := privKey.(crypto.Signer); ok {
		s.signers[id] = &signerEntry{signer: signer, expiresAt: time.Now().Add(s.ttl)}
	}
	return nil
}

func (s *SoftwareStore) keyPath(id string) string {
	// Sanitize ID to prevent path traversal.
	safe := filepath.Base(id)
	return filepath.Join(s.dir, safe+".key.enc")
}

func (s *SoftwareStore) detectAlgorithm(id string) (Algorithm, error) {
	// For ML-DSA keys, detect algorithm from PEM type without full decryption.
	path := s.keyPath(id)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", ErrKeyNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read key file: %w", err)
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock != nil {
		if algo, ok := mldsaAlgoFromPEMType(pemBlock.Type); ok {
			return algo, nil
		}
	}

	// Metadata is called on every issuance; decrypting here costs one Argon2id
	// run (64 MiB). A cached signer already carries the public key, so use it.
	s.mu.RLock()
	entry, cached := s.signers[id]
	s.mu.RUnlock()
	if cached && time.Now().Before(entry.expiresAt) {
		return algorithmOfPublicKey(entry.signer.Public())
	}

	privKey, err := s.loadAndDecrypt(id)
	if err != nil {
		return "", err
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("unknown key type %T", privKey)
	}
	return algorithmOfPublicKey(signer.Public())
}

func algorithmOfPublicKey(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() <= 2048 {
			return RSA2048, nil
		}
		return RSA4096, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return ECDSAP256, nil
		case elliptic.P384():
			return ECDSAP384, nil
		}
		return "", fmt.Errorf("unsupported ECDSA curve")
	case ed25519.PublicKey:
		return Ed25519, nil
	default:
		return "", fmt.Errorf("unknown key type %T", pub)
	}
}

// encryptAndPersist serializes the private key as PKCS#8, encrypts with
// Argon2id-derived AES-256-GCM, and writes to disk with 0600 permissions.
//
// File format: PEM block with type "ENCRYPTED PRIVATE KEY"
// Headers: Salt (hex), Nonce (hex)
// Body: AES-256-GCM ciphertext of DER-encoded PKCS#8
func (s *SoftwareStore) encryptAndPersist(id string, privKey crypto.PrivateKey) error {
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal PKCS#8: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	derivedKey := argon2.IDKey(s.passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, pkcs8DER, nil)

	pemBlock := &pem.Block{
		Type: "ENCRYPTED PRIVATE KEY",
		Headers: map[string]string{
			"Salt":  fmt.Sprintf("%x", salt),
			"Nonce": fmt.Sprintf("%x", nonce),
		},
		Bytes: ciphertext,
	}

	path := s.keyPath(id)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	_, writeErr := f.Write(pem.EncodeToMemory(pemBlock))
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// loadAndDecrypt reads an encrypted PEM key file and decrypts it.
func (s *SoftwareStore) loadAndDecrypt(id string) (crypto.PrivateKey, error) {
	path := s.keyPath(id)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("invalid PEM data for key %s", id)
	}

	// ML-DSA keys are stored with algorithm-specific PEM types.
	if algo, ok := mldsaAlgoFromPEMType(pemBlock.Type); ok {
		rawBytes, err := s.decryptRawBytes(pemBlock)
		if err != nil {
			return nil, err
		}
		return reconstructMLDSASigner(algo, rawBytes)
	}

	if pemBlock.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", pemBlock.Type)
	}

	saltHex, ok := pemBlock.Headers["Salt"]
	if !ok {
		return nil, fmt.Errorf("missing Salt header in key %s", id)
	}
	nonceHex, ok := pemBlock.Headers["Nonce"]
	if !ok {
		return nil, fmt.Errorf("missing Nonce header in key %s", id)
	}

	salt, err := hexDecode(saltHex, saltLen)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := hexDecode(nonceHex, nonceLen)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	derivedKey := argon2.IDKey(s.passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, pemBlock.Bytes, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	privKey, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}

	return privKey, nil
}

// encryptAndPersistRaw encrypts raw key bytes (used for ML-DSA keys) with
// the same AES-256-GCM + Argon2id scheme as encryptAndPersist but skips PKCS#8.
// The algorithm is encoded in the PEM block type for later identification.
func (s *SoftwareStore) encryptAndPersistRaw(id string, algo Algorithm, rawBytes []byte) error {
	pemType, ok := mldsaPEMTypeForAlgo(algo)
	if !ok {
		return fmt.Errorf("no PEM type for algorithm %s", algo)
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	derivedKey := argon2.IDKey(s.passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, rawBytes, nil)

	pemBlock := &pem.Block{
		Type: pemType,
		Headers: map[string]string{
			"Salt":  fmt.Sprintf("%x", salt),
			"Nonce": fmt.Sprintf("%x", nonce),
		},
		Bytes: ciphertext,
	}

	path := s.keyPath(id)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	_, writeErr := f.Write(pem.EncodeToMemory(pemBlock))
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// decryptRawBytes decrypts an ML-DSA PEM block and returns the raw key bytes.
func (s *SoftwareStore) decryptRawBytes(pemBlock *pem.Block) ([]byte, error) {
	saltHex, ok := pemBlock.Headers["Salt"]
	if !ok {
		return nil, fmt.Errorf("missing Salt header")
	}
	nonceHex, ok := pemBlock.Headers["Nonce"]
	if !ok {
		return nil, fmt.Errorf("missing Nonce header")
	}

	salt, err := hexDecode(saltHex, saltLen)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := hexDecode(nonceHex, nonceLen)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	derivedKey := argon2.IDKey(s.passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, pemBlock.Bytes, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func generatePrivateKey(algo Algorithm) (crypto.PrivateKey, error) {
	switch algo {
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, ErrUnsupportedAlgo
	}
}

func hexDecode(s string, expectedLen int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) != expectedLen {
		return nil, fmt.Errorf("hex decode: expected %d bytes, got %d", expectedLen, len(b))
	}
	return b, nil
}
