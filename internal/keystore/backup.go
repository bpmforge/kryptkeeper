// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// backupSchemaVersion is bumped whenever the bundle's JSON shape changes in
// a way RestoreAll needs to know about.
const backupSchemaVersion = 1

// BackupKeyStatus records what happened to a single key during BackupAll.
type BackupKeyStatus string

const (
	BackupKeyExported              BackupKeyStatus = "exported"
	BackupKeySkippedNonExtractable BackupKeyStatus = "skipped_non_extractable"
	BackupKeyError                 BackupKeyStatus = "error"
)

// BackupKeyEntry is one key's outcome in a Bundle.
type BackupKeyEntry struct {
	ID        string          `json:"id"`
	Algorithm Algorithm       `json:"algorithm,omitempty"`
	Status    BackupKeyStatus `json:"status"`
	PEM       string          `json:"pem,omitempty"`   // present only when Status == exported
	Error     string          `json:"error,omitempty"` // present only when Status == error
}

// Bundle is the JSON-serializable shape BackupAll produces and RestoreAll
// consumes.
type Bundle struct {
	SchemaVersion int              `json:"schema_version"`
	CreatedAt     string           `json:"created_at"`
	Keys          []BackupKeyEntry `json:"keys"`
}

// BackupAll exports every key in store under backupPassphrase and returns
// the JSON-encoded bundle. It is best-effort per key: a key backed by a
// non-extractable backend (PKCS#11/HSM, cloud KMS, Vault transit) or one
// that otherwise fails to export is recorded in the bundle with its status
// and error rather than aborting the whole backup — an operator can inspect
// the bundle for skipped/errored keys and fall back to the documented
// non-extractable-backend DR path (back up the DB + the key reference; the
// key itself stays in the HSM/KMS). BackupAll only returns a non-nil error
// when the store itself cannot be enumerated at all (store.List fails).
func BackupAll(store Store, backupPassphrase []byte) ([]byte, error) {
	metas, err := store.List()
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	bundle := Bundle{
		SchemaVersion: backupSchemaVersion,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		Keys:          make([]BackupKeyEntry, 0, len(metas)),
	}
	for _, m := range metas {
		pemBytes, err := store.ExportEncryptedKey(m.ID, backupPassphrase)
		switch {
		case err == nil:
			bundle.Keys = append(bundle.Keys, BackupKeyEntry{
				ID:        m.ID,
				Algorithm: m.Algorithm,
				Status:    BackupKeyExported,
				PEM:       string(pemBytes),
			})
		case isNonExtractableBackendError(err):
			bundle.Keys = append(bundle.Keys, BackupKeyEntry{
				ID:        m.ID,
				Algorithm: m.Algorithm,
				Status:    BackupKeySkippedNonExtractable,
				Error:     err.Error(),
			})
		default:
			bundle.Keys = append(bundle.Keys, BackupKeyEntry{
				ID:        m.ID,
				Algorithm: m.Algorithm,
				Status:    BackupKeyError,
				Error:     err.Error(),
			})
		}
	}

	out, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshal backup bundle: %w", err)
	}
	return out, nil
}

// isNonExtractableBackendError reports whether err is one of the fixed
// "keys are non-extractable" errors returned by PKCS11Store, CloudKMSStore,
// or VaultStore's ExportEncryptedKey — a known, documented DR limitation,
// not an unexpected failure.
func isNonExtractableBackendError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "non-extractable") || strings.Contains(msg, "not permitted")
}

// RestoreAll re-imports every exported key in a Bundle (as produced by
// BackupAll) into store under backupPassphrase. Keys recorded as skipped or
// errored in the bundle are not attempted (there is nothing to import).
// RestoreAll is best-effort: it attempts every exported key even if an
// earlier one fails, and returns the count that succeeded alongside a
// combined error describing every failure (nil if all succeeded).
func RestoreAll(store Store, bundle []byte, backupPassphrase []byte) (imported int, err error) {
	var b Bundle
	if err := json.Unmarshal(bundle, &b); err != nil {
		return 0, fmt.Errorf("parse backup bundle: %w", err)
	}

	var errs []error
	for _, k := range b.Keys {
		if k.Status != BackupKeyExported {
			continue
		}
		if importErr := store.ImportEncryptedKey(k.ID, []byte(k.PEM), backupPassphrase); importErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k.ID, importErr))
			continue
		}
		imported++
	}
	return imported, errors.Join(errs...)
}
