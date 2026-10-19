// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Router fronts several Store backends so one hub can keep software, PKCS#11
// and KMS CA keys side by side (W23-11). Labels use the env vocabulary
// (software, pkcs11, vault, cloudkms) because that is what
// CheckHSMPQCSupport and CheckRootKeyCustody key on.
type Router struct {
	mu       sync.Mutex
	createMu sync.Mutex

	backends map[string]Store
	def      string
	assign   map[string]string
	resolve  func(keyID string) (string, bool)

	createLabel string
}

// NewRouter builds a Router. def "" means "software".
func NewRouter(def string, backends map[string]Store) (*Router, error) {
	if def == "" {
		def = "software"
	}
	if _, ok := backends[def]; !ok {
		return nil, fmt.Errorf("default key backend %q is not among the configured backends", def)
	}
	m := make(map[string]Store, len(backends))
	for k, v := range backends {
		m[k] = v
	}
	return &Router{backends: m, def: def, assign: make(map[string]string)}, nil
}

// BackendLabelFromStorageType converts the canonical CA/API vocabulary to the
// env vocabulary. Returning "cloud_kms" instead of "cloudkms" would silently
// disable the PQC-on-HSM refusal.
func BackendLabelFromStorageType(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "cloud_kms", "cloud-kms", "cloudkms":
		return "cloudkms"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

// Backends returns the enabled labels, sorted.
func (r *Router) Backends() []string {
	out := make([]string, 0, len(r.backends))
	for k := range r.backends {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SetResolver installs the post-restart key-to-backend lookup (built from CA
// rows). It must be set before anything reads keys, or every non-default CA
// key reports as missing.
func (r *Router) SetResolver(fn func(keyID string) (string, bool)) {
	r.mu.Lock()
	r.resolve = fn
	r.mu.Unlock()
}

// WithCreateBackend runs fn with key generation pinned to label. It holds
// createMu for the whole call, so creates are serialised; never nest calls.
func (r *Router) WithCreateBackend(label string, fn func() error) error {
	label = BackendLabelFromStorageType(label)
	if _, ok := r.backends[label]; !ok {
		return fmt.Errorf("key backend %q is not enabled on this hub (enabled: %s)", label, strings.Join(r.Backends(), ", "))
	}
	r.createMu.Lock()
	defer r.createMu.Unlock()
	r.mu.Lock()
	r.createLabel = label
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.createLabel = ""
		r.mu.Unlock()
	}()
	return fn()
}

// CurrentBackendLabel is the backend a create in flight targets, else the default.
func (r *Router) CurrentBackendLabel() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createLabel != "" {
		return r.createLabel
	}
	return r.def
}

func (r *Router) storeFor(id string) Store {
	r.mu.Lock()
	label, ok := r.assign[id]
	resolve := r.resolve
	r.mu.Unlock()
	if !ok && resolve != nil {
		if l, found := resolve(id); found {
			label, ok = BackendLabelFromStorageType(l), true
		}
	}
	if s, found := r.backends[label]; ok && found {
		return s
	}
	// A rotated-out key lives beside its parent as "<id>-retired-<ts>" and
	// must stay on the same backend as that parent.
	if i := strings.Index(id, "-retired-"); i > 0 {
		return r.storeFor(id[:i])
	}
	return r.backends[r.def]
}

func (r *Router) GenerateKey(id string, algo Algorithm) (KeyMetadata, error) {
	label := r.CurrentBackendLabel()
	md, err := r.backends[label].GenerateKey(id, algo)
	if err != nil {
		return md, err
	}
	r.mu.Lock()
	r.assign[id] = label
	r.mu.Unlock()
	return md, nil
}

func (r *Router) Signer(id string) (crypto.Signer, error)       { return r.storeFor(id).Signer(id) }
func (r *Router) PublicKey(id string) (crypto.PublicKey, error) { return r.storeFor(id).PublicKey(id) }
func (r *Router) Metadata(id string) (KeyMetadata, error)       { return r.storeFor(id).Metadata(id) }

func (r *Router) Delete(id string) error {
	if err := r.storeFor(id).Delete(id); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.assign, id)
	r.mu.Unlock()
	return nil
}

func (r *Router) RotateKey(id string, algo Algorithm) (KeyRotateResult, error) {
	return r.storeFor(id).RotateKey(id, algo)
}

func (r *Router) ExportEncryptedKey(id string, pass []byte) ([]byte, error) {
	return r.storeFor(id).ExportEncryptedKey(id, pass)
}

// ImportEncryptedKey always lands on the default backend, as before routing.
func (r *Router) ImportEncryptedKey(id string, data, pass []byte) error {
	if err := r.backends[r.def].ImportEncryptedKey(id, data, pass); err != nil {
		return err
	}
	r.mu.Lock()
	r.assign[id] = r.def
	r.mu.Unlock()
	return nil
}

// List concatenates every backend's keys, de-duplicated by ID, in stable order.
func (r *Router) List() ([]KeyMetadata, error) {
	var out []KeyMetadata
	seen := make(map[string]bool)
	labels := r.Backends()
	// default first so a shared ID reports its default-backend metadata
	sort.SliceStable(labels, func(i, j int) bool { return labels[i] == r.def && labels[j] != r.def })
	for _, l := range labels {
		items, err := r.backends[l].List()
		if err != nil {
			return nil, fmt.Errorf("list %s keys: %w", l, err)
		}
		for _, m := range items {
			if !seen[m.ID] {
				seen[m.ID] = true
				out = append(out, m)
			}
		}
	}
	return out, nil
}

// LoadHybridKeyPair forwards to the owning backend when it supports hybrids.
func (r *Router) LoadHybridKeyPair(id string) (HybridKeyPair, error) {
	if hl, ok := r.storeFor(id).(HybridKeyLoader); ok {
		return hl.LoadHybridKeyPair(id)
	}
	return HybridKeyPair{}, ErrUnsupportedAlgo
}

// Close closes every backend that exposes a Close method.
func (r *Router) Close() error {
	var errs []error
	for _, s := range r.backends {
		switch c := s.(type) {
		case interface{ Close() error }:
			errs = append(errs, c.Close())
		case interface{ Close() }:
			c.Close()
		}
	}
	return errors.Join(errs...)
}
