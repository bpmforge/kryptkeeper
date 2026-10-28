// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"sync"
	"time"
)

// KeyRotation is one row in the ca_key_rotations ledger (W9-04/G-35).
type KeyRotation struct {
	ID        string
	CAID      string
	OldKeyID  string
	NewKeyID  string
	NewCertSN string
	Method    string // "rekey_reissue" | "cross_sign"
	RotatedAt time.Time
	// OldCertPEM is the CA certificate the retired key signed under (W23-19),
	// so OCSP can answer for certificates issued before the rotation. Empty
	// on rows written before migration 000129.
	OldCertPEM []byte
}

// Store persists and retrieves CA metadata and certificates.
// Implementations must be safe for concurrent use.
type Store interface {
	// Save inserts or replaces a CA record.
	Save(ca *CA) error
	// Load retrieves a CA by ID. Returns ErrCANotFound if absent.
	Load(id string) (*CA, error)
	// List returns all stored CAs.
	List() ([]*CA, error)
	// UpdateStatus changes the status field for the given CA ID.
	UpdateStatus(id, status string) error
	// RecordKeyRotation appends a row to the CA key-rotation ledger.
	RecordKeyRotation(r KeyRotation) error
	// ListKeyRotations returns the rotation history for a CA, newest first.
	ListKeyRotations(caID string) ([]KeyRotation, error)
}

// CADeleter is an optional Store capability (kept off Store so existing test
// doubles need not implement it).
type CADeleter interface {
	// Delete removes a CA record. Returns ErrCANotFound if absent.
	Delete(id string) error
}

// MemStore is a thread-safe in-memory Store suitable for tests and
// as the default when no DB is configured.
type MemStore struct {
	mu        sync.RWMutex
	data      map[string]*CA
	rotations []KeyRotation
}

func NewMemStore() *MemStore {
	return &MemStore{data: make(map[string]*CA)}
}

func (s *MemStore) Save(ca *CA) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := cloneCA(ca)
	s.data[ca.ID] = &clone
	return nil
}

func (s *MemStore) Load(id string) (*CA, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ca, ok := s.data[id]
	if !ok {
		return nil, ErrCANotFound
	}
	clone := cloneCA(ca)
	return &clone, nil
}

func (s *MemStore) List() ([]*CA, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*CA, 0, len(s.data))
	for _, ca := range s.data {
		clone := cloneCA(ca)
		result = append(result, &clone)
	}
	return result, nil
}

// cloneCA copies the struct and the slice it owns, so a caller mutating the
// returned CA's CRL list cannot reach the stored one.
func cloneCA(c *CA) CA {
	clone := *c
	clone.CRLDistributionPoints = append([]string(nil), c.CRLDistributionPoints...)
	return clone
}

func (s *MemStore) UpdateStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ca, ok := s.data[id]
	if !ok {
		return ErrCANotFound
	}
	ca.Status = status
	return nil
}

func (s *MemStore) RecordKeyRotation(r KeyRotation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotations = append(s.rotations, r)
	return nil
}

func (s *MemStore) ListKeyRotations(caID string) ([]KeyRotation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []KeyRotation
	for i := len(s.rotations) - 1; i >= 0; i-- {
		if s.rotations[i].CAID == caID {
			result = append(result, s.rotations[i])
		}
	}
	return result, nil
}

func (s *MemStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; !ok {
		return ErrCANotFound
	}
	delete(s.data, id)
	return nil
}
