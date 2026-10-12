// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import "sync"

// Store persists ACME server state (accounts, orders, authorizations, certificates)
// so that in-flight orders survive a process restart.
type Store interface {
	SaveAccount(acct *Account) error
	LoadAccount(id string) (*Account, bool)
	ListAccounts() []*Account

	SaveOrder(order *Order) error
	LoadOrder(id string) (*Order, bool)
	ListOrders() []*Order

	SaveAuthz(authz *Authorization) error
	LoadAuthz(id string) (*Authorization, bool)

	SaveCert(id string, pem []byte) error
	LoadCert(id string) ([]byte, bool)

	// SaveEABKey upserts an External Account Binding MAC key (W4-04).
	SaveEABKey(key *EABKey) error
	// LoadEABKey looks up an EAB key by kid; satisfies eabKeyLookup.
	LoadEABKey(kid string) (*EABKey, bool)
	// BindAccountEAB records which EAB kid a newly created account presented.
	BindAccountEAB(accountID, kid string) error
}

// MemStore is an in-process, non-persistent Store implementation.
type MemStore struct {
	mu         sync.RWMutex
	accounts   map[string]*Account
	orders     map[string]*Order
	authzs     map[string]*Authorization
	certs      map[string][]byte
	eabKeys    map[string]*EABKey
	accountEAB map[string]string
}

// NewMemStore returns an empty in-memory ACME store.
func NewMemStore() *MemStore {
	return &MemStore{
		accounts:   make(map[string]*Account),
		orders:     make(map[string]*Order),
		authzs:     make(map[string]*Authorization),
		certs:      make(map[string][]byte),
		eabKeys:    make(map[string]*EABKey),
		accountEAB: make(map[string]string),
	}
}

func (s *MemStore) SaveAccount(acct *Account) error {
	s.mu.Lock()
	s.accounts[acct.ID] = acct
	s.mu.Unlock()
	return nil
}

func (s *MemStore) LoadAccount(id string) (*Account, bool) {
	s.mu.RLock()
	a, ok := s.accounts[id]
	s.mu.RUnlock()
	return a, ok
}

func (s *MemStore) ListAccounts() []*Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, a)
	}
	return out
}

func (s *MemStore) SaveOrder(order *Order) error {
	s.mu.Lock()
	s.orders[order.ID] = order
	s.mu.Unlock()
	return nil
}

func (s *MemStore) LoadOrder(id string) (*Order, bool) {
	s.mu.RLock()
	o, ok := s.orders[id]
	s.mu.RUnlock()
	return o, ok
}

func (s *MemStore) ListOrders() []*Order {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Order, 0, len(s.orders))
	for _, o := range s.orders {
		out = append(out, o)
	}
	return out
}

func (s *MemStore) SaveAuthz(authz *Authorization) error {
	s.mu.Lock()
	s.authzs[authz.ID] = authz
	s.mu.Unlock()
	return nil
}

func (s *MemStore) LoadAuthz(id string) (*Authorization, bool) {
	s.mu.RLock()
	a, ok := s.authzs[id]
	s.mu.RUnlock()
	return a, ok
}

func (s *MemStore) SaveCert(id string, pemBytes []byte) error {
	s.mu.Lock()
	s.certs[id] = pemBytes
	s.mu.Unlock()
	return nil
}

func (s *MemStore) LoadCert(id string) ([]byte, bool) {
	s.mu.RLock()
	p, ok := s.certs[id]
	s.mu.RUnlock()
	return p, ok
}

func (s *MemStore) SaveEABKey(key *EABKey) error {
	s.mu.Lock()
	stored := *key
	s.eabKeys[key.KID] = &stored
	s.mu.Unlock()
	return nil
}

func (s *MemStore) LoadEABKey(kid string) (*EABKey, bool) {
	s.mu.RLock()
	k, ok := s.eabKeys[kid]
	s.mu.RUnlock()
	return k, ok
}

func (s *MemStore) BindAccountEAB(accountID, kid string) error {
	s.mu.Lock()
	s.accountEAB[accountID] = kid
	s.mu.Unlock()
	return nil
}

// Ensure interface is satisfied.
var _ Store = (*MemStore)(nil)
