// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"sync"
	"time"

	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/intune"
)

// SCEPCredentialLookup is the part of the outbound credential store the SCEP
// label API needs: metadata only, never a secret.
type SCEPCredentialLookup interface {
	Get(ctx context.Context, id string) (OutboundCredentialMeta, error)
}

// lazyOutboundCredentials opens the encrypted credential store on first use,
// so a hub without a credential passphrase still starts; Resolve then fails
// closed (the same shape as the ITSM resolver).
type lazyOutboundCredentials struct {
	once  sync.Once
	store OutboundCredentialStore
}

func (l *lazyOutboundCredentials) open() (OutboundCredentialStore, error) {
	l.once.Do(func() { l.store = newOutboundCredentialStoreFromEnv() })
	if l.store == nil {
		return nil, errors.New("outbound credential store not configured")
	}
	return l.store, nil
}

func (l *lazyOutboundCredentials) Get(ctx context.Context, id string) (OutboundCredentialMeta, error) {
	s, err := l.open()
	if err != nil {
		return OutboundCredentialMeta{}, err
	}
	return s.Get(ctx, id)
}

func (l *lazyOutboundCredentials) resolve(ctx context.Context, id string) ([]byte, error) {
	s, err := l.open()
	if err != nil {
		return nil, err
	}
	return s.Resolve(ctx, id)
}

// NewSCEPIntune builds the Intune client the SCEP labels use and the credential
// lookup the label API validates against (W20-23, D-327). Calls to Entra, Graph
// and the Intune service go through the egress guard, https only: those hosts
// are public, so nothing here relaxes the address policy.
func NewSCEPIntune(userAgent string) (*intune.Manager, SCEPCredentialLookup, error) {
	creds := &lazyOutboundCredentials{}
	mgr, err := intune.NewManager(intune.Options{
		HTTP:      egress.NewClient(egress.PolicyFromEnv(egress.Policy{RequireHTTPS: true, Timeout: 20 * time.Second})),
		Resolve:   creds.resolve,
		UserAgent: userAgent,
	})
	return mgr, creds, err
}
