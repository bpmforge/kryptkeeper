// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type fileUserProvider struct {
	mu    sync.Mutex
	users []UserRecord
}

func (p *fileUserProvider) seed() []UserRecord {
	return []UserRecord{}
}

func (p *fileUserProvider) ListUsers(_ context.Context) ([]UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.users) == 0 {
		p.users = p.seed()
	}
	out := make([]UserRecord, len(p.users))
	copy(out, p.users)
	return out, nil
}

func (p *fileUserProvider) InviteUser(_ context.Context, email string, role string) (UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.users) == 0 {
		p.users = p.seed()
	}
	now := time.Now().UTC()
	u := UserRecord{
		ID:        fmt.Sprintf("user-%d", now.UnixNano()),
		Email:     email,
		Role:      role,
		Status:    "invited",
		CreatedAt: now.Format(time.RFC3339),
	}
	p.users = append(p.users, u)
	return u, nil
}

func (p *fileUserProvider) UpdateUser(_ context.Context, id string, role string, status string) (UserRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.users) == 0 {
		p.users = p.seed()
	}
	for i, u := range p.users {
		if u.ID == id {
			if role != "" {
				p.users[i].Role = role
			}
			if status != "" {
				p.users[i].Status = status
			}
			return p.users[i], nil
		}
	}
	return UserRecord{}, fmt.Errorf("user %q not found", id)
}

func (p *fileUserProvider) DeactivateUser(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.users) == 0 {
		p.users = p.seed()
	}
	for i, u := range p.users {
		if u.ID == id {
			p.users[i].Status = "deactivated"
			return nil
		}
	}
	return fmt.Errorf("user %q not found", id)
}
