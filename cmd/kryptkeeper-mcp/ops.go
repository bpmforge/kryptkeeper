// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"kryptkeeper/internal/mcpserver"
	"kryptkeeper/internal/metrics"
)

// defaultOpsAddr is loopback so nothing is exposed unasked; containers set
// KRYPTKEEPER_OPS_ADDR=0.0.0.0:9102 for kubelet probes.
const defaultOpsAddr = "127.0.0.1:9102"

const opsRoleCacheTTL = 5 * time.Second

type selfRoleChecker interface {
	CheckSelfRole(ctx context.Context) (mcpserver.SelfRole, error)
}

// newOpsConfig reports ready only while the hub is reachable AND this token
// is still non-approver (the boot check can go stale if the role is changed
// hub-side). Results are cached so frequent probes do not hammer the hub.
func newOpsConfig(addr string, hub selfRoleChecker, now func() time.Time) metrics.OpsConfig {
	var (
		mu      sync.Mutex
		at      time.Time
		lastErr error
	)
	return metrics.OpsConfig{
		Addr: addr,
		Ready: func(ctx context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			if !at.IsZero() && now().Sub(at) < opsRoleCacheTTL {
				return lastErr
			}
			self, err := hub.CheckSelfRole(ctx)
			if err == nil && self.CanApproveActions {
				err = errors.New("token role can approve actions")
			}
			at, lastErr = now(), err
			return err
		},
	}
}
