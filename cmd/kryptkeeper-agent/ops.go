// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/metrics"
)

// defaultOpsAddr is loopback so nothing is exposed unasked; containers set
// KRYPTKEEPER_OPS_ADDR=0.0.0.0:9101 for kubelet probes.
const defaultOpsAddr = "127.0.0.1:9101"

// lastHeartbeatOK is the unix time of the last successful hub heartbeat
// (0 = none yet).
var lastHeartbeatOK atomic.Int64

// newOpsConfig makes the agent ready while heartbeats keep succeeding: one
// missed poll plus slack still counts as healthy, three do not.
func newOpsConfig(addr string, pollInterval time.Duration, now func() time.Time) metrics.OpsConfig {
	return metrics.OpsConfig{
		Addr: addr,
		Ready: func(context.Context) error {
			last := lastHeartbeatOK.Load()
			if last == 0 {
				return errors.New("no successful heartbeat yet")
			}
			if age := now().Sub(time.Unix(last, 0)); age > 3*pollInterval+time.Minute {
				return errors.New("last successful heartbeat is stale")
			}
			return nil
		},
	}
}
