// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"sync/atomic"

	"kryptkeeper/internal/metrics"
)

// defaultOpsAddr is loopback so nothing is exposed unasked; containers set
// KRYPTKEEPER_OPS_ADDR=0.0.0.0:9103 for kubelet probes.
const defaultOpsAddr = "127.0.0.1:9103"

// ready is true only while the controller loop is running.
var ready atomic.Bool

func newOpsConfig(addr string) metrics.OpsConfig {
	return metrics.OpsConfig{
		Addr: addr,
		Ready: func(context.Context) error {
			if !ready.Load() {
				return errors.New("controller not running")
			}
			return nil
		},
	}
}
