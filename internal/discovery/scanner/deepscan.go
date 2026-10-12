// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// Deep scan: our own TCP-connect port sweep — the "slow, in-depth" mode.
// Unlike the catalogue sweep (a fixed list of known cert/key ports), a deep
// scan finds EVERY open TCP port on a host, then runs the normal
// protocol-aware capture on each one, so a cert or SSH key on an unexpected
// port is still found. It is a connect() scan, not a raw-socket SYN scan:
// unprivileged, portable, and honest about what it sees (a full 3-way
// handshake), at the cost of being slower and more visible than nmap's
// half-open default. No external dependency — this is the product's own
// code.

const (
	// deepPortMin/deepPortMax bound the sweep. The whole 1–65535 range;
	// callers narrow it via ScanConfig if they want a faster partial deep
	// scan.
	deepPortMin = 1
	deepPortMax = 65535

	// deepProbeTimeout is the per-port connect timeout for the open-check —
	// short on purpose so tens of thousands of closed/filtered ports do not
	// each cost the full capture timeout. A closed port RSTs immediately; a
	// filtered port is what this bounds.
	deepProbeTimeout = 800 * time.Millisecond

	// deepProbeConcurrency caps in-flight connect probes. Higher than the
	// capture concurrency because each probe is cheap, but bounded so a deep
	// scan does not exhaust file descriptors or look like a flood.
	deepProbeConcurrency = 100
)

// deepPortRange returns the [min,max] the deep sweep should cover, honoring
// an explicit ScanConfig.Ports (treated as [min,max] when exactly two
// ascending values are given — a caller-narrowed deep scan) and otherwise
// the full range.
func deepPortRange(cfg ScanConfig) (int, int) {
	if cfg.DeepPortLo >= 1 && cfg.DeepPortHi <= 65535 && cfg.DeepPortLo <= cfg.DeepPortHi && cfg.DeepPortHi > 0 {
		return cfg.DeepPortLo, cfg.DeepPortHi
	}
	return deepPortMin, deepPortMax
}

// deepOpenPorts TCP-connect-scans host across [lo,hi] and returns the open
// ports, sorted. Respects ctx cancellation so a killed scan job stops
// promptly instead of running to the end of the range.
func deepOpenPorts(ctx context.Context, host string, lo, hi int) []int {
	sem := make(chan struct{}, deepProbeConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	open := make([]int, 0)
	dialer := &net.Dialer{Timeout: deepProbeTimeout}

	for port := lo; port <= hi; port++ {
		select {
		case <-ctx.Done():
			wg.Wait()
			sort.Ints(open)
			return open
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, itoa(p)))
			if err != nil {
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

// itoa is a tiny strconv.Itoa to keep this file's imports minimal.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
