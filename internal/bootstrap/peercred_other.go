// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package bootstrap

import "errors"

// peerCredFromFD is the default-build stub: peer-credential attestation
// relies on SO_PEERCRED / LOCAL_PEERCRED, which exist only on Unix. On
// other platforms the gRPC Workload API attestor fails closed rather
// than trusting an unauthenticated peer.
func peerCredFromFD(_ int) (uint32, error) {
	return 0, errors.New("peer-credential attestation is unsupported on this platform")
}
