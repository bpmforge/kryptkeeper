// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bootstrap

import "golang.org/x/sys/unix"

// peerCredFromFD reads the connecting process's UID from a Unix-domain
// socket via SO_PEERCRED — the kernel-attested identity the SPIFFE
// Workload API attests on. It cannot be forged by the peer.
func peerCredFromFD(fd int) (uint32, error) {
	uc, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return uc.Uid, nil
}
