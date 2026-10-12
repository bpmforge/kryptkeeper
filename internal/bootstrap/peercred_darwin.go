// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package bootstrap

import "golang.org/x/sys/unix"

// peerCredFromFD reads the connecting process's UID from a Unix-domain
// socket via LOCAL_PEERCRED (macOS/BSD's equivalent of SO_PEERCRED) —
// the kernel-attested identity, unforgeable by the peer.
func peerCredFromFD(fd int) (uint32, error) {
	xu, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return xu.Uid, nil
}
