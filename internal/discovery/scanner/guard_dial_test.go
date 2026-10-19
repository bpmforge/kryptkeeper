// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// L-2: the deny list is enforced on the address actually dialled, so a name
// that resolves to cloud metadata is refused even though CheckTarget (which
// never resolves) let it through.
func TestGuardedDialerRefusesLinkLocalAtDialTime(t *testing.T) {
	d := guardedDialer(time.Second)
	for _, addr := range []string{"169.254.169.254:80", "[fe80::1]:80", "[::ffff:169.254.169.254]:80", "0.0.0.0:80"} {
		if _, err := d.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrTargetDenied) {
			t.Errorf("%s: want ErrTargetDenied, got %v", addr, err)
		}
	}
}

func TestGuardedDialerKeepsPrivateAndLoopbackScannable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := guardedDialer(time.Second).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("loopback scan target refused: %v", err)
	}
	conn.Close()
}

func TestGuardedDialerHonoursOperatorDenyCIDRs(t *testing.T) {
	t.Setenv(EnvDenyCIDRs, "127.0.0.0/8")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := guardedDialer(time.Second).DialContext(context.Background(), "tcp", ln.Addr().String()); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("want ErrTargetDenied, got %v", err)
	}
}
