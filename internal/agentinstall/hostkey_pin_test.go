// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/egress"
)

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func freshKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPinnedHostKeyCallback_MismatchNamesBothFingerprints(t *testing.T) {
	addr, served, signer := startTestSSHServer(t)
	host, port := splitAddr(t, addr)
	other := freshKey(t)
	_, err := NewSSHExecutor(context.Background(), SSHTarget{
		Host: host, Port: port, User: "u", Signer: signer,
		HostKeyCallback:   PinnedHostKeyCallback(other),
		HostKeyAlgorithms: []string{other.Type()},
		DialTimeout:       5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected a host key mismatch, got a connection")
	}
	var mm *HostKeyMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("want *HostKeyMismatchError in chain, got %T: %v", err, err)
	}
	if mm.Pinned != HostKeyFingerprint(other) || mm.Observed != HostKeyFingerprint(served) {
		t.Fatalf("fingerprints wrong: %+v", mm)
	}
	for _, fp := range []string{HostKeyFingerprint(other), HostKeyFingerprint(served)} {
		if !strings.Contains(err.Error(), fp) {
			t.Fatalf("error %q does not name %s", err, fp)
		}
	}
}

func TestPinnedHostKeyCallback_MatchingKeyConnects(t *testing.T) {
	addr, served, signer := startTestSSHServer(t)
	host, port := splitAddr(t, addr)
	e, err := NewSSHExecutor(context.Background(), SSHTarget{
		Host: host, Port: port, User: "u", Signer: signer,
		HostKeyCallback:   PinnedHostKeyCallback(served),
		HostKeyAlgorithms: []string{served.Type()},
		DialTimeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("matching pin must connect: %v", err)
	}
	_ = e.Close()
}

func TestProbeHostKey_ReturnsServedKey(t *testing.T) {
	addr, served, _ := startTestSSHServer(t)
	host, port := splitAddr(t, addr)
	got, err := probeHostKeyWithPolicy(context.Background(), host, port, 5*time.Second,
		egress.Policy{AllowLoopback: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	if HostKeyFingerprint(got) != HostKeyFingerprint(served) {
		t.Fatalf("probe returned %s, server serves %s", HostKeyFingerprint(got), HostKeyFingerprint(served))
	}
	line := HostKeyLine(got)
	if FingerprintOfLine(line) != HostKeyFingerprint(served) {
		t.Fatalf("line round-trip failed: %q", line)
	}
}

func TestProbeHostKey_RefusesLoopbackByDefault(t *testing.T) {
	addr, _, _ := startTestSSHServer(t)
	host, port := splitAddr(t, addr)
	if k, err := ProbeHostKey(context.Background(), host, port, 3*time.Second); err == nil {
		t.Fatalf("loopback probe must be refused, got key %s", HostKeyFingerprint(k))
	}
}
