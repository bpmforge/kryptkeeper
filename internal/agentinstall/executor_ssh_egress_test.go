// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/egress"
)

func TestSSHExecutorRefusesMetadataAtDialTime(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSSHExecutor(context.Background(), SSHTarget{
		Host: "169.254.169.254", Port: 22, User: "x", Signer: signer,
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error { return nil },
		DialTimeout:     time.Second,
	})
	if !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("want ErrBlockedDestination, got %v", err)
	}
}
