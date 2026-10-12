// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// W7-01: the real SPIFFE Workload API over gRPC. These tests bring up
// the server on a temp Unix socket and connect with an actual gRPC
// client — the test process IS the peer, so its kernel UID genuinely
// drives peer-credential attestation with no cloud and no mocks.

func startTestWorkloadAPI(t *testing.T, reg *SelectorRegistry) string {
	t.Helper()
	spiffeTestSetup(t) // wires spiffeEngine + SPIFFE_TRUST_DOMAIN/SPIFFE_SIGNING_CA_ID
	// A Unix socket path must fit sun_path (~104 bytes on macOS), so a
	// short /tmp dir is used rather than the long t.TempDir() path.
	dir, err := os.MkdirTemp("/tmp", "kkwl")
	if err != nil {
		t.Fatalf("tmp socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "w.sock")
	srv, err := startWorkloadAPIServer(sock, reg, stubAuditProvider{})
	if err != nil {
		t.Fatalf("start workload API: %v", err)
	}
	t.Cleanup(srv.Stop)
	return sock
}

func dialWorkloadAPI(t *testing.T, sock string) workload.SpiffeWorkloadAPIClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return workload.NewSpiffeWorkloadAPIClient(conn)
}

// The workload MUST send the security header per the SPIFFE spec.
func workloadCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true")), cancel
}

func TestWorkloadAPIAttestsByPeerCredential(t *testing.T) {
	reg := NewSelectorRegistry()
	// Bind THIS process's UID to a registered identity — the operator's
	// approval. The workload does not name itself.
	reg.RegisterUID(uint32(os.Getuid()), "spiffe://example.org/ns/prod/sa/checkout")
	client := dialWorkloadAPI(t, startTestWorkloadAPI(t, reg))

	ctx, cancel := workloadCtx(t)
	defer cancel()
	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if len(resp.Svids) != 1 {
		t.Fatalf("expected one SVID, got %d", len(resp.Svids))
	}
	svid := resp.Svids[0]
	if svid.SpiffeId != "spiffe://example.org/ns/prod/sa/checkout" {
		t.Fatalf("wrong SPIFFE ID: %q", svid.SpiffeId)
	}
	// The SVID is a real cert carrying the registered ID as a URI SAN.
	cert, err := x509.ParseCertificate(svid.X509Svid)
	if err != nil {
		t.Fatalf("parse SVID cert: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != svid.SpiffeId {
		t.Fatalf("SVID must carry the SPIFFE ID as a URI SAN, got %v", cert.URIs)
	}
	// The private key is a real unencrypted PKCS#8 key.
	if _, err := x509.ParsePKCS8PrivateKey(svid.X509SvidKey); err != nil {
		t.Fatalf("SVID key must be PKCS#8 DER: %v", err)
	}
	if len(svid.Bundle) == 0 {
		t.Fatal("response must carry the trust bundle")
	}
}

func TestWorkloadAPIRefusesUnregisteredPeer(t *testing.T) {
	reg := NewSelectorRegistry()
	// Register some OTHER uid, not this process's — attestation must fail.
	reg.RegisterUID(uint32(os.Getuid())+40000, "spiffe://example.org/other")
	client := dialWorkloadAPI(t, startTestWorkloadAPI(t, reg))

	ctx, cancel := workloadCtx(t)
	defer cancel()
	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an unregistered peer must be refused PermissionDenied, got %v", err)
	}
}

func TestWorkloadAPIRequiresSecurityHeader(t *testing.T) {
	reg := NewSelectorRegistry()
	reg.RegisterUID(uint32(os.Getuid()), "spiffe://example.org/ns/prod/sa/checkout")
	client := dialWorkloadAPI(t, startTestWorkloadAPI(t, reg))

	// No workload.spiffe.io header — the spec requires it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a call missing the security header must be refused InvalidArgument, got %v", err)
	}
}
