// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package spiffe_test

// Live SPIFFE Workload API conformance (W29-01): a real hub process serving
// the Workload API on a Unix socket, driven by the real go-spiffe client.
// Skipped unless KK_LIVE_SPIFFE=1; bring the hub up with run.sh, which sets:
//
//	KK_SPIFFE_HUB_BASE      e.g. http://127.0.0.1:8123
//	KK_SPIFFE_TOKEN         the hub's bootstrap token
//	KK_SPIFFE_SOCKET        the Workload API socket path
//	KK_SPIFFE_TRUST_DOMAIN  e.g. kk.test
//	KK_SPIFFE_TTL           the hub's SPIFFE_SVID_TTL, e.g. 20s
//
// Test order matters: the unregistered-UID test must run BEFORE this process's
// UID is bound by the fetch test (Go runs tests in source order).

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type liveEnv struct {
	hub, token, sock, trustDomain string
	ttl                           time.Duration
}

func skipUnlessLive(t *testing.T) liveEnv {
	t.Helper()
	if os.Getenv("KK_LIVE_SPIFFE") != "1" {
		t.Skip("set KK_LIVE_SPIFFE=1 (and the KK_SPIFFE_* vars) to run against a live hub; see tests/live/spiffe/run.sh")
	}
	e := liveEnv{
		hub:         os.Getenv("KK_SPIFFE_HUB_BASE"),
		token:       os.Getenv("KK_SPIFFE_TOKEN"),
		sock:        os.Getenv("KK_SPIFFE_SOCKET"),
		trustDomain: os.Getenv("KK_SPIFFE_TRUST_DOMAIN"),
	}
	ttl, err := time.ParseDuration(os.Getenv("KK_SPIFFE_TTL"))
	if err != nil {
		t.Fatalf("KK_LIVE_SPIFFE=1 but KK_SPIFFE_TTL invalid: %v", err)
	}
	e.ttl = ttl
	for name, v := range map[string]string{"KK_SPIFFE_HUB_BASE": e.hub, "KK_SPIFFE_TOKEN": e.token, "KK_SPIFFE_SOCKET": e.sock, "KK_SPIFFE_TRUST_DOMAIN": e.trustDomain} {
		if v == "" {
			t.Fatalf("KK_LIVE_SPIFFE=1 but %s is unset", name)
		}
	}
	return e
}

func (e liveEnv) addr() workloadapi.ClientOption { return workloadapi.WithAddr("unix://" + e.sock) }

func (e liveEnv) spiffeID() string { return "spiffe://" + e.trustDomain + "/ns/live/sa/harness" }

func (e liveEnv) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.hub+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // test-controlled local URL
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// bindSelf registers this process's UID to the harness SPIFFE ID (idempotent).
func (e liveEnv) bindSelf(t *testing.T) {
	t.Helper()
	code, body := e.do(t, http.MethodPost, "/api/v1/spiffe/workload-selectors",
		map[string]any{"uid": os.Getuid(), "spiffe_id": e.spiffeID()})
	if code != http.StatusCreated {
		t.Fatalf("bind selector: %d %s", code, body)
	}
}

func TestGoSpiffeUnregisteredUIDDenied(t *testing.T) {
	e := skipUnlessLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := workloadapi.FetchX509Context(ctx, e.addr())
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unregistered UID must get PermissionDenied, got %v", err)
	}
}

func TestGoSpiffeFetchX509SVID(t *testing.T) {
	e := skipUnlessLive(t)
	e.bindSelf(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	svid, err := workloadapi.FetchX509SVID(ctx, e.addr())
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	if svid.ID.String() != e.spiffeID() {
		t.Fatalf("SVID id %q, want %q", svid.ID, e.spiffeID())
	}
	leaf := svid.Certificates[0]
	if until := time.Until(leaf.NotAfter); until > 24*time.Hour {
		t.Fatalf("SVID TTL %v exceeds 24h", until)
	}

	// The chain must validate against the hub's published bundle.
	code, pemBytes := e.do(t, http.MethodGet, "/api/v1/spiffe/bundle", nil)
	if code != http.StatusOK {
		t.Fatalf("bundle: %d %s", code, pemBytes)
	}
	pool := x509.NewCertPool()
	var roots []*x509.Certificate
	for rest := pemBytes; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("bundle cert: %v", err)
		}
		pool.AddCert(c)
		roots = append(roots, c)
	}
	if len(roots) == 0 {
		t.Fatal("bundle has no certificates")
	}
	inter := x509.NewCertPool()
	for _, c := range svid.Certificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to /spiffe/bundle: %v", err)
	}
	td := spiffeid.RequireTrustDomainFromString(e.trustDomain)
	if _, _, err := x509svid.Verify(svid.Certificates, x509bundle.FromX509Authorities(td, roots)); err != nil {
		t.Fatalf("x509svid.Verify against bundle: %v", err)
	}
}

func TestGoSpiffeRotatesAtHalfLife(t *testing.T) {
	e := skipUnlessLive(t)
	e.bindSelf(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(e.addr()))
	if err != nil {
		t.Fatalf("NewX509Source: %v", err)
	}
	defer src.Close()

	first, err := src.GetX509SVID()
	if err != nil {
		t.Fatal(err)
	}
	firstLeaf := first.Certificates[0]
	deadline := time.Now().Add(2 * e.ttl)
	for {
		cur, err := src.GetX509SVID() // the SAME source object throughout: no restart
		if err != nil {
			t.Fatal(err)
		}
		if leaf := cur.Certificates[0]; leaf.SerialNumber.Cmp(firstLeaf.SerialNumber) != 0 {
			if gap := leaf.NotBefore.Sub(firstLeaf.NotBefore); gap > e.ttl/2+5*time.Second {
				t.Fatalf("rotated %v after the first leaf's NotBefore; want <= TTL/2 (%v) + 5s", gap, e.ttl/2)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no rotation within 2x TTL (%v)", 2*e.ttl)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// documented limitation: SO_PEERCRED cannot tell same-UID/pid-namespace
// workloads apart; do not weaken.
func TestSharedUIDWorkloadsGetSameSPIFFEID(t *testing.T) {
	e := skipUnlessLive(t)
	e.bindSelf(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ids := make([]string, 2)
	for i := range ids {
		src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(e.addr()))
		if err != nil {
			t.Fatalf("source %d: %v", i, err)
		}
		defer src.Close()
		svid, err := src.GetX509SVID()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = svid.ID.String()
	}
	if ids[0] != ids[1] {
		t.Fatalf("same-UID workloads got different ids: %s", fmt.Sprint(ids))
	}
	if !strings.HasPrefix(ids[0], "spiffe://") {
		t.Fatalf("unexpected id %q", ids[0])
	}
}
