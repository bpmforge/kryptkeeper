// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentclient"
	"kryptkeeper/internal/trustpush"
)

type fakeTrustHub struct {
	tasks   []agentclient.TrustTask
	results []agentclient.TrustResult
}

func (h *fakeTrustHub) GetTrustTasks(context.Context) ([]agentclient.TrustTask, error) {
	return h.tasks, nil
}
func (h *fakeTrustHub) PostTrustResult(_ context.Context, r agentclient.TrustResult) error {
	h.results = append(h.results, r)
	return nil
}

type recRunner struct {
	argv []string
	out  []byte
}

func (r *recRunner) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	r.argv = append(r.argv, strings.Join(append([]string{name}, args...), " "))
	return r.out, nil
}

func trustTestPEM(t *testing.T, isCA bool) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "trust test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestTrustStorePushIsOffByDefault(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if trustStorePushEnabled(get) {
		t.Fatal("must be off when unset")
	}
	env[trustStorePushEnv] = "yes"
	if trustStorePushEnabled(get) {
		t.Fatal("only the literal true opts in")
	}
	env[trustStorePushEnv] = "True"
	if !trustStorePushEnabled(get) {
		t.Fatal("true must opt in")
	}
}

func TestOptedOutAgentRefusesAndRunsNothing(t *testing.T) {
	run := &recRunner{}
	hub := &fakeTrustHub{tasks: []agentclient.TrustTask{{BundleID: "b1", Action: "add", CertPEM: trustTestPEM(t, true)}}}
	p := newTrustPusher(false, &trustpush.Applier{GOOS: "linux", Runner: run})
	p.poll(context.Background(), hub)
	p.poll(context.Background(), hub) // the hub re-offers a refused bundle; the agent must not repeat itself
	if len(run.argv) != 0 {
		t.Fatalf("an opted-out agent must run no command: %v", run.argv)
	}
	if len(hub.results) != 1 || hub.results[0].Outcome != trustpush.OutcomeRefused {
		t.Fatalf("results = %+v", hub.results)
	}
}

func TestOptedInAgentRejectsNonCAWithoutDispatch(t *testing.T) {
	run := &recRunner{}
	hub := &fakeTrustHub{tasks: []agentclient.TrustTask{{BundleID: "b1", Action: "add", CertPEM: trustTestPEM(t, false)}}}
	p := newTrustPusher(true, &trustpush.Applier{GOOS: "linux", Runner: run})
	p.poll(context.Background(), hub)
	if len(run.argv) != 0 || len(hub.results) != 1 || hub.results[0].Outcome != trustpush.OutcomeFailed {
		t.Fatalf("argv=%v results=%+v", run.argv, hub.results)
	}
}

func TestOptedInAgentDispatchesThroughSudoAndReports(t *testing.T) {
	reply, _ := json.Marshal(trustpush.Result{Outcome: trustpush.OutcomeApplied, Detail: "added 1 certificate(s)"})
	run := &recRunner{out: reply}
	hub := &fakeTrustHub{tasks: []agentclient.TrustTask{{BundleID: "b1", Action: "add", CertPEM: trustTestPEM(t, true)}}}
	p := newTrustPusher(true, &trustpush.Applier{GOOS: "linux", Runner: run})
	p.poll(context.Background(), hub)
	p.poll(context.Background(), hub)
	if len(run.argv) != 1 || run.argv[0] != "sudo -n /usr/local/bin/kryptkeeper-agent --trust-store-apply" {
		t.Fatalf("argv = %v", run.argv)
	}
	if len(hub.results) != 1 || hub.results[0].Outcome != trustpush.OutcomeApplied {
		t.Fatalf("results = %+v", hub.results)
	}
}

func TestFailedBundleRetriesOnlyAfterTheBackoff(t *testing.T) {
	run := &recRunner{out: []byte(`{"outcome":"failed","detail":"x"}`)}
	hub := &fakeTrustHub{tasks: []agentclient.TrustTask{{BundleID: "b1", Action: "add", CertPEM: trustTestPEM(t, true)}}}
	p := newTrustPusher(true, &trustpush.Applier{GOOS: "linux", Runner: run})
	clock := time.Now()
	p.now = func() time.Time { return clock }
	p.poll(context.Background(), hub)
	p.poll(context.Background(), hub)
	clock = clock.Add(trustRetryAfter + time.Second)
	p.poll(context.Background(), hub)
	if len(run.argv) != 2 {
		t.Fatalf("want two attempts, got %v", run.argv)
	}
}

func TestHelperAppliesFromStdin(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=debian\n"), 0o644)
	run := &recRunner{}
	a := &trustpush.Applier{GOOS: "linux", Root: root, StatePath: filepath.Join(root, "s.json"), Runner: run}
	body, _ := json.Marshal(trustpush.Request{Action: trustpush.ActionAdd, CertPEM: trustTestPEM(t, true)})
	var out bytes.Buffer
	if code := runTrustStoreHelper(bytes.NewReader(body), &out, a); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if len(run.argv) != 1 || run.argv[0] != "/usr/sbin/update-ca-certificates" {
		t.Fatalf("argv = %v", run.argv)
	}
	if code := runTrustStoreHelper(strings.NewReader("not json"), &out, a); code != 1 {
		t.Fatalf("garbage must fail, exit %d", code)
	}
}

func TestTrustStoreSudoersIsOneExactRuleAndOptIn(t *testing.T) {
	got := trustStoreSudoers("kryptkeeper-agent")
	if !strings.Contains(got, "Cmnd_Alias KK_TRUSTSTORE = /usr/local/bin/kryptkeeper-agent --trust-store-apply\n") ||
		!strings.Contains(got, "kryptkeeper-agent ALL=(root) NOPASSWD: KK_TRUSTSTORE\n") {
		t.Fatalf("rule text:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "*") {
			t.Fatalf("a wildcard in the trust store rule: %q", line)
		}
	}
	base, err := generateSudoers(sudoersModeFlag(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(base, "KK_TRUSTSTORE") {
		t.Fatal("the default drop-in must never carry the trust store rule (D-114)")
	}
}
