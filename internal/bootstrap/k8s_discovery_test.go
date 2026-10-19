// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"kryptkeeper/internal/certmanager"
)

// W19-17: k8s-certmanager was accepted by discovery_scanner_provider.go
// but had no case in handlers_discovery.go's scan_type switch and no
// runner on the DB stores at all, so it was unreachable via the API under
// either discovery provider. These prove the DB path now runs the
// injected connector and persists results — the cloud_discovery_test.go
// precedent, since k8s-certmanager shares the cloud types' "no target,
// scope is the connector's credentials" contract.

type fakeCertManagerConnector struct {
	certs []certmanager.Certificate
	err   error
}

func (f *fakeCertManagerConnector) ListCertificates(context.Context) ([]certmanager.Certificate, error) {
	return f.certs, f.err
}

// overrideCertManagerConnector swaps the factory for one test and returns
// a channel closed when the scan finalizes.
func overrideCertManagerConnector(t *testing.T, fake *fakeCertManagerConnector) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	origFactory := newCertManagerConnectorForScan
	origAfter := afterDiscoveryScanPersist
	newCertManagerConnectorForScan = func() (certManagerCertLister, error) {
		return fake, nil
	}
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() {
		newCertManagerConnectorForScan = origFactory
		afterDiscoveryScanPersist = origAfter
	})
	return done
}

func TestK8sCertManagerScanPersistsResultsToJobRow(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	fake := &fakeCertManagerConnector{certs: []certmanager.Certificate{
		{Namespace: "uat", Name: "uat-leaf", CommonName: "uat-leaf.example.com", Ready: true},
		{Namespace: "uat", Name: "uat-other", CommonName: "other.example.com", Ready: false},
	}}
	done := overrideCertManagerConnector(t, fake)

	result, err := store.CreateScan(context.Background(), scanTypeK8sCertManager, "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if result.Target != "" {
		t.Fatalf("k8s-certmanager scan takes no target, got %q", result.Target)
	}
	waitForScan(t, done)

	var jobType, status string
	var summary, errMsg *string
	err = db.QueryRow("SELECT type, status, results_summary, error_message FROM scan_jobs WHERE id = ?", result.ID).
		Scan(&jobType, &status, &summary, &errMsg)
	if err != nil {
		t.Fatalf("job row: %v", err)
	}
	if jobType != scanTypeK8sCertManager {
		t.Fatalf("job type %q, want %q", jobType, scanTypeK8sCertManager)
	}
	if status != "completed" {
		t.Fatalf("status %q, want completed (err=%v)", status, errMsg)
	}
	if summary == nil {
		t.Fatal("results_summary not persisted")
	}
	var parsed k8sCertManagerScanSummary
	if err := json.Unmarshal([]byte(*summary), &parsed); err != nil {
		t.Fatalf("summary unmarshal: %v", err)
	}
	if parsed.Certificates != 2 || len(parsed.Items) != 2 {
		t.Fatalf("summary %+v, want 2 certificates", parsed)
	}
	if parsed.Items[0].CommonName != "uat-leaf.example.com" {
		t.Fatalf("summary missing the cert-manager-issued certificate: %+v", parsed.Items)
	}
}

func TestK8sCertManagerScanConnectorFailureFinalizesFailed(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	done := overrideCertManagerConnector(t, &fakeCertManagerConnector{err: errors.New("k8s api auth error (401)")})

	result, err := store.CreateScan(context.Background(), scanTypeK8sCertManager, "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitForScan(t, done)

	var status string
	var errMsg *string
	if err := db.QueryRow("SELECT status, error_message FROM scan_jobs WHERE id = ?", result.ID).Scan(&status, &errMsg); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status %q, want failed", status)
	}
	if errMsg == nil || !strings.Contains(*errMsg, "401") {
		t.Fatalf("error_message %v must carry the connector's reason", errMsg)
	}
}

func TestK8sCertManagerScanRejectedWithoutRunner(t *testing.T) {
	// Sanity: the type-refusal guard still lists k8s-certmanager as a
	// real runner, not silently falling through to the network scanner.
	// (There's no "no runner" state to hit for k8s-certmanager itself --
	// unlike winrm it needs no per-provider SetXScanner wiring -- so this
	// just confirms an unrelated bogus type is still refused up front.)
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	if _, err := store.CreateScan(context.Background(), "not-a-real-type", "x", nil); err == nil || !strings.Contains(err.Error(), "no runner") {
		t.Fatalf("bogus scan type must be refused up front: %v", err)
	}
}

// W24-23: multi-cluster cert-manager scans.

type multiClusterHarness struct {
	done <-chan struct{}
}

// overrideClusters injects the cluster list and per-cluster fakes (keyed by
// cluster name); a missing key means a connector-init error.
func overrideClusters(t *testing.T, clusters []kubeClusterSource, fakes map[string]*fakeCertManagerConnector) multiClusterHarness {
	t.Helper()
	done := make(chan struct{})
	origLoader, origNew, origAfter := kubeClusterSourcesLoader, newCertManagerConnectorForCluster, afterDiscoveryScanPersist
	kubeClusterSourcesLoader = func(context.Context) ([]kubeClusterSource, error) { return clusters, nil }
	newCertManagerConnectorForCluster = func(c kubeClusterSource) (certManagerCertLister, error) {
		f, ok := fakes[c.Name]
		if !ok {
			return nil, errors.New("rbac denied (403)")
		}
		return f, nil
	}
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() {
		kubeClusterSourcesLoader, newCertManagerConnectorForCluster, afterDiscoveryScanPersist = origLoader, origNew, origAfter
	})
	return multiClusterHarness{done: done}
}

func runClusterScan(t *testing.T, h multiClusterHarness) (status string, errMsg string, sum k8sCertManagerScanSummary) {
	t.Helper()
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	result, err := store.CreateScan(context.Background(), scanTypeK8sCertManager, "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitForScan(t, h.done)
	var summary, em *string
	if err := db.QueryRow("SELECT status, results_summary, error_message FROM scan_jobs WHERE id = ?", result.ID).Scan(&status, &summary, &em); err != nil {
		t.Fatal(err)
	}
	if em != nil {
		errMsg = *em
	}
	if summary != nil && *summary != "" {
		if err := json.Unmarshal([]byte(*summary), &sum); err != nil {
			t.Fatalf("summary: %v", err)
		}
	}
	return status, errMsg, sum
}

func TestCertManagerScanTwoClustersRecordsCluster(t *testing.T) {
	h := overrideClusters(t, []kubeClusterSource{{Name: "east"}, {Name: "west"}}, map[string]*fakeCertManagerConnector{
		"east": {certs: []certmanager.Certificate{{Namespace: "a", Name: "e1"}}},
		"west": {certs: []certmanager.Certificate{{Namespace: "b", Name: "w1"}, {Namespace: "b", Name: "w2"}}},
	})
	status, _, sum := runClusterScan(t, h)
	if status != "completed" || sum.Certificates != 3 || len(sum.Clusters) != 2 {
		t.Fatalf("status %s summary %+v", status, sum)
	}
	for _, it := range sum.Items {
		want := map[string]string{"e1": "east", "w1": "west", "w2": "west"}[it.Name]
		if it.Cluster != want {
			t.Fatalf("item %s cluster %q want %q", it.Name, it.Cluster, want)
		}
	}
	for _, c := range sum.Clusters {
		if c.Error != "" {
			t.Fatalf("unexpected cluster error: %+v", c)
		}
	}
}

func TestCertManagerScanOneClusterFailsOthersSucceed(t *testing.T) {
	h := overrideClusters(t, []kubeClusterSource{{Name: "east"}, {Name: "west"}}, map[string]*fakeCertManagerConnector{
		"east": {certs: []certmanager.Certificate{{Namespace: "a", Name: "e1"}}},
		"west": {err: errors.New("unreachable")},
	})
	status, errMsg, sum := runClusterScan(t, h)
	if status != "completed" || len(sum.Items) != 1 || sum.Items[0].Cluster != "east" {
		t.Fatalf("status %s summary %+v", status, sum)
	}
	if !strings.Contains(errMsg, "cluster west") || strings.Contains(errMsg, "cluster east") {
		t.Fatalf("error_message must name only the failed cluster: %q", errMsg)
	}
	if sum.Clusters[1].Name != "west" || sum.Clusters[1].Error == "" || sum.Clusters[0].Error != "" {
		t.Fatalf("per-cluster results: %+v", sum.Clusters)
	}
}

func TestCertManagerScanAllClustersFailFinalizesFailed(t *testing.T) {
	h := overrideClusters(t, []kubeClusterSource{{Name: "east"}, {Name: "bad", credErr: kubeClusterCredentialBad}}, map[string]*fakeCertManagerConnector{
		"east": {err: errors.New("boom")},
	})
	status, errMsg, _ := runClusterScan(t, h)
	if status != "failed" || !strings.Contains(errMsg, "cluster east") || !strings.Contains(errMsg, "cluster bad: credential invalid") {
		t.Fatalf("status %s err %q", status, errMsg)
	}
}

type fakeCredResolver map[string]string

func (f fakeCredResolver) Resolve(_ context.Context, id string) ([]byte, error) {
	v, ok := f[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return []byte(v), nil
}

func TestKubeClusterSourcesLoadFromConfig(t *testing.T) {
	raw := `[{"name":"prod-east","credential_ref":"c1","namespace":"apps"},{"name":"bad","credential_ref":"c2"},{"name":"gone","credential_ref":"c3"}]`
	srcs, err := parseKubeClusterSources(raw)
	if err != nil || len(srcs) != 3 {
		t.Fatalf("parse: %v %+v", err, srcs)
	}
	if strings.Contains(raw, "bearer") || strings.Contains(raw, "base_url") {
		t.Fatal("config value must not carry secrets")
	}
	srcs = resolveKubeClusterCredentials(context.Background(), srcs, fakeCredResolver{
		"c1": `{"base_url":"https://k.example:6443","bearer_token":"tok","ca_cert":"PEM","namespace":"ignored"}`,
		"c2": `{"bearer_token":"tok"}`,
	})
	if srcs[0].APIURL != "https://k.example:6443" || srcs[0].Token != "tok" || string(srcs[0].CACert) != "PEM" || srcs[0].Namespace != "apps" || srcs[0].credErr != "" {
		t.Fatalf("resolved: %+v", srcs[0])
	}
	if srcs[1].credErr != kubeClusterCredentialBad || srcs[2].credErr != kubeClusterCredentialBad {
		t.Fatalf("bad credentials must be flagged: %+v %+v", srcs[1], srcs[2])
	}
	for _, bad := range []string{`not json`, `[{"name":""}]`, `[{"name":"a/b"}]`, `[{"name":"x"},{"name":"x"}]`} {
		if _, err := parseKubeClusterSources(bad); err == nil {
			t.Fatalf("expected error for %s", bad)
		}
	}
}

func TestKubeClusterSourcesEnvFallbackWhenUnset(t *testing.T) {
	t.Setenv("KRYPTKEEPER_K8S_CLUSTERS", "")
	if v := discoveryConfigValueFrom(context.Background(), nil, configKeyKubeClusters); v != "" {
		t.Fatalf("unset must be empty (legacy single-cluster path), got %q", v)
	}
	if srcs, err := parseKubeClusterSources(""); err != nil || srcs != nil {
		t.Fatalf("empty value must yield nil: %v %v", srcs, err)
	}
	t.Setenv("KRYPTKEEPER_K8S_CLUSTERS", `[{"name":"e","credential_ref":"c"}]`)
	if v := discoveryConfigValueFrom(context.Background(), nil, configKeyKubeClusters); !strings.Contains(v, `"e"`) {
		t.Fatalf("env value not read: %q", v)
	}
}
