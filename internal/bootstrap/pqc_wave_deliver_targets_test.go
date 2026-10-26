// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/pqc"
)

const haproxyPEMPath = "/etc/nginx/tls/renewed.crt" // the shared fake verifier serves this path

// waveE2EHAProxy runs a real ML-DSA-65 wave member through the real install
// path against an in-memory haproxy host (D-315). serve nil = the host serves
// whatever its combined PEM holds, like a reloaded haproxy.
func waveE2EHAProxy(t *testing.T, serve func() string, failCmd string) (migrateWaveExecutionResult, *renewalFakeExecutor) {
	t.Helper()
	fx := newWaveExecuteTestFixture(t)
	_, wave := waveTestMember(t, fx, "hap.example.com")
	host := &renewalFakeExecutor{files: map[string][]byte{haproxyPEMPath: []byte("OLD-COMBINED")}, failCommand: failCmd}
	exec := newRenewalTestEngine(t, fx.certs, host, testSSHCredentialJSON(t))
	if serve != nil {
		exec.verifier = func(context.Context, string) (string, error) { return serve(), nil }
	}
	exp := fx.keys.(keystore.PrivateKeyPKCS8Exporter)
	tgt := ManagedTarget{ID: "h1", Name: "lb", Host: "hap.example.com", InstallMode: "ssh", CredentialRef: "cred-1",
		InstallServerType: "haproxy", InstallCertPath: haproxyPEMPath}
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{list: []ManagedTarget{tgt}}, waves: fx.waveStore,
		deliver: &keystoreWaveDeliverer{exporter: exp, certs: fx.certs, installer: exec, audit: &memAuditProvider{}}}
	return runWaveMigration(context.Background(), d, wave, "ML-DSA-65", waveHooks{}), host
}

func TestWaveDeliverer_HAProxyMLDSACombinedPEMDelivered(t *testing.T) {
	res, host := waveE2EHAProxy(t, nil, "")
	if res.Migrated != 1 || res.Regressed || res.Results[0].Delivery != "verified" {
		t.Fatalf("result = %+v, want migrated with verified delivery", res)
	}
	rest := host.files[haproxyPEMPath]
	var types []string
	var keyDER []byte
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		types = append(types, b.Type)
		if b.Type == "PRIVATE KEY" {
			keyDER = b.Bytes
		}
	}
	if len(types) != 2 || types[0] != "CERTIFICATE" || types[1] != "PRIVATE KEY" {
		t.Fatalf("combined file layout = %v, want CERTIFICATE then PRIVATE KEY", types)
	}
	if _, alg, err := keystore.ParseMLDSAPKCS8(keyDER); err != nil || alg != keystore.MLDSA65 {
		t.Fatalf("combined file key is not ML-DSA-65: %v %v", alg, err)
	}
}

func TestWaveDeliverer_HAProxyVerifyFailureRollsBackAndRegresses(t *testing.T) {
	res, host := waveE2EHAProxy(t, func() string { return strings.Repeat("ab", 32) }, "")
	r := res.Results[0]
	if r.Status != pqc.MemberFailed || !res.Regressed || r.OldSerialServed == nil || !*r.OldSerialServed {
		t.Fatalf("member=%+v regressed=%v, want failed, rolled back, regressed", r, res.Regressed)
	}
	if string(host.files[haproxyPEMPath]) != "OLD-COMBINED" {
		t.Fatalf("combined file not restored: %.30q", host.files[haproxyPEMPath])
	}
}

func TestWaveDeliverer_HAProxyConfigTestFailureRollsBack(t *testing.T) {
	// haproxy -c is what rejects a build whose OpenSSL cannot load the key.
	res, host := waveE2EHAProxy(t, nil, "haproxy")
	if !res.Regressed || res.Results[0].Status != pqc.MemberFailed {
		t.Fatalf("result = %+v, want failed and regressed", res)
	}
	if string(host.files[haproxyPEMPath]) != "OLD-COMBINED" {
		t.Fatalf("combined file not restored after config test failure")
	}
}

// k8sFakeCluster is a minimal Secrets API holding at most one Secret.
type k8sFakeCluster struct{ secret []byte }

func (c *k8sFakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if c.secret == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(c.secret)
	case http.MethodPost, http.MethodPut:
		c.secret, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (c *k8sFakeCluster) field(name string) []byte {
	var m struct {
		Data map[string]string `json:"data"`
	}
	if json.Unmarshal(c.secret, &m) != nil {
		return nil
	}
	b, _ := base64.StdEncoding.DecodeString(m.Data[name])
	return b
}

func TestWaveDeliverer_K8sMLDSASecretDeliveredAndVerified(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	_, wave := waveTestMember(t, fx, "k8s.example.com")
	cluster := &k8sFakeCluster{}
	srv := httptest.NewServer(cluster)
	t.Cleanup(srv.Close)
	exec := NewRenewalExecutor(fx.certs, &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-push", CredentialType: CredentialTypeAPIToken},
		payload: pushCredentialJSON(t, srv.URL),
	})
	exec.pushClient = srv.Client()
	exec.verifier = func(context.Context, string) (string, error) { // the ingress serves what the Secret holds
		b, _ := pem.Decode(cluster.field("tls.crt"))
		if b == nil {
			return "", errors.New("no cert in secret")
		}
		return agentinstall.FingerprintSHA256(b.Bytes), nil
	}
	audit := &memAuditProvider{}
	tgt := ManagedTarget{ID: "k1", Name: "edge", Host: "k8s.example.com", InstallMode: "k8s", CredentialRef: "cred-push"}
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{list: []ManagedTarget{tgt}}, waves: fx.waveStore,
		deliver: &keystoreWaveDeliverer{exporter: fx.keys.(keystore.PrivateKeyPKCS8Exporter), certs: fx.certs, installer: exec, audit: audit}}
	res := runWaveMigration(context.Background(), d, wave, "ML-DSA-65", waveHooks{})
	if res.Migrated != 1 || res.Regressed || res.Results[0].Delivery != "verified" {
		t.Fatalf("result = %+v, want migrated with verified delivery", res)
	}
	kb, _ := pem.Decode(cluster.field("tls.key"))
	if kb == nil || kb.Type != "PRIVATE KEY" {
		t.Fatalf("tls.key is not a PRIVATE KEY PEM")
	}
	if _, alg, err := keystore.ParseMLDSAPKCS8(kb.Bytes); err != nil || alg != keystore.MLDSA65 {
		t.Fatalf("tls.key is not ML-DSA-65: %v %v", alg, err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "key.export_for_delivery" {
		t.Fatalf("audit = %+v", audit.entries)
	}
	if bytes.Contains([]byte(audit.entries[0].ChangeSummary), kb.Bytes[:16]) {
		t.Fatal("audit row leaks key bytes")
	}
}

func TestPushMaterial_RefusesNonK8sAndUnparseableChain(t *testing.T) {
	e := NewRenewalExecutor(nil, &renewalFakeCredStore{})
	if _, err := e.PushMaterial(context.Background(), ManagedTarget{InstallMode: "f5", CredentialRef: "c"}, RenewalInstallProfile{}, nil, nil); err == nil {
		t.Fatal("f5 must be refused")
	}
	if _, err := e.PushMaterial(context.Background(), ManagedTarget{InstallMode: "k8s", CredentialRef: "c"}, RenewalInstallProfile{}, []byte("junk"), nil); err == nil {
		t.Fatal("unparseable chain must be refused before the cluster is touched")
	}
}
