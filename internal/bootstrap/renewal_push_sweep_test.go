// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentinstall"

	"encoding/pem"
)

// Every push install mode is picked up by the scheduler once it has a
// credential, and an opted-in target that cannot be executed is skipped with a
// logged reason rather than silently.
func TestAutoRenewTargetsIncludePushModes(t *testing.T) {
	for _, mode := range []string{"f5", "citrix", "k8s", "iis"} {
		t.Run(mode, func(t *testing.T) {
			var logs bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(prev) })

			ok := ManagedTarget{Name: "ok", Host: mode + ".example.com", InstallMode: mode, AutoRenew: true, AutoRenewSetBy: "admin-1", CredentialRef: "c"}
			noCred := ManagedTarget{Name: "nocred", Host: mode + "2.example.com", InstallMode: mode, AutoRenew: true, AutoRenewSetBy: "admin-1"}
			optOut := ManagedTarget{Name: "optout", Host: mode + "3.example.com", InstallMode: mode, CredentialRef: "c"}
			got := autoRenewTargetsByHost([]ManagedTarget{ok, noCred, optOut})
			if len(got) != 1 || got[ok.Host].InstallMode != mode {
				t.Fatalf("eligible = %v, want only %s", got, ok.Host)
			}
			if !strings.Contains(logs.String(), `"nocred"`) || !strings.Contains(logs.String(), "no credential_ref") {
				t.Fatalf("skipped target not logged with its reason: %q", logs.String())
			}
			if strings.Contains(logs.String(), `"optout"`) {
				t.Fatalf("a target that never opted in must not be logged as skipped: %q", logs.String())
			}
		})
	}
}

// The scheduler renews and pushes a k8s Secret with nobody calling renew, and
// leaves the credential type check to the executor.
func TestRenewalSweepPushesK8sSecret(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-sweep-k8s",
	})
	if err != nil {
		t.Fatal(err)
	}

	var stored []byte
	cluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPost:
			stored, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(cluster.Close)

	engineX := NewRenewalExecutor(provider, &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-push", CredentialType: CredentialTypeAPIToken},
		payload: pushCredentialJSON(t, cluster.URL),
	})
	engineX.pushClient = cluster.Client()
	engineX.verifier = func(context.Context, string) (string, error) {
		var manifest struct {
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(stored, &manifest); err != nil {
			return "", err
		}
		raw, err := base64.StdEncoding.DecodeString(manifest.Data["tls.crt"])
		if err != nil {
			return "", err
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return "", errors.New("stored cert unparseable")
		}
		return agentinstall.FingerprintSHA256(block.Bytes), nil
	}

	targets := newSweepTestTargetStore(t)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := targets.Create(ctx, ManagedTarget{
		ID: "tgt-k8s-sweep", Name: "edge-cluster", Host: "sweep.example.com",
		DiscoveryMode: "none", InstallMode: "k8s", RenewalMethod: "manual",
		CredentialRef: "cred-push", AutoRenew: true, AutoRenewSetBy: "admin-1", RenewalThresholdDays: 100, Tenant: "default", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	sched := newSweepScheduler(t, provider, targets, engineX)
	sched.runScan()

	if st := sched.Status(); st.LastAutoRenewTriggers != 1 {
		t.Fatalf("expected the sweep to renew the k8s target, got %+v", st)
	}
	after, _, err := provider.GetCertificate(ctx, issued.CertificateItem.FingerprintSHA256)
	if err != nil || after.SuccessorFP == nil {
		t.Fatalf("no successor minted: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("the Secret never reached the cluster")
	}
}
