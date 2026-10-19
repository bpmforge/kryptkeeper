// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// W24-23: multi-cluster kubeconfig sources shared by the cert-manager scan
// and the mesh sweep. The config value only names a cluster and points at an
// api_token credential; the API URL, token and CA live in the credential
// (pushCredentialPayload shape) so no secret ever sits in the config value.

const (
	configKeyKubeClusters      = "discovery.kube_clusters"
	configKeyMeshLeafRetention = "discovery.mesh_leaf_retention_days"
	defaultMeshLeafRetention   = 7 * 24 * time.Hour
	kubeClusterCredentialBad   = "credential invalid"
)

type kubeClusterSource struct {
	Name, CredentialRef, Namespace string
	APIURL, Token                  string
	CACert                         []byte
	// credErr is set (never the payload) when the credential could not be
	// resolved or lacks base_url; the cluster is then reported, not scanned.
	credErr string
}

type kubeClusterConfigEntry struct {
	Name          string `json:"name"`
	CredentialRef string `json:"credential_ref"`
	Namespace     string `json:"namespace"`
}

type credentialResolver interface {
	Resolve(ctx context.Context, id string) ([]byte, error)
}

// parseKubeClusterSources decodes the config value. Empty means "not
// configured" (nil), which selects the legacy single-cluster env path.
func parseKubeClusterSources(raw string) ([]kubeClusterSource, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var entries []kubeClusterConfigEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, errors.New("discovery.kube_clusters is not a valid JSON array")
	}
	seen := map[string]bool{}
	out := make([]kubeClusterSource, 0, len(entries))
	for _, e := range entries {
		name := strings.TrimSpace(e.Name)
		if name == "" || strings.Contains(name, "/") || seen[name] {
			return nil, errors.New("discovery.kube_clusters: each cluster needs a unique name without '/'")
		}
		seen[name] = true
		out = append(out, kubeClusterSource{Name: name, CredentialRef: strings.TrimSpace(e.CredentialRef), Namespace: strings.TrimSpace(e.Namespace)})
	}
	return out, nil
}

// resolveKubeClusterCredentials fills APIURL/Token/CACert per cluster. A bad
// credential only marks that cluster; the payload is never echoed.
func resolveKubeClusterCredentials(ctx context.Context, srcs []kubeClusterSource, creds credentialResolver) []kubeClusterSource {
	for i := range srcs {
		if creds == nil || srcs[i].CredentialRef == "" {
			srcs[i].credErr = kubeClusterCredentialBad
			continue
		}
		plain, err := creds.Resolve(ctx, srcs[i].CredentialRef)
		if err != nil {
			srcs[i].credErr = kubeClusterCredentialBad
			continue
		}
		var p pushCredentialPayload
		if json.Unmarshal(plain, &p) != nil || strings.TrimSpace(p.BaseURL) == "" {
			srcs[i].credErr = kubeClusterCredentialBad
			continue
		}
		srcs[i].APIURL = strings.TrimSpace(p.BaseURL)
		srcs[i].Token = p.BearerToken
		if p.CACert != "" {
			srcs[i].CACert = []byte(p.CACert)
		}
		if srcs[i].Namespace == "" {
			srcs[i].Namespace = p.Namespace
		}
	}
	return srcs
}

// discoveryConfigValueFrom returns the DB override for key, else the
// registry's env default. A nil store (unconfigured passphrase) is env-only.
func discoveryConfigValueFrom(ctx context.Context, store ConfigStore, key string) string {
	if store != nil {
		if entry, ok, err := store.Get(ctx, key); err == nil && ok && strings.TrimSpace(entry.Value) != "" {
			return entry.Value
		}
	}
	if def, ok := configRegistryByKey[key]; ok && def.EnvVar != "" {
		return os.Getenv(def.EnvVar)
	}
	return ""
}

// discoveryStores opens the config and credential stores once: each open is a
// DB handle, and the mesh scheduler re-reads the values every tick.
type discoveryStores struct {
	once   sync.Once
	config ConfigStore
	creds  OutboundCredentialStore
}

var sharedDiscoveryStores discoveryStores

func (d *discoveryStores) get() (ConfigStore, OutboundCredentialStore) {
	d.once.Do(func() {
		d.config = newConfigStoreFromEnv()
		d.creds = newOutboundCredentialStoreFromEnv()
	})
	return d.config, d.creds
}

// kubeClusterSourcesLoader is a package var so tests inject sources. The
// default re-reads the config value on every call.
var kubeClusterSourcesLoader = func(ctx context.Context) ([]kubeClusterSource, error) {
	cfg, creds := sharedDiscoveryStores.get()
	srcs, err := parseKubeClusterSources(discoveryConfigValueFrom(ctx, cfg, configKeyKubeClusters))
	if err != nil || len(srcs) == 0 {
		return nil, err
	}
	// A nil interface-typed store must not become a non-nil credentialResolver.
	if creds == nil {
		return resolveKubeClusterCredentials(ctx, srcs, nil), nil
	}
	return resolveKubeClusterCredentials(ctx, srcs, creds), nil
}

// meshLeafRetention reads discovery.mesh_leaf_retention_days (config, then env).
func meshLeafRetention(ctx context.Context) time.Duration {
	cfg, _ := sharedDiscoveryStores.get()
	return parseLeafRetentionDays(discoveryConfigValueFrom(ctx, cfg, configKeyMeshLeafRetention))
}

func parseLeafRetentionDays(raw string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
		return time.Duration(n) * 24 * time.Hour
	}
	return defaultMeshLeafRetention
}
