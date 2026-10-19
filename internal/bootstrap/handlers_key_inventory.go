// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/keyinventory"
	"kryptkeeper/internal/sshkeys"
)

// W17-03: the W15-01 unified cloud key inventory, wired into the product.
//
// The engine shipped complete and tested but had zero importers, so no
// operator could reach it. This is the crypto-agility denominator for
// KEYS — the cert side has had an inventory since W1; without this half,
// "are we quantum-ready" can only be answered for certificates while the
// KMS keys that protect them stay invisible.
//
// Read-only: a dead provider degrades the result and is reported, never
// fatal (the Collect contract, preserved through the handler).

// KeyInventoryResponse is the API shape: the raw inventory plus the PQC
// rollup, since readiness is the question this endpoint exists to answer.
type KeyInventoryResponse struct {
	GeneratedAt string             `json:"generated_at"`
	Total       int                `json:"total"`
	PQCSummary  map[string]int     `json:"pqc_summary"`
	Providers   []string           `json:"providers"`
	Keys        []keyinventory.Key `json:"keys"`
	Errors      []string           `json:"errors,omitempty"`
}

// newKeyInventorySources builds the configured provider sources. A
// package var so tests inject fakes and CI needs no cloud credentials —
// the newCloudConnector precedent from W5-12.
var newKeyInventorySources = func(ctx context.Context) []keyinventory.KeySource {
	var sources []keyinventory.KeySource

	// AWS: the SDK's default credential chain, same as the ACM connector.
	if region := firstNonEmptyEnv("AWS_REGION", "AWS_DEFAULT_REGION"); region != "" {
		if src, err := keyinventory.NewAWSKeySource(ctx, region); err == nil {
			sources = append(sources, src)
		} else {
			logging.Warnf("key inventory: aws source unavailable: %v", err)
		}
	}
	// Azure Key Vault: same vault URL the cert-side connector uses.
	if vault := strings.TrimSpace(os.Getenv("AZURE_KEYVAULT_URL")); vault != "" {
		if token := strings.TrimSpace(os.Getenv("AZURE_ACCESS_TOKEN")); token != "" {
			sources = append(sources, keyinventory.NewAzureKeyVaultSource(vault, token, nil))
		}
	}
	// GCP KMS: keyring path + the same access token the cert side uses.
	if ring := strings.TrimSpace(os.Getenv("GCP_KMS_KEYRING")); ring != "" {
		if token := strings.TrimSpace(os.Getenv("GOOGLE_ACCESS_TOKEN")); token != "" {
			sources = append(sources, keyinventory.NewGCPKMSSource("", ring, token, nil))
		}
	}
	return sources
}

// keyInventoryProviderTimeout and sshUserKeyInventory are test seams (W24-33).
var keyInventoryProviderTimeout = keyinventory.DefaultProviderTimeout
var sshUserKeyInventory = sshkeys.Shared

// discoverySSHHostKeyLister adapts the discovery provider's SSH endpoints.
type discoverySSHHostKeyLister struct{ p DiscoveryProvider }

const sshHostKeyMaxPages = 100

func (l discoverySSHHostKeyLister) ListSSHHostKeys(ctx context.Context) ([]keyinventory.SSHHostKeyRecord, error) {
	var out []keyinventory.SSHHostKeyRecord
	cursor := 0
	for page := 0; page < sshHostKeyMaxPages; page++ {
		res, err := l.p.ListEndpoints(ctx, DiscoveryEndpointQuery{Protocol: "ssh", Limit: 100, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, ep := range res.Endpoints {
			if len(ep.SSHHostKeyAlgorithms) == 0 {
				continue
			}
			out = append(out, keyinventory.SSHHostKeyRecord{
				Host: ep.Hostname, Port: ep.Port, Algorithms: ep.SSHHostKeyAlgorithms, LastScanned: ep.LastSeenAt,
			})
		}
		if res.NextCursor == nil {
			break
		}
		cursor = *res.NextCursor
	}
	return out, nil
}

// keyInventoryDiscovery is the discovery provider the SSH host-key source
// reads; registerKeyInventoryHandler sets it once at registration so other
// reports (executive summary, W24-35) collect the same unified inventory.
var keyInventoryDiscovery DiscoveryProvider

// collectKeyInventory gathers cloud, SSH host and SSH user keys, each provider
// bounded by keyInventoryProviderTimeout.
func collectKeyInventory(ctx context.Context) keyinventory.KeyInventory {
	sources := newKeyInventorySources(ctx)
	if keyInventoryDiscovery != nil {
		sources = append(sources, keyinventory.NewSSHHostKeySource(discoverySSHHostKeyLister{keyInventoryDiscovery}))
	}
	sources = append(sources, keyinventory.NewSSHUserKeySource(sshUserKeyInventory, time.Now))
	return keyinventory.CollectWithTimeout(ctx, keyInventoryProviderTimeout, sources...)
}

// sanitizeInventoryErrors keeps the raw cloud SDK errors (ARNs, account and
// tenant ids, key-ring paths) in the server log and hands the client only
// the provider name. Collect formats each error as "<provider>: <error>".
func sanitizeInventoryErrors(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		logging.Infof("key inventory: provider error: %s", e)
		provider := "provider"
		if i := strings.Index(e, ": "); i > 0 && !strings.ContainsAny(e[:i], " /:") {
			provider = e[:i]
		}
		out = append(out, "cloud key inventory unavailable: "+provider)
	}
	return out
}

func firstNonEmptyEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// registerKeyInventoryHandler mounts the unified cloud key inventory.
//
// CLOUD-001: the inventory enumerates every KMS key in the hub's cloud
// accounts and fans out live to each provider, so authentication alone is
// not enough. It needs key.manage or report.read, resolved by the same
// principalPermissions the write gate uses (mcp-agent resolves to nothing).
func registerKeyInventoryHandler(mux *http.ServeMux, auth *Authenticator, roles *CustomRoleStore, auditProvider AuditProvider, discovery DiscoveryProvider) {
	keyInventoryDiscovery = discovery
	mux.HandleFunc("/api/v1/inventory/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "inventory.keys", "inventory", "cloud-keys", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := pd.ID
		if perms, admin := principalPermissions(pd, roles); !admin && !perms["key.manage"] && !perms["report.read"] {
			emitAuditEvent(r, auditProvider, principal, "inventory.keys", "inventory", "cloud-keys", AuditOutcomeDenied)
			writeForbidden(w, "key.manage or report.read permission required")
			return
		}

		inv := collectKeyInventory(r.Context())

		resp := KeyInventoryResponse{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Total:       len(inv.Keys),
			PQCSummary:  map[string]int{},
			Providers:   []string{},
			Keys:        inv.Keys,
			Errors:      sanitizeInventoryErrors(inv.Errors),
		}
		if resp.Keys == nil {
			resp.Keys = []keyinventory.Key{}
		}
		seen := map[string]bool{}
		for _, k := range inv.Keys {
			readiness := k.PQCReadiness
			if readiness == "" {
				readiness = "unknown"
			}
			resp.PQCSummary[readiness]++
			if !seen[k.Provider] {
				seen[k.Provider] = true
				resp.Providers = append(resp.Providers, k.Provider)
			}
		}

		// A partial result is a success: the request did what it could and
		// names what it could not. Errors ride in the body, not the status.
		outcome := "success"
		if len(inv.Errors) > 0 {
			outcome = "partial"
		}
		emitAuditEventDetail(r, auditProvider, principal, "inventory.keys", "inventory", "cloud-keys", AuditOutcomeSuccess,
			fmt.Sprintf(`{"result":%q,"keys":%d}`, outcome, resp.Total))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data KeyInventoryResponse `json:"data"`
		}{Data: resp}); err != nil {
			logging.Warnf("failed to encode key inventory: %v", err)
		}
	})
}
