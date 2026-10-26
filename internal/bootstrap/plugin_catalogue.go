// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Install from the signed plugin catalogue (W38-11, D-311, D-328). The hub
// fetches catalogue.json only when an administrator asks (the catalogue tab
// or the API), never in the background. The catalogue is verified with the
// keys PluginTrust already holds, so no new trust root exists: a catalogue
// signed by anything else is refused. An install then downloads the manifest,
// module and bundle and hands them to DeliveryPluginManager.Install, the
// same function a manual upload calls, so the SHA-256 pin, trust tier and
// the enable-time approval rules are identical by construction.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/plugins/delivery"
)

// DefaultPluginCatalogueURL is where first-party plugins are published.
// KRYPTKEEPER_PLUGIN_CATALOGUE_URL overrides it; set empty it disables the
// catalogue (air-gapped hubs use the offline import instead).
const DefaultPluginCatalogueURL = "https://kryptkeeper.io/plugins/catalogue.json"

const pluginCatalogueEnv = "KRYPTKEEPER_PLUGIN_CATALOGUE_URL"

var (
	errCatalogueOff      = errors.New("the plugin catalogue is turned off (KRYPTKEEPER_PLUGIN_CATALOGUE_URL is empty)")
	errCatalogueFetch    = errors.New("plugin catalogue unavailable")
	errCatalogueVerify   = errors.New("plugin catalogue signature does not verify against a trusted plugin-signing key")
	errCatalogueNotFound = errors.New("plugin not found in the catalogue")
	errCatalogueIncompat = errors.New("this plugin version needs a newer hub")
	errCatalogueMismatch = errors.New("catalogue entry does not match the downloaded files")
)

// PluginCatalogue is the catalogue source for one hub.
type PluginCatalogue struct {
	url        string
	client     *http.Client
	mgr        *DeliveryPluginManager
	hubVersion string
}

// PluginCatalogueURLFromEnv returns the configured catalogue URL: the
// default when the variable is unset, "" (disabled) when set but blank.
func PluginCatalogueURLFromEnv() string {
	if v, ok := os.LookupEnv(pluginCatalogueEnv); ok {
		return strings.TrimSpace(v)
	}
	return DefaultPluginCatalogueURL
}

// catalogueHTTPClient is the only client the catalogue uses. Private space is
// reachable because an operator may mirror the catalogue internally; the
// KRYPTKEEPER_EGRESS_DENY_PRIVATE switch still applies. Redirects stay on the
// same host.
func catalogueHTTPClient() *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:          true,
		AllowLoopback:         egressAllowLoopback,
		RequireHTTPS:          !egressAllowLoopback,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               60 * time.Second,
	}))
}

// EnableCatalogue attaches a catalogue to the manager. hubVersion gates
// min_hub_version ("dev" or unparseable versions are treated as compatible).
// A blank url leaves the catalogue disabled.
func (m *DeliveryPluginManager) EnableCatalogue(url, hubVersion string) {
	if m == nil || strings.TrimSpace(url) == "" {
		return
	}
	m.catalogue = &PluginCatalogue{url: strings.TrimSpace(url), client: catalogueHTTPClient(), mgr: m, hubVersion: hubVersion}
}

// verifyCatalogue checks the signature over the exact catalogue bytes, then
// parses them. Only a key PluginTrust holds may sign a catalogue; an unsigned
// one is refused (Classify would call it community, which is not enough).
func (c *PluginCatalogue) verifyCatalogue(raw []byte, bundle string) (delivery.Catalogue, error) {
	if strings.TrimSpace(bundle) == "" {
		return delivery.Catalogue{}, errCatalogueVerify
	}
	tier, _, err := c.mgr.trust.Classify(raw, bundle)
	if err != nil || (tier != PluginTierFirstParty && tier != PluginTierVerified) {
		return delivery.Catalogue{}, errCatalogueVerify
	}
	return delivery.ParseCatalogue(raw)
}

// Load fetches and verifies the catalogue. The signature bundle sits beside
// it at <url>.bundle.
func (c *PluginCatalogue) Load(ctx context.Context) (delivery.Catalogue, error) {
	raw, err := delivery.Download(ctx, c.client, c.url, delivery.MaxCatalogueBytes)
	if err != nil {
		return delivery.Catalogue{}, fmt.Errorf("%w: %v", errCatalogueFetch, err)
	}
	bundle, err := delivery.Download(ctx, c.client, c.url+".bundle", delivery.MaxBundleBytes)
	if err != nil {
		return delivery.Catalogue{}, fmt.Errorf("%w: %v", errCatalogueFetch, err)
	}
	return c.verifyCatalogue(raw, string(bundle))
}

// PluginCatalogueRow is one catalogue entry with its local status.
type PluginCatalogueRow struct {
	delivery.CatalogueEntry
	// Status is "available", "installed" (this version) or "upgradable"
	// (an older version is installed).
	Status           string `json:"status"`
	InstalledVersion string `json:"installed_version,omitempty"`
	Compatible       bool   `json:"compatible"`
}

// hubCompatible reports whether the entry runs on this hub version.
func (c *PluginCatalogue) hubCompatible(e delivery.CatalogueEntry) bool {
	if e.MinHubVersion == "" {
		return true
	}
	cmp, ok := delivery.CompareVersions(c.hubVersion, e.MinHubVersion)
	return !ok || cmp >= 0
}

// Rows annotates the catalogue with what is installed.
func (c *PluginCatalogue) Rows(ctx context.Context, cat delivery.Catalogue) ([]PluginCatalogueRow, error) {
	installed, err := c.mgr.List(ctx)
	if err != nil {
		return nil, err
	}
	have := map[string][]string{}
	for _, p := range installed {
		for _, v := range p.Versions {
			have[p.ID] = append(have[p.ID], v.Version)
		}
	}
	rows := make([]PluginCatalogueRow, 0, len(cat.Entries))
	for _, e := range cat.Entries {
		row := PluginCatalogueRow{CatalogueEntry: e, Status: "available", Compatible: c.hubCompatible(e)}
		for _, v := range have[e.ID] {
			cmp, ok := delivery.CompareVersions(v, e.Version)
			switch {
			case v == e.Version:
				row.Status, row.InstalledVersion = "installed", v
			case ok && cmp < 0 && row.Status != "installed":
				row.Status, row.InstalledVersion = "upgradable", v
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Install downloads one catalogue entry and installs it exactly as an upload.
func (c *PluginCatalogue) Install(ctx context.Context, id, version, by string) (DeliveryPluginVersion, error) {
	cat, err := c.Load(ctx)
	if err != nil {
		return DeliveryPluginVersion{}, err
	}
	e, ok := cat.Find(id, version)
	if !ok {
		return DeliveryPluginVersion{}, errCatalogueNotFound
	}
	if !c.hubCompatible(e) {
		return DeliveryPluginVersion{}, fmt.Errorf("%w (needs %s)", errCatalogueIncompat, e.MinHubVersion)
	}
	manifest, err := delivery.Download(ctx, c.client, e.ManifestURL, delivery.MaxManifestBytes)
	if err != nil {
		return DeliveryPluginVersion{}, fmt.Errorf("%w: %v", errCatalogueFetch, err)
	}
	bundle, err := delivery.Download(ctx, c.client, e.BundleURL, delivery.MaxBundleBytes)
	if err != nil {
		return DeliveryPluginVersion{}, fmt.Errorf("%w: %v", errCatalogueFetch, err)
	}
	wasm, err := delivery.Download(ctx, c.client, e.WasmURL, delivery.MaxCatalogueModule)
	if err != nil {
		return DeliveryPluginVersion{}, fmt.Errorf("%w: %v", errCatalogueFetch, err)
	}
	return c.installFiles(ctx, e, manifest, bundle, wasm, by)
}

// installFiles is shared by the online install and the offline import: it
// binds the entry to the files, then calls the one install path.
func (c *PluginCatalogue) installFiles(ctx context.Context, e delivery.CatalogueEntry, manifest, bundle, wasm []byte, by string) (DeliveryPluginVersion, error) {
	sum := sha256.Sum256(wasm)
	if hex.EncodeToString(sum[:]) != e.SHA256 {
		return DeliveryPluginVersion{}, delivery.ErrHashMismatch
	}
	man, err := abi.ParseManifest(manifest)
	if err != nil {
		return DeliveryPluginVersion{}, err
	}
	if man.ID != e.ID || man.Version != e.Version || man.Artifact.SHA256 != e.SHA256 {
		return DeliveryPluginVersion{}, errCatalogueMismatch
	}
	// An unsigned manifest would install as community; the catalogue promises
	// signed plugins, so a missing bundle is refused here rather than
	// downgraded by Install.
	if strings.TrimSpace(string(bundle)) == "" {
		return DeliveryPluginVersion{}, errPluginSignature
	}
	return c.mgr.Install(ctx, manifest, wasm, string(bundle), by)
}

// ImportCatalogue installs one plugin from catalogue files carried in by hand
// (air-gapped hubs): the catalogue and its bundle from a release asset, plus
// that plugin's manifest, bundle and module. It verifies the catalogue the
// same way Load does and never touches the network.
func (m *DeliveryPluginManager) ImportCatalogue(ctx context.Context, catalogue []byte, catalogueBundle string, id, version string, manifest, bundle, wasm []byte, by string) (DeliveryPluginVersion, error) {
	c := &PluginCatalogue{mgr: m}
	cat, err := c.verifyCatalogue(catalogue, catalogueBundle)
	if err != nil {
		return DeliveryPluginVersion{}, err
	}
	e, ok := cat.Find(id, version)
	if !ok {
		return DeliveryPluginVersion{}, errCatalogueNotFound
	}
	return c.installFiles(ctx, e, manifest, bundle, wasm, by)
}
