// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

// The signed plugin catalogue (W37-11 as W38-11, D-311, D-328). catalogue.json
// lists first-party plugin versions with the URLs of their manifest, module
// and cosign bundle. This file holds the format, its validation, version
// ordering and a size-capped download. Signature checking and the install
// itself stay in internal/bootstrap, next to PluginTrust and the install path
// a manual upload uses, so the catalogue adds no second trust path.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// CatalogueFormat is the only catalogue.json "version" this hub reads.
const CatalogueFormat = 1

// Download caps. A module may be large; a manifest or signature never is.
const (
	MaxCatalogueBytes  = 4 << 20
	MaxManifestBytes   = 1 << 20
	MaxBundleBytes     = 64 << 10
	MaxCatalogueModule = 32 << 20
)

// CatalogueEntry is one installable plugin version.
type CatalogueEntry struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Publisher   string `json:"publisher"`
	Version     string `json:"version"`
	Description string `json:"description"`
	ManifestURL string `json:"manifest_url"`
	WasmURL     string `json:"wasm_url"`
	// BundleURL is the cosign bundle over the exact bytes at ManifestURL.
	BundleURL string `json:"bundle_url"`
	// SHA256 is the module's digest; it must equal the manifest's pinned one.
	SHA256 string `json:"sha256"`
	// Capabilities is a display summary only. The manifest decides what the
	// plugin may do, and the install path shows the manifest's own wording.
	Capabilities  []string `json:"capabilities"`
	MinHubVersion string   `json:"min_hub_version,omitempty"`
}

// Catalogue is the parsed catalogue.json.
type Catalogue struct {
	Version     int              `json:"version"`
	GeneratedAt string           `json:"generated_at"`
	Entries     []CatalogueEntry `json:"entries"`
}

var catalogueSemver = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)
var catalogueHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseCatalogue decodes and validates catalogue bytes. Unknown fields are
// refused so a newer format never half-works on an older hub. Every URL must
// be absolute http(s); the egress policy decides which are reachable.
func ParseCatalogue(raw []byte) (Catalogue, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Catalogue
	if err := dec.Decode(&c); err != nil {
		return Catalogue{}, fmt.Errorf("catalogue: %w", err)
	}
	if dec.More() {
		return Catalogue{}, errors.New("catalogue: trailing data")
	}
	if c.Version != CatalogueFormat {
		return Catalogue{}, fmt.Errorf("catalogue: format version %d is not supported (want %d)", c.Version, CatalogueFormat)
	}
	seen := map[string]bool{}
	for i, e := range c.Entries {
		if err := e.validate(); err != nil {
			return Catalogue{}, fmt.Errorf("catalogue: entry %d (%s): %w", i, e.ID, err)
		}
		key := e.ID + "@" + e.Version
		if seen[key] {
			return Catalogue{}, fmt.Errorf("catalogue: %s listed twice", key)
		}
		seen[key] = true
	}
	return c, nil
}

func (e CatalogueEntry) validate() error {
	if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.Publisher) == "" {
		return errors.New("id, name and publisher are required")
	}
	if _, ok := parseSemver(e.Version); !ok {
		return fmt.Errorf("version %q is not semver", e.Version)
	}
	if e.MinHubVersion != "" {
		if _, ok := parseSemver(e.MinHubVersion); !ok {
			return fmt.Errorf("min_hub_version %q is not semver", e.MinHubVersion)
		}
	}
	if !catalogueHex.MatchString(e.SHA256) {
		return errors.New("sha256 must be 64 lowercase hex characters")
	}
	kind := e.Kind
	if kind == "" {
		kind = abi.KindDelivery
	}
	if !abi.Kinds[kind] {
		return fmt.Errorf("kind %q is not supported", kind)
	}
	for _, u := range []string{e.ManifestURL, e.WasmURL, e.BundleURL} {
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return fmt.Errorf("%q is not an absolute http(s) URL", u)
		}
	}
	return nil
}

type semver struct {
	n   [3]int
	pre string
}

func parseSemver(s string) (semver, bool) {
	m := catalogueSemver.FindStringSubmatch(s)
	if m == nil {
		return semver{}, false
	}
	var v semver
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return semver{}, false
		}
		v.n[i] = n
	}
	v.pre = m[4]
	return v, true
}

// CompareVersions orders two semver strings (-1, 0, 1). A pre-release sorts
// below its release; two pre-releases compare as text, which is enough to
// pick a default install version and flag an upgrade. ok is false when either
// side is not semver, and the caller must then treat the answer as unknown.
func CompareVersions(a, b string) (int, bool) {
	x, okA := parseSemver(a)
	y, okB := parseSemver(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if x.n[i] != y.n[i] {
			if x.n[i] < y.n[i] {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case x.pre == y.pre:
		return 0, true
	case x.pre == "":
		return 1, true
	case y.pre == "":
		return -1, true
	case x.pre < y.pre:
		return -1, true
	}
	return 1, true
}

// Find returns the entry for id at version, or the highest version of id
// when version is empty.
func (c Catalogue) Find(id, version string) (CatalogueEntry, bool) {
	var best CatalogueEntry
	found := false
	for _, e := range c.Entries {
		if e.ID != id {
			continue
		}
		if version != "" {
			if e.Version == version {
				return e, true
			}
			continue
		}
		if !found {
			best, found = e, true
			continue
		}
		if cmp, ok := CompareVersions(e.Version, best.Version); ok && cmp > 0 {
			best = e
		}
	}
	return best, found
}

// ErrCatalogueTooLarge is returned when a download passes its cap.
var ErrCatalogueTooLarge = errors.New("catalogue download is larger than allowed")

// Download GETs rawURL with client (which must be the egress-guarded one) and
// returns at most max bytes; a longer body is an error, not a truncation,
// because a cut-off manifest would fail its signature in a confusing way.
func Download(ctx context.Context, client *http.Client, rawURL string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, ErrCatalogueTooLarge
	}
	return body, nil
}
