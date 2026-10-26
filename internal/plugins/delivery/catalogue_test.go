// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const goodEntry = `{"id":"kryptkeeper.a","kind":"delivery","name":"A","publisher":"P","version":"1.2.0","description":"d",
"manifest_url":"https://x.example/m.json","wasm_url":"https://x.example/p.wasm","bundle_url":"https://x.example/m.json.bundle",
"sha256":"` + "0000000000000000000000000000000000000000000000000000000000000000" + `","capabilities":["network"],"min_hub_version":"1.1.0"}`

func catalogueJSON(entries ...string) []byte {
	return []byte(`{"version":1,"generated_at":"2026-10-25T00:00:00Z","entries":[` + strings.Join(entries, ",") + `]}`)
}

func TestParseCatalogue(t *testing.T) {
	c, err := ParseCatalogue(catalogueJSON(goodEntry))
	if err != nil || len(c.Entries) != 1 {
		t.Fatalf("good catalogue: %v", err)
	}
	for name, raw := range map[string][]byte{
		"wrong format":  []byte(`{"version":2,"entries":[]}`),
		"unknown field": []byte(`{"version":1,"entries":[],"extra":1}`),
		"duplicate":     catalogueJSON(goodEntry, goodEntry),
		"bad sha":       catalogueJSON(strings.Replace(goodEntry, `"sha256":"0000`, `"sha256":"zz00`, 1)),
		"file url":      catalogueJSON(strings.Replace(goodEntry, "https://x.example/p.wasm", "file:///etc/passwd", 1)),
		"bad kind":      catalogueJSON(strings.Replace(goodEntry, `"delivery"`, `"issuer"`, 1)),
		"bad version":   catalogueJSON(strings.Replace(goodEntry, `"1.2.0"`, `"latest"`, 1)),
		"trailing":      append(catalogueJSON(), []byte(`{}`)...),
	} {
		if _, err := ParseCatalogue(raw); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestCompareVersionsAndFind(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.2.0", "1.10.0", -1}, {"2.0.0", "1.9.9", 1}, {"1.0.0", "1.0.0", 0}, {"1.0.0-rc1", "1.0.0", -1}, {"v1.1.0", "1.1.0", 0}} {
		if got, ok := CompareVersions(c.a, c.b); !ok || got != c.want {
			t.Errorf("%s vs %s: %d %v", c.a, c.b, got, ok)
		}
	}
	if _, ok := CompareVersions("dev", "1.0.0"); ok {
		t.Error("dev compared as semver")
	}
	two := strings.Replace(goodEntry, `"1.2.0"`, `"1.10.0"`, 1)
	c, err := ParseCatalogue(catalogueJSON(goodEntry, two))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := c.Find("kryptkeeper.a", ""); !ok || e.Version != "1.10.0" {
		t.Errorf("highest version: %+v", e)
	}
	if e, ok := c.Find("kryptkeeper.a", "1.2.0"); !ok || e.Version != "1.2.0" {
		t.Errorf("pinned version: %+v", e)
	}
	if _, ok := c.Find("kryptkeeper.b", ""); ok {
		t.Error("found an unlisted id")
	}
}

func TestDownloadCapsAndStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("a", 100)))
	}))
	defer srv.Close()
	ctx := context.Background()
	if b, err := Download(ctx, srv.Client(), srv.URL+"/ok", 100); err != nil || len(b) != 100 {
		t.Errorf("exact size: %d %v", len(b), err)
	}
	if _, err := Download(ctx, srv.Client(), srv.URL+"/ok", 99); err != ErrCatalogueTooLarge {
		t.Errorf("oversize: %v", err)
	}
	if _, err := Download(ctx, srv.Client(), srv.URL+"/missing", 100); err == nil {
		t.Error("a 404 was accepted")
	}
}
