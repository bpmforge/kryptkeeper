// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command healthcheck is the container HEALTHCHECK probe for the hub image.
// It has no shell/curl dependency (this image is distroless), so it must be
// a real HTTP(S) client. W19-23: the hub's default listener now serves TLS
// with a self-issued certificate (see cmd/kryptkeeper/tls.go), so this
// binary must be able to verify that certificate against the hub's own CA
// bundle rather than either failing closed on every boot or -- the thing
// CLAUDE.md forbids outright -- skipping verification.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	os.Exit(run(os.Getenv("HEALTHCHECK_URL"), os.Getenv("HEALTHCHECK_CA_FILE"), os.Stderr))
}

// run performs the health probe and returns the process exit code. It is
// separated from main so tests can drive it without exec'ing a subprocess.
func run(url, caFile string, stderr *os.File) int {
	if url == "" {
		url = "http://127.0.0.1:8080/healthz"
	}

	client, err := newHealthcheckClient(caFile)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck request failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		fmt.Fprintf(stderr, "healthcheck status not healthy: %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

// newHealthcheckClient builds an http.Client. With no caFile it is the
// stdlib default (system roots) -- correct for a plain-HTTP or
// operator-supplied-cert deployment. With caFile set, it trusts *only* that
// CA bundle: a self-issued hub CA is never in the system root store, and
// InsecureSkipVerify is never an option here (CLAUDE.md: "never loosen a
// verification path to make a gate green") -- a wrong or missing CA file
// must fail the probe, not silently pass it.
func newHealthcheckClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return &http.Client{Timeout: 2 * time.Second}, nil
	}

	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates found in CA file %s", caFile)
	}

	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}, nil
}
