// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// kryptkeeper-certmanager is a cert-manager external issuer that delegates
// certificate signing to the Kryptkeeper Hub.
//
// Deploy inside the same Kubernetes cluster as cert-manager. The controller
// list+watches CertificateRequest resources where issuerRef.group equals
// "certmanager.kryptkeeper.io" and issues certificates via the Hub API.
//
// Environment variables:
//
//	KRYPTKEEPER_HUB_URL    Hub base URL (required)
//	KRYPTKEEPER_API_TOKEN  Hub bearer token (required)
//	KRYPTKEEPER_CA_ID      Default CA ID (required)
//	KRYPTKEEPER_TEMPLATE_ID Default template ID (required)
//	KRYPTKEEPER_NAMESPACES  Comma-separated namespaces to watch (default: all)
//	KRYPTKEEPER_RESYNC_INTERVAL Safety-net full resync interval in seconds (default: 300);
//	                          requests are normally picked up immediately via a watch
package main

import (
	"context"
	"kryptkeeper/internal/logging"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kryptkeeper/internal/certmanagerissuer"
	"kryptkeeper/internal/metrics"
)

// version/commit/date are injected by .goreleaser.yaml's ldflags at release
// build time (W20-02); "dev"/"unknown" is what a plain `go build` leaves.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			logging.Infof("kryptkeeper-certmanager %s (commit %s, built %s)", version, commit, date)
			os.Exit(0)
		}
	}

	logging.Setup(logging.ConfigFromEnv(os.Getenv))

	hubURL := mustEnv("KRYPTKEEPER_HUB_URL")
	apiToken := mustEnv("KRYPTKEEPER_API_TOKEN")
	caID := mustEnv("KRYPTKEEPER_CA_ID")
	templateID := mustEnv("KRYPTKEEPER_TEMPLATE_ID")

	var namespaces []string
	if raw := os.Getenv("KRYPTKEEPER_NAMESPACES"); raw != "" {
		namespaces = strings.Split(raw, ",")
	}

	resyncInterval := 300 * time.Second
	if raw := os.Getenv("KRYPTKEEPER_RESYNC_INTERVAL"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			resyncInterval = time.Duration(n) * time.Second
		}
	}

	k8s, err := certmanagerissuer.NewInClusterClient()
	if err != nil {
		logging.Fatalf("init k8s client: %v", err)
	}

	ctrl := certmanagerissuer.NewController(k8s, certmanagerissuer.IssuerConfig{
		HubURL:     hubURL,
		APIToken:   apiToken,
		CAID:       caID,
		TemplateID: templateID,
	}, namespaces)
	ctrl.ResyncInterval = resyncInterval

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		cfg := newOpsConfig(metrics.OpsAddrFromEnv(os.Getenv, defaultOpsAddr))
		if err := metrics.ServeOps(ctx, cfg); err != nil {
			slog.Warn("certmanager ops listener not started", "addr", cfg.Addr, "error", err)
		}
	}()

	ready.Store(true)
	err = ctrl.Run(ctx)
	ready.Store(false)
	if err != nil && err != context.Canceled {
		logging.Fatalf("controller exited: %v", err)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		logging.Fatalf("required environment variable %s is not set", key)
	}
	return v
}
