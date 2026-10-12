// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// kryptkeeper-agent is a lightweight satellite agent that discovers certificates
// on the local host and reports them to the Kryptkeeper Hub for lifecycle management.
//
// Environment variables:
//
//	KRYPTKEEPER_HUB_URL       Hub base URL (required, e.g. https://kryptkeeper.example.com)
//	KRYPTKEEPER_AGENT_NAME    Human-readable name for this agent (default: hostname)
//	KRYPTKEEPER_AGENT_TYPE    Agent type: linux | mac | windows (default: detected from OS)
//	KRYPTKEEPER_AGENT_ID      Agent ID from prior registration (omit to auto-register)
//	KRYPTKEEPER_AGENT_TOKEN   Agent token from prior registration (omit to auto-register)
//	KRYPTKEEPER_AGENT_CREDENTIALS_FILE  Where a console run keeps its registration (0600; default
//	                          <user config dir>/kryptkeeper-agent/credentials.env); read on start
//	KRYPTKEEPER_POLL_INTERVAL Polling interval in seconds (default: 300)
//	KRYPTKEEPER_SCAN_PATHS    Comma-separated cert directory paths to scan (default: standard paths)
//	KRYPTKEEPER_CONFIG_PATHS  Comma-separated config directories to scan for cert references
//	KRYPTKEEPER_WEB_ROOT      Web root for ACME HTTP-01 challenge files (optional)
//	KRYPTKEEPER_HUB_CA_CERT      Inline PEM CA bundle to verify the Hub's TLS
//	                             certificate (default: system roots)
//	KRYPTKEEPER_HUB_CA_CERT_FILE Path to the same, if not passed inline
//
// Flags:
//
//	--generate-systemd   Print a systemd unit file to stdout and exit
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/agentclient"
	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/agentinstall"
)

// version/commit/date are injected by .goreleaser.yaml's ldflags at release
// build time (W20-02); "dev"/"unknown" is what a plain `go build` leaves.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Handle generator flags before requiring HUB_URL.
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--generate-systemd":
			fmt.Print(generateSystemdUnit())
			os.Exit(0)
		case "--generate-sudoers":
			fmt.Print(generateSudoers())
			os.Exit(0)
		case "--version":
			fmt.Printf("kryptkeeper-agent %s (commit %s, built %s)\n", version, commit, date)
			os.Exit(0)
		}
	}

	// W18-07: under the Windows Service Control Manager the agent is started
	// without an interactive environment; the service shim loads its settings
	// from a file and drives run() until the SCM asks it to stop.
	if runAsWindowsService(run) {
		return
	}
	run(context.Background())
}

// run is the agent loop. It returns when ctx is cancelled (service stop);
// as a console process ctx is never cancelled.
func run(ctx context.Context) {
	hubURL := mustEnv("KRYPTKEEPER_HUB_URL")

	agentName := os.Getenv("KRYPTKEEPER_AGENT_NAME")
	if agentName == "" {
		hostname, _ := os.Hostname()
		agentName = hostname
	}
	if agentName == "" {
		agentName = "kryptkeeper-agent"
	}

	agentType := agentclient.AgentType(os.Getenv("KRYPTKEEPER_AGENT_TYPE"))
	if agentType == "" {
		agentType = defaultAgentType()
	}

	// A console run keeps its registration in a private credentials file
	// (never in logs) and reloads it here; the Windows service keeps it in
	// its settings file instead.
	credFile := ""
	if serviceEnvFile == "" {
		credFile = credentialsFilePath()
		if credFile != "" {
			if err := loadEnvFile(credFile); err != nil && !os.IsNotExist(err) {
				log.Fatalf("load agent credentials from %s: %v", credFile, err)
			}
		}
	}
	agentID := os.Getenv("KRYPTKEEPER_AGENT_ID")
	agentToken := os.Getenv("KRYPTKEEPER_AGENT_TOKEN")

	pollInterval := 300 * time.Second
	if raw := os.Getenv("KRYPTKEEPER_POLL_INTERVAL"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollInterval = time.Duration(n) * time.Second
		}
	}

	scanPaths := agentdiscovery.DefaultLinuxPaths
	if raw := os.Getenv("KRYPTKEEPER_SCAN_PATHS"); raw != "" {
		scanPaths = strings.Split(raw, ",")
	}

	configPaths := agentdiscovery.DefaultConfigPaths
	if raw := os.Getenv("KRYPTKEEPER_CONFIG_PATHS"); raw != "" {
		configPaths = strings.Split(raw, ",")
	}

	webRoot := os.Getenv("KRYPTKEEPER_WEB_ROOT")

	// W19-32: the Hub has self-issued its own TLS listener by default since
	// W19-14, so the agent needs an explicit trust anchor for it -- a bad
	// bundle fails startup here rather than surfacing as a confusing TLS
	// error on the first heartbeat.
	hubRootCAs, err := agentclient.HubCACertPoolFromEnv()
	if err != nil {
		log.Fatalf("hub CA trust: %v", err)
	}

	client := agentclient.New(hubURL, agentID, agentToken, hubRootCAs)
	client.EnrollmentSecret = os.Getenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRET")

	if agentID == "" || agentToken == "" {
		log.Printf("registering agent %q (%s) with hub %s", agentName, agentType, hubURL)
		resp, err := client.Register(context.Background(), agentName, agentType)
		if err != nil {
			log.Fatalf("registration failed: %v", err)
		}
		log.Printf("registered: agent_id=%s", resp.AgentID)
		if serviceEnvFile != "" {
			// A service restarts on every boot; without persisting, each start
			// would register a fresh agent and orphan the previous one.
			if err := persistCredentials(serviceEnvFile, resp.AgentID, resp.Token); err != nil {
				log.Fatalf("persist agent credentials to %s: %v", serviceEnvFile, err)
			}
			log.Printf("agent credentials saved to %s", serviceEnvFile)
		} else {
			// The token is never logged (log sinks are not a secret store);
			// it goes to a 0600 file the next start reads back.
			if credFile == "" {
				log.Printf("agent registered as %s; no credentials file location (set KRYPTKEEPER_AGENT_CREDENTIALS_FILE), so the agent will re-register on its next start", resp.AgentID)
			} else if err := writeCredentialsFile(credFile, resp.AgentID, resp.Token); err != nil {
				log.Fatalf("persist agent credentials to %s: %v", credFile, err)
			} else {
				log.Printf("agent registered as %s; credentials saved to %s (mode 0600)", resp.AgentID, credFile)
			}
		}
	}

	log.Printf("agent %s starting; hub=%s poll=%s", client.AgentID, hubURL, pollInterval)

	for {
		runCycle(client, scanPaths, configPaths, webRoot, hubRootCAs)
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

func runCycle(client *agentclient.Client, scanPaths, configPaths []string, webRoot string, hubRootCAs *x509.CertPool) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := client.Heartbeat(ctx); err != nil {
		log.Printf("heartbeat error: %v", err)
	}

	// Discover certs from filesystem and Windows store (platform-specific).
	certs, err := agentdiscovery.WalkCerts(scanPaths)
	if err != nil {
		log.Printf("discovery error: %v", err)
	}

	// Also discover certs referenced in web server config files.
	var endpoints []agentclient.Endpoint
	if len(configPaths) > 0 {
		cfgCerts, err := agentdiscovery.WalkConfigCerts(configPaths)
		if err != nil {
			log.Printf("config discovery error: %v", err)
		}
		certs = append(certs, cfgCerts...)

		// v1.3 autopilot: discover installable endpoints (cert+key+server+port).
		endpoints = agentdiscovery.WalkEndpoints(configPaths)
	}

	log.Printf("discovered %d certificates, %d endpoints", len(certs), len(endpoints))

	if len(certs) > 0 || len(endpoints) > 0 {
		accepted, err := client.PostInventory(ctx, certs, endpoints)
		if err != nil {
			log.Printf("inventory post error: %v", err)
		} else {
			log.Printf("hub accepted %d certificates (%d endpoints)", accepted, len(endpoints))
		}
	}

	tasks, err := client.GetTasks(ctx)
	if err != nil {
		log.Printf("get tasks error: %v", err)
		return
	}

	renewer := agentclient.NewAcmeRenewer(client.HubURL, hubRootCAs)
	for _, task := range tasks {
		log.Printf("task %s: %s %s (expires %s)", task.TaskID, task.Action, task.Subject,
			task.NotAfter.Format("2006-01-02"))
		if task.Action == "renew" {
			go renewAsync(client, renewer, task, webRoot)
		}
	}
}

func renewAsync(client *agentclient.Client, renewer *agentclient.AcmeRenewer, task agentclient.RenewalTask, webRoot string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	identifiers := renewalIdentifiers(task)
	if len(identifiers) == 0 {
		// W19-13: a pre-W19-13 hub sent no Identifiers and task.Subject's CN
		// isn't a hostname either -- there is nothing an ACME order could
		// validate. Using task.Subject (a full RDN string like
		// "CN=localhost") here was the original bug (UAT W19-04).
		log.Printf("renew %s: no usable DNS identifier, skipping", task.Subject)
		return
	}
	result, err := renewer.Renew(ctx, identifiers, webRoot)
	if err != nil {
		log.Printf("renew %s: %v", task.Subject, err)
		return
	}
	log.Printf("renewed %s: cert %d bytes", task.Subject, len(result.CertPEM))

	// v1.3 autopilot: if the task carries install hints, install the renewed
	// cert where the web server reads it, validate, reload, and verify (with
	// rollback), then report the outcome to the Hub.
	if task.CertPath == "" {
		return
	}
	newFP := leafFingerprint(result.CertPEM)
	installer := agentinstall.New(agentinstall.NewSudoExecutor())
	res, err := installer.Install(ctx, agentinstall.InstallRequest{
		ServerType:          string(task.ServerType),
		CertPath:            task.CertPath,
		KeyPath:             task.KeyPath,
		CertPEM:             result.CertPEM,
		KeyPEM:              result.KeyPEM,
		ReloadMethod:        task.ReloadMethod,
		VerifyHostPort:      task.VerifyHostPort,
		ExpectedFingerprint: newFP,
	})
	if err != nil {
		log.Printf("install %s: %v (outcome=%s rolled_back=%v)", task.Subject, err, res.Outcome, res.RolledBack)
	} else {
		log.Printf("installed %s: cert=%s outcome=%s verified=%v", task.Subject, task.CertPath, res.Outcome, res.Verified)
	}

	if rerr := client.PostRenewalResult(ctx, agentclient.RenewalResult{
		TaskID:            task.TaskID,
		Fingerprint:       newFP,
		Outcome:           res.Outcome,
		ServedFingerprint: res.ServedFingerprint,
		RolledBack:        res.RolledBack,
		Detail:            res.Detail,
	}); rerr != nil {
		log.Printf("report result %s: %v", task.Subject, rerr)
	}
}

// renewalIdentifiers returns the DNS identifiers to use for task's ACME
// order: task.Identifiers if the hub sent them (W19-13+), else a parsed CN
// from task.Subject if it is a syntactically valid hostname. Never returns
// task.Subject itself -- that is a full RDN string (e.g. "CN=localhost") and
// was the original bug this compatibility path guards against (UAT W19-04).
// task.Identifiers is passed through unvalidated: the hub's renewalIdentifiers
// (internal/bootstrap/handlers_agents.go) already validated every entry it
// sends, and re-validating here would silently drop an identifier a newer
// hub deliberately included.
func renewalIdentifiers(task agentclient.RenewalTask) []string {
	if len(task.Identifiers) > 0 {
		return task.Identifiers
	}
	if host, ok := parseCNHostname(task.Subject); ok {
		return []string{host}
	}
	return nil
}

// parseCNHostname extracts the CN attribute value from an RDN string in the
// form pkix.Name.String() produces (e.g. "CN=localhost,O=Example") and
// reports whether it is a syntactically valid hostname. Duplicated from
// internal/bootstrap/handlers_agents.go's identical helper -- CLAUDE.md rules
// out a shared util package for a ~15-line parser two independent binaries
// each need once.
func parseCNHostname(subject string) (string, bool) {
	for _, part := range splitRDN(subject) {
		if v, ok := strings.CutPrefix(part, "CN="); ok {
			v = strings.TrimSpace(v)
			return v, isValidHostname(v)
		}
	}
	return "", false
}

// splitRDN splits a pkix.Name.String() RDN sequence on unescaped commas
// (RFC 2253 backslash-escapes a literal comma inside an attribute value).
func splitRDN(s string) []string {
	var parts []string
	var cur strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ',':
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, strings.TrimSpace(cur.String()))
	return parts
}

// isValidHostname reports whether h is a syntactically valid DNS hostname.
// Single-label names like "localhost" are accepted; an IP literal or
// anything with invalid label characters is not.
func isValidHostname(h string) bool {
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				return false
			}
		}
	}
	return true
}

// leafFingerprint returns the lowercase-hex SHA-256 of the first certificate in
// a PEM bundle (the leaf), or "" if none is found.
func leafFingerprint(certPEM []byte) string {
	for block, rest := pem.Decode(certPEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			return agentinstall.FingerprintSHA256(block.Bytes)
		}
	}
	return ""
}

func defaultAgentType() agentclient.AgentType {
	switch runtime.GOOS {
	case "darwin":
		return agentclient.AgentTypeMac
	case "windows":
		return agentclient.AgentTypeWindows
	default:
		return agentclient.AgentTypeLinux
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

// generateSudoers returns the sudoers drop-in for Renewal Autopilot (v1.3).
// It grants the agent ONLY the commands needed to install renewed certs and
// reload the web server — the narrow privilege model from the v1.3 scope.
//
// NOTE: the default systemd unit sets NoNewPrivileges=true, which blocks sudo.
// Autopilot requires setting NoNewPrivileges=false in the unit; until then the
// agent stays discovery+renew-only and never installs. This is an opt-in.
func generateSudoers() string {
	return `# Kryptkeeper Agent — Renewal Autopilot privilege allowlist (v1.3)
#
# Install:   kryptkeeper-agent --generate-sudoers | sudo tee /etc/sudoers.d/kryptkeeper-agent
# Secure:    sudo chmod 0440 /etc/sudoers.d/kryptkeeper-agent
# Validate:  sudo visudo -cf /etc/sudoers.d/kryptkeeper-agent
#
# Tighten the cert-directory globs below to the exact paths discovered on THIS
# host before deploying. Wildcards do not span '/', so list each cert dir.
#
# Also required for autopilot: set NoNewPrivileges=false in the systemd unit
# (the default true value blocks sudo). Leave it true to keep the agent
# discovery+renew-only (no install).

Cmnd_Alias KK_INSTALL = /usr/bin/install -m * /etc/nginx/ssl/*, /usr/bin/install -m * /etc/apache2/ssl/*
Cmnd_Alias KK_READ    = /bin/cat /etc/nginx/ssl/*, /bin/cat /etc/apache2/ssl/*
Cmnd_Alias KK_TEST    = /usr/sbin/nginx -t, /usr/sbin/apachectl configtest, /usr/bin/apachectl configtest
Cmnd_Alias KK_RELOAD  = /usr/bin/systemctl reload nginx, /usr/bin/systemctl reload apache2, /usr/sbin/nginx -s reload, /usr/sbin/apachectl -k graceful

kryptkeeper-agent ALL=(root) NOPASSWD: KK_INSTALL, KK_READ, KK_TEST, KK_RELOAD
`
}

// generateSystemdUnit returns a systemd unit file for the kryptkeeper-agent service.
func generateSystemdUnit() string {
	return `[Unit]
Description=Kryptkeeper Satellite Agent
Documentation=https://github.com/bpmforge/kryptkeeper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=kryptkeeper-agent
Group=kryptkeeper-agent
ExecStart=/usr/local/bin/kryptkeeper-agent
Restart=on-failure
RestartSec=30s

# Required environment variables — set values before enabling.
Environment=KRYPTKEEPER_HUB_URL=https://your-hub.example.com
Environment=KRYPTKEEPER_AGENT_ID=<agent-id-from-registration>
Environment=KRYPTKEEPER_AGENT_TOKEN=<token-from-registration>

# Optional tuning
#Environment=KRYPTKEEPER_POLL_INTERVAL=300
#Environment=KRYPTKEEPER_SCAN_PATHS=/etc/ssl,/etc/pki/tls
#Environment=KRYPTKEEPER_WEB_ROOT=/var/www/html

# Hardening
# NOTE: NoNewPrivileges=true blocks sudo. To enable Renewal Autopilot (cert
# install + web-server reload), set this to false AND install the sudoers
# drop-in (kryptkeeper-agent --generate-sudoers). Leave true for
# discovery+renew-only operation.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/kryptkeeper-agent
PrivateTmp=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
`
}
