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
//	KRYPTKEEPER_ENROLL_TOKEN  Single-use enrollment token minted by a hub admin (kkenr_...); exchanged for
//	                          the long-lived credential on first start, then scrubbed from the service
//	                          env file. Env/file only (never a CLI argument); never logged
//	KRYPTKEEPER_AGENT_CREDENTIALS_FILE  Where a console run keeps its registration (0600; default
//	                          <user config dir>/kryptkeeper-agent/credentials.env); read on start
//	KRYPTKEEPER_POLL_INTERVAL Polling interval in seconds (default: 60)
//	KRYPTKEEPER_SCAN_PATHS    Comma-separated cert directory paths to scan (default: standard paths; on Windows see docs/ops/WINDOWS_AGENT.md)
//	KRYPTKEEPER_CONFIG_PATHS  Comma-separated config directories to scan for cert references
//	KRYPTKEEPER_WEB_ROOT      Web root for ACME HTTP-01 challenge files (optional)
//	KRYPTKEEPER_HUB_CA_CERT      Inline PEM CA bundle to verify the Hub's TLS
//	                             certificate (default: system roots)
//	KRYPTKEEPER_HUB_CA_CERT_FILE Path to the same, if not passed inline
//
// Flags:
//
//	--generate-systemd   Print a systemd unit file to stdout and exit
//	--generate-sudoers   Print the sudoers drop-in
//	--generate-trust-store-sudoers  Print the separate, opt-in sudoers drop-in for trust store push
//	--trust-store-apply  Root half of trust store push (reached only through sudo; see docs/ops/TRUST_STORE_PUSH.md)
//
// Trust store push (W40-03) is off unless KRYPTKEEPER_TRUST_STORE_PUSH=true.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/privexec"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/agentclient"
	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/metrics"
)

// version/commit/date are injected by .goreleaser.yaml's ldflags at release
// build time (W20-02); "dev"/"unknown" is what a plain `go build` leaves.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// startupBanner is the first log line: it names the running build so an
// operator can match the agent to the version the hub lists for it.
func startupBanner() string {
	return fmt.Sprintf("kryptkeeper-agent %s (commit %s, built %s) starting", version, commit, date)
}

func main() {
	// Handle generator flags before requiring HUB_URL.
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--generate-systemd":
			fmt.Print(generateSystemdUnit())
			os.Exit(0)
		case "--generate-sudoers":
			out, err := generateSudoers(sudoersModeFlag(os.Args[1:]))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			fmt.Print(out)
			os.Exit(0)
		case "--generate-trust-store-sudoers":
			fmt.Print(trustStoreSudoers("kryptkeeper-agent"))
			os.Exit(0)
		case "--trust-store-apply":
			os.Exit(runTrustStoreHelper(os.Stdin, os.Stdout, newTrustApplier(runtime.GOOS)))
		case "--version":
			fmt.Printf("kryptkeeper-agent %s (commit %s, built %s)\n", version, commit, date)
			os.Exit(0)
		}
	}

	logging.Setup(logging.ConfigFromEnv(os.Getenv))

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
	logging.Info(startupBanner())
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
				logging.Fatalf("load agent credentials from %s: %v", credFile, err)
			}
		}
	}
	agentID := os.Getenv("KRYPTKEEPER_AGENT_ID")
	agentToken := os.Getenv("KRYPTKEEPER_AGENT_TOKEN")

	// 60s keeps a healthy agent inside the hub's 5-minute stale cutoff.
	pollInterval := 60 * time.Second
	if raw := os.Getenv("KRYPTKEEPER_POLL_INTERVAL"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollInterval = time.Duration(n) * time.Second
		}
	}

	// Probes answer while registering; readiness stays false until the first
	// heartbeat. A bind failure must not stop the agent or block service start.
	go func() {
		cfg := newOpsConfig(metrics.OpsAddrFromEnv(os.Getenv, defaultOpsAddr), pollInterval, time.Now)
		if err := metrics.ServeOps(ctx, cfg); err != nil {
			slog.Warn("agent ops listener not started", "addr", cfg.Addr, "error", err)
		}
	}()

	scanPaths := agentdiscovery.DefaultLinuxPaths
	if runtime.GOOS == "windows" {
		scanPaths = agentdiscovery.DefaultWindowsPaths(os.Getenv)
	}
	if raw := os.Getenv("KRYPTKEEPER_SCAN_PATHS"); raw != "" {
		scanPaths = strings.Split(raw, ",")
	}

	configPaths := agentdiscovery.DefaultConfigPaths
	if raw := os.Getenv("KRYPTKEEPER_CONFIG_PATHS"); raw != "" {
		configPaths = strings.Split(raw, ",")
	}

	webRoot := os.Getenv("KRYPTKEEPER_WEB_ROOT")

	// W34-09: the discovery walk runs through the same privilege layer as the
	// hub's SSH scans. Password mode needs a stored secret and is not offered.
	disc, err := newHostDiscovery(os.Getenv("KRYPTKEEPER_PRIVILEGE_MODE"))
	if err != nil {
		logging.Fatalf("%v", err)
	}

	// W19-32: the Hub has self-issued its own TLS listener by default since
	// W19-14, so the agent needs an explicit trust anchor for it -- a bad
	// bundle fails startup here rather than surfacing as a confusing TLS
	// error on the first heartbeat.
	hubRootCAs, err := agentclient.HubCACertPoolFromEnv()
	if err != nil {
		logging.Fatalf("hub CA trust: %v", err)
	}

	client := agentclient.New(hubURL, agentID, agentToken, hubRootCAs)
	client.EnrollmentSecret = os.Getenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRET")
	client.EnrollmentToken = strings.TrimSpace(os.Getenv("KRYPTKEEPER_ENROLL_TOKEN"))
	client.Version = version

	if agentID == "" || agentToken == "" {
		logging.Infof("registering agent %q (%s) with hub %s", agentName, agentType, hubURL)
		resp, err := client.Register(context.Background(), agentName, agentType)
		if err != nil {
			logging.Fatalf("registration failed: %v", err)
		}
		logging.Infof("registered: agent_id=%s", resp.AgentID)
		enrolledByToken := client.EnrollmentToken != ""
		if serviceEnvFile != "" {
			// A service restarts on every boot; without persisting, each start
			// would register a fresh agent and orphan the previous one.
			if err := persistCredentials(serviceEnvFile, resp.AgentID, resp.Token); err != nil {
				logging.Fatalf("persist agent credentials to %s: %v", serviceEnvFile, err)
			}
			logging.Infof("agent credentials saved to %s", serviceEnvFile)
			if enrolledByToken {
				// Scrub only after the credentials are safely persisted.
				if err := scrubEnrollToken(serviceEnvFile); err != nil {
					logging.Warnf("could not remove the spent enrollment token from %s: %v", serviceEnvFile, err)
				}
			}
		} else {
			// The token is never logged (log sinks are not a secret store);
			// it goes to a 0600 file the next start reads back.
			if credFile == "" {
				logging.Infof("agent registered as %s; no credentials file location (set KRYPTKEEPER_AGENT_CREDENTIALS_FILE), so the agent will re-register on its next start", resp.AgentID)
			} else if err := writeCredentialsFile(credFile, resp.AgentID, resp.Token); err != nil {
				logging.Fatalf("persist agent credentials to %s: %v", credFile, err)
			} else {
				logging.Infof("agent registered as %s; credentials saved to %s (mode 0600)", resp.AgentID, credFile)
			}
		}
	}

	client.EnrollmentToken = ""
	os.Unsetenv("KRYPTKEEPER_ENROLL_TOKEN")

	logging.Infof("agent %s starting; hub=%s poll=%s", client.AgentID, hubURL, pollInterval)

	guard := newRenewGuard()
	guard.enableHTTP01Preflight(runtime.GOOS, webRoot)
	trust := newTrustPusher(trustStorePushEnabled(os.Getenv), newTrustApplier(runtime.GOOS))
	for {
		runCycle(client, guard, disc, scanPaths, configPaths, webRoot, hubRootCAs)
		tctx, tcancel := context.WithTimeout(ctx, 5*time.Minute)
		trust.poll(tctx, client)
		tcancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

func runCycle(client *agentclient.Client, guard *renewGuard, disc hostDiscovery, scanPaths, configPaths []string, webRoot string, hubRootCAs *x509.CertPool) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := client.Heartbeat(ctx); err != nil {
		logging.Infof("heartbeat error: %v", err)
	} else {
		lastHeartbeatOK.Store(time.Now().Unix())
	}

	// Discover certs from filesystem and Windows store (platform-specific).
	certs, host, err := disc.discover(ctx, scanPaths)
	if err != nil {
		logging.Infof("discovery error: %v", err)
	}
	if host != nil && host.UnreadableTotal > 0 {
		logging.Infof("discovery: %d path(s) unreadable at privilege mode %s; reported to the hub", host.UnreadableTotal, host.PrivilegeMode)
	}

	// Also discover certs referenced in web server config files.
	var endpoints []agentclient.Endpoint
	if len(configPaths) > 0 {
		cfgCerts, err := agentdiscovery.WalkConfigCerts(configPaths)
		if err != nil {
			logging.Infof("config discovery error: %v", err)
		}
		certs = append(certs, cfgCerts...)

		// v1.3 autopilot: discover installable endpoints (cert+key+server+port).
		endpoints = agentdiscovery.WalkEndpoints(configPaths)
	}

	logging.Infof("discovered %d certificates, %d endpoints", len(certs), len(endpoints))

	if len(certs) > 0 || len(endpoints) > 0 || host != nil {
		accepted, err := client.PostInventoryHost(ctx, certs, endpoints, host)
		if err != nil {
			logging.Infof("inventory post error: %v", err)
		} else {
			logging.Infof("hub accepted %d certificates (%d endpoints)", accepted, len(endpoints))
		}
	}

	tasks, err := client.GetTasks(ctx)
	if err != nil {
		logging.Infof("get tasks error: %v", err)
		return
	}

	renewer := agentclient.NewAcmeRenewer(client.HubURL, hubRootCAs)
	for _, task := range tasks {
		logging.Infof("task %s: %s %s (expires %s)", task.TaskID, task.Action, task.Subject,
			task.NotAfter.Format("2006-01-02"))
	}
	// A task stays queued at the hub until a result is reported, so the same
	// one comes back every poll; the guard keeps it to one run at a time.
	guard.dispatchRenewals(tasks, func(task agentclient.RenewalTask) error {
		return renewTask(client, renewer, task, webRoot)
	})
}

// renewTask runs one renewal and returns its error so the guard can back off.
// Every failure is also reported to the hub: that clears the queued task and
// puts the error in the task history, where otherwise the operator sees a
// task that never completes and no reason.
func renewTask(client *agentclient.Client, renewer *agentclient.AcmeRenewer, task agentclient.RenewalTask, webRoot string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err := doRenew(ctx, client, renewer, task, webRoot)
	if err != nil {
		logging.Infof("renew %s: %v", task.Subject, err)
	}
	return err
}

// doRenew renews task and, when it carries install hints, installs the result.
// An install failure has already been reported by installRenewed with its own
// outcome, so only the other failures are reported here.
func doRenew(ctx context.Context, client *agentclient.Client, renewer *agentclient.AcmeRenewer, task agentclient.RenewalTask, webRoot string) error {
	// Refuse before ordering: issuing a certificate that cannot be installed
	// only burns an ACME order and leaves the key unused.
	if err := installUnsupported(runtime.GOOS, task); err != nil {
		return reportFailure(client, task, err)
	}
	identifiers := renewalIdentifiers(task)
	if len(identifiers) == 0 {
		// W19-13: a pre-W19-13 hub sent no Identifiers and task.Subject's CN
		// isn't a hostname either -- there is nothing an ACME order could
		// validate. Using task.Subject (a full RDN string like
		// "CN=localhost") here was the original bug (UAT W19-04).
		return reportFailure(client, task, fmt.Errorf("no usable DNS identifier"))
	}
	result, err := renewer.Renew(ctx, identifiers, webRoot)
	if err != nil {
		return reportFailure(client, task, err)
	}
	logging.Infof("renewed %s: cert %d bytes", task.Subject, len(result.CertPEM))

	// v1.3 autopilot: if the task carries install hints, install the renewed
	// cert where the web server reads it, validate, reload, and verify (with
	// rollback), then report the outcome to the Hub.
	if task.CertPath == "" {
		return nil
	}
	return installRenewed(ctx, client, task, result)
}

// installUnsupported reports why task's install hints cannot be honoured on
// goos. The install step shells out through sudo to nginx/apache/haproxy
// paths, which cannot work on Windows; a Windows cert-store/IIS target is
// not implemented (v1 limit; use agentless WinRM/IIS).
func installUnsupported(goos string, task agentclient.RenewalTask) error {
	if goos == "windows" && task.CertPath != "" {
		return errors.New("install targets are not supported on the Windows agent; use agentless WinRM/IIS")
	}
	return nil
}

// reportFailure posts a failed result for task and returns err unchanged.
func reportFailure(client *agentclient.Client, task agentclient.RenewalTask, err error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if rerr := client.PostRenewalResult(ctx, agentclient.RenewalResult{
		TaskID:      task.TaskID,
		Fingerprint: task.Fingerprint,
		Outcome:     "failed",
		Detail:      err.Error(),
	}); rerr != nil {
		logging.Infof("report failure %s: %v", task.Subject, rerr)
	}
	return err
}

func installRenewed(ctx context.Context, client *agentclient.Client, task agentclient.RenewalTask, result *agentclient.RenewResult) error {
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
		logging.Infof("install %s: %v (outcome=%s rolled_back=%v)", task.Subject, err, res.Outcome, res.RolledBack)
	} else {
		logging.Infof("installed %s: cert=%s outcome=%s verified=%v", task.Subject, task.CertPath, res.Outcome, res.Verified)
	}

	if rerr := client.PostRenewalResult(ctx, agentclient.RenewalResult{
		TaskID:            task.TaskID,
		Fingerprint:       newFP,
		Outcome:           res.Outcome,
		ServedFingerprint: res.ServedFingerprint,
		RolledBack:        res.RolledBack,
		Detail:            res.Detail,
	}); rerr != nil {
		logging.Infof("report result %s: %v", task.Subject, rerr)
	}
	return err
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
		logging.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

// generateSudoers returns the sudoers drop-in for Renewal Autopilot (v1.3),
// rendered by the same privexec.Sudoers the hub's privilege bundle uses. The
// default nopasswd mode grants only the commands needed to install renewed
// certs and reload the web server; helper mode grants one hash-pinned helper.
//
// NOTE: the default systemd unit sets NoNewPrivileges=true, which blocks sudo.
// Autopilot requires setting NoNewPrivileges=false in the unit; until then the
// agent stays discovery+renew-only and never installs. This is an opt-in.
func generateSudoers(mode privexec.Mode) (string, error) {
	body, err := privexec.Sudoers("kryptkeeper-agent", mode, "", []string{"/etc/nginx/ssl", "/etc/apache2/ssl"})
	if err != nil {
		return "", err
	}
	header := `# Kryptkeeper Agent - Renewal Autopilot privilege allowlist (v1.3)
#
# Install:   kryptkeeper-agent --generate-sudoers | sudo tee /etc/sudoers.d/kryptkeeper-agent
# Secure:    sudo chmod 0440 /etc/sudoers.d/kryptkeeper-agent
# Validate:  sudo visudo -cf /etc/sudoers.d/kryptkeeper-agent
# Helper:    kryptkeeper-agent --generate-sudoers --sudoers-mode=helper
#
# Tighten the cert-directory globs below to the exact paths on THIS host. In an
# argument, '*' matches '/' too (fnmatch without FNM_PATHNAME), so a glob is not
# a directory boundary; list each cert dir and prefer helper mode.
#
# Also required for autopilot: set NoNewPrivileges=false in the systemd unit
# (the default true value blocks sudo). Leave it true to keep the agent
# discovery+renew-only (no install).

`
	return header + body, nil
}

// sudoersModeFlag reads --sudoers-mode=<mode>; the default keeps the
// pre-W34 behaviour (raw allowlist).
func sudoersModeFlag(args []string) privexec.Mode {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--sudoers-mode="); ok {
			return privexec.Mode(v)
		}
	}
	return privexec.ModeNoPasswd
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
#Environment=KRYPTKEEPER_POLL_INTERVAL=60
#Environment=KRYPTKEEPER_SCAN_PATHS=/etc/ssl,/etc/pki/tls
#Environment=KRYPTKEEPER_WEB_ROOT=/var/www/html

# Hardening
# NOTE: NoNewPrivileges=true blocks sudo. To enable Renewal Autopilot (cert
# install + web-server reload), set this to false AND install the sudoers
# drop-in (kryptkeeper-agent --generate-sudoers). Leave true for
# discovery+renew-only operation.
# Trust store push (KRYPTKEEPER_TRUST_STORE_PUSH=true) also needs
# NoNewPrivileges=false, the --generate-trust-store-sudoers drop-in, and
# ReadWritePaths for the anchor directory it writes (docs/ops/TRUST_STORE_PUSH.md).
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
