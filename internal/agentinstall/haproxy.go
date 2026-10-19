// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"fmt"
	"os"
)

// W5-02 (PE-4/D-044/FR-P5): the HAProxy install target. HAProxy's `crt`
// directive reads a SINGLE file — full certificate chain followed by the
// private key — so this flow writes one combined 0600 file, always runs
// `haproxy -c` before reloading, and never falls through to a blind
// systemctl reload.

// defaultHAProxyConfigPath is used when the request does not override it.
const defaultHAProxyConfigPath = "/etc/haproxy/haproxy.cfg"

// combineHAProxyPEM joins the cert chain and key into HAProxy's expected
// single-file layout, newline-safe: chain first, key last.
func combineHAProxyPEM(certPEM, keyPEM []byte) []byte {
	var buf bytes.Buffer
	buf.Write(bytes.TrimRight(certPEM, "\n"))
	buf.WriteByte('\n')
	buf.Write(bytes.TrimRight(keyPEM, "\n"))
	buf.WriteByte('\n')
	return buf.Bytes()
}

// installHAProxy is the HAProxy-specific install flow: combined-file
// write, mandatory config test, systemd reload, optional verify, and
// rollback with a best-effort reload of the restored file.
func (in *Installer) installHAProxy(ctx context.Context, req InstallRequest) (InstallResult, error) {
	if req.CertPath == "" || len(req.CertPEM) == 0 {
		return InstallResult{}, fmt.Errorf("haproxy install: cert path and PEM are required")
	}
	// HAProxy cannot serve without the key in the same file — refuse up
	// front rather than write a keyless combined file.
	if len(req.KeyPEM) == 0 {
		return InstallResult{}, fmt.Errorf("haproxy install: key PEM is required (crt is a single combined file)")
	}
	// HAProxy's binary reload needs master-socket / -sf PID plumbing this
	// installer does not implement — refuse rather than pretend.
	if req.ReloadMethod == "binary" {
		return InstallResult{}, fmt.Errorf("haproxy install: reload method %q not supported — HAProxy binary reload requires master-socket plumbing; use systemctl (default)", req.ReloadMethod)
	}

	configPath := req.HAProxyConfigPath
	if configPath == "" {
		configPath = defaultHAProxyConfigPath
	}

	// 1. Snapshot the current combined file for rollback. 0600: it holds
	// the private key.
	backups := []fileBackup{in.snapshot(ctx, req.CertPath, 0o600)}
	if err := snapshotError(backups); err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, err
	}

	// 2. Write the combined chain+key file.
	if err := in.place(req.CertPath, combineHAProxyPEM(req.CertPEM, req.KeyPEM), 0o600, backups[0]); err != nil {
		return InstallResult{}, fmt.Errorf("haproxy install: write combined file: %w", err)
	}

	// 3. Config test — ALWAYS. This is the fall-through the old path had:
	// no haproxy case meant no test and a blind reload.
	if out, err := in.exec.Run(ctx, "haproxy", "-c", "-f", configPath); err != nil {
		in.rollback(ctx, backups, req)
		return InstallResult{RolledBack: true, Outcome: OutcomeConfigTestFailed, Detail: string(out)},
			fmt.Errorf("haproxy install: config test failed, rolled back: %w", err)
	}

	// 4. Reload via systemd (the master process handles the handover).
	reloadName, reloadArgs := "systemctl", []string{"reload", "haproxy"}
	if out, err := in.exec.Run(ctx, reloadName, reloadArgs...); err != nil {
		in.rollback(ctx, backups, req)
		_, _ = in.exec.Run(ctx, reloadName, reloadArgs...) // best-effort rollback reload; primary error already returned
		return InstallResult{Installed: true, RolledBack: true, Outcome: OutcomeReloadFailed, Detail: string(out)},
			fmt.Errorf("haproxy install: reload failed, rolled back: %w", err)
	}

	// 5. Verify-after-install, same contract as the generic flow -- including
	// the retry-until-match tolerance for a reload signal that returns
	// before new workers actually take over (see verifyUntilMatchOrExhausted's
	// doc comment in installer.go; found live against real haproxy is
	// unconfirmed, but the reload command has the same signal-vs-applied gap
	// as nginx/apache's, which W19-02 did confirm live).
	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, err := in.verifyUntilMatchOrExhausted(ctx, req.VerifyHostPort, req.ExpectedFingerprint)
		if err != nil {
			in.rollback(ctx, backups, req)
			_, _ = in.exec.Run(ctx, reloadName, reloadArgs...) // best-effort rollback reload; primary error already returned
			return InstallResult{Installed: true, Reloaded: true, RolledBack: true, Outcome: OutcomeVerifyFailed, Detail: err.Error()},
				fmt.Errorf("haproxy install: verify failed, rolled back: %w", err)
		}
		if normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			in.rollback(ctx, backups, req)
			_, _ = in.exec.Run(ctx, reloadName, reloadArgs...) // best-effort rollback reload; primary error already returned
			return InstallResult{
					Installed: true, Reloaded: true, RolledBack: true,
					ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
					Detail: "served fingerprint does not match renewed cert",
				},
				fmt.Errorf("haproxy install: verify mismatch (served %s, want %s), rolled back",
					served, req.ExpectedFingerprint)
		}
		return InstallResult{
			Installed: true, Reloaded: true, Verified: true,
			ServedFingerprint: served, Outcome: OutcomeInstalledVerified,
		}, nil
	}

	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}

// haproxyStageFiles validates a staged HAProxy request exactly as
// installHAProxy does, registers the single combined 0600 file through add
// and returns the config path the config test must use (W27-14).
func haproxyStageFiles(req InstallRequest, add func(live string, content []byte, mode os.FileMode)) (string, error) {
	if req.CertPath == "" || len(req.CertPEM) == 0 {
		return "", fmt.Errorf("haproxy stage: cert path and PEM are required")
	}
	if len(req.KeyPEM) == 0 {
		return "", fmt.Errorf("haproxy stage: key PEM is required (crt is a single combined file)")
	}
	if req.ReloadMethod == "binary" {
		return "", fmt.Errorf("haproxy stage: reload method %q not supported — HAProxy binary reload requires master-socket plumbing; use systemctl (default)", req.ReloadMethod)
	}
	add(req.CertPath, combineHAProxyPEM(req.CertPEM, req.KeyPEM), 0o600)
	if req.HAProxyConfigPath != "" {
		return req.HAProxyConfigPath, nil
	}
	return defaultHAProxyConfigPath, nil
}
