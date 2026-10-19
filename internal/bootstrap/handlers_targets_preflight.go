// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/privexec"
)

// W34-15 (D-210): POST /api/v1/targets/{id}/preflight dials the target with its
// pinned host key, authenticates, and reports per capability whether the SSH
// account can do what scans (and, with auto_renew, renewals) need. GET returns
// the last stored report. W33-30 had not landed when this was written, so the
// route is created here and W33-30 is absorbed.

const (
	preflightDialTimeout = 8 * time.Second
	preflightTotalBudget = 45 * time.Second
	preflightAction      = "target.privilege.preflight"
)

// preflightDial is the dial seam; tests substitute it.
var preflightDial sshDialFunc = liveSSHDial

type preflightRow struct {
	Capability string `json:"capability"`
	Status     string `json:"status"` // ok | fail | skipped
	Detail     string `json:"detail,omitempty"`
	Fix        string `json:"fix,omitempty"`
}

type preflightReport struct {
	CheckedAt     string         `json:"checked_at"`
	Mode          string         `json:"mode"`
	Roles         []string       `json:"roles"`
	Rows          []preflightRow `json:"rows"`
	OK            bool           `json:"ok"`
	PrivilegedAll bool           `json:"privileged_all"`
}

func okRow(c string) preflightRow { return preflightRow{Capability: c, Status: "ok"} }
func failRow(c, detail, fix string) preflightRow {
	return preflightRow{Capability: c, Status: "fail", Detail: detail, Fix: fix}
}
func skipRow(c, detail string) preflightRow {
	return preflightRow{Capability: c, Status: "skipped", Detail: detail}
}

var helperVerbsByRole = map[privexec.Role][]string{
	privexec.RoleScan:    {"list", "stat", "read-cert", "listeners"},
	privexec.RoleInstall: {"install", "config-test", "reload"},
}

var rawCommandsByRole = map[privexec.Role][]string{
	privexec.RoleScan:    {"find", "stat", "cat", "ss"},
	privexec.RoleInstall: {"install", "systemctl"},
}

// buildPreflightRows turns privexec reports (one per role) into rows. Rows
// carry the fix inline so the UI can render them without extra knowledge.
func buildPreflightRows(mode privexec.Mode, user string, reports map[privexec.Role]privexec.Report, roles []privexec.Role) []preflightRow {
	base := reports[roles[0]]
	rows := []preflightRow{okRow("ssh_auth")}
	if mode == privexec.ModeNone {
		return append(rows, skipRow("sudo_present", "sudo mode is none: only world-readable files can be read"),
			failRow("privilege", "no privilege mode configured", "Create the credential with mode helper, nopasswd or password to read root-owned certificates; see the privilege bundle."))
	}
	if base.SudoPresent {
		rows = append(rows, okRow("sudo_present"))
	} else {
		rows = append(rows, failRow("sudo_present", "sudo was not found on the host", "Install sudo (for example: apt install sudo, or dnf install sudo)."))
		return rows
	}
	if base.RequireTTY {
		rows = append(rows, failRow("requiretty", "sudo wants a tty and the scan has none", base.RequireTTYFix))
	} else {
		rows = append(rows, okRow("requiretty"))
	}
	switch mode {
	case privexec.ModeNoPasswd:
		if base.NoPasswdOK {
			rows = append(rows, okRow("nopasswd"))
		} else {
			rows = append(rows, failRow("nopasswd", "sudo -n true failed", fmt.Sprintf("Add a NOPASSWD sudoers rule for %s (download it from the privilege bundle).", user)))
		}
	case privexec.ModePassword:
		if base.PasswordOK {
			rows = append(rows, okRow("password"))
		} else {
			rows = append(rows, failRow("password", "sudo rejected the stored password", fmt.Sprintf("Update the credential with the current sudo password and make sure %s may use sudo.", user)))
		}
	case privexec.ModeHelper:
		if base.HelperPresent {
			rows = append(rows, okRow("helper_present"))
		} else {
			rows = append(rows, failRow("helper_present", "helper not found or not executable", "Install the helper as root at "+privexec.DefaultHelperPath+" (privilege bundle, Download helper)."))
		}
		switch {
		case !base.HelperPresent:
			rows = append(rows, skipRow("helper_sha", "helper is not installed"))
		case base.HelperSHAOK:
			rows = append(rows, okRow("helper_sha"))
		default:
			rows = append(rows, failRow("helper_sha", "installed helper differs from the pinned sha256 (HELPER_TAMPERED)", "Reinstall the helper from the privilege bundle, or update the credential's pinned sha256 if you changed the helper on purpose."))
		}
		if base.HelperPresent && !base.NoPasswdOK {
			rows = append(rows, failRow("helper_sudo", "sudo -n on the helper failed", fmt.Sprintf("Add the sudoers line for %s from the privilege bundle.", user)))
		}
	}
	for _, role := range roles {
		rep := reports[role]
		var names []string
		if mode == privexec.ModeHelper {
			names = helperVerbsByRole[role]
		} else {
			names = rawCommandsByRole[role]
		}
		for _, n := range names {
			capName := "command:" + n
			if mode == privexec.ModeHelper {
				capName = "verb:" + n
			}
			switch {
			case gapFor(rep, n):
				rows = append(rows, failRow(capName, string(role)+" needs it and sudo -l does not list it", "Add "+n+" to the sudoers allowlist, or switch to helper mode."))
			case rep.PrivilegedAll:
				rows = append(rows, okRow(capName))
			default:
				rows = append(rows, skipRow(capName, "blocked by an earlier failure"))
			}
		}
	}
	return rows
}

func gapFor(rep privexec.Report, command string) bool {
	for _, m := range rep.Missing {
		if strings.HasPrefix(m, "sudo -l does not list "+command+" ") {
			return true
		}
	}
	return false
}

func handleTargetPreflight(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, id string, store ManagedTargetStore, creds OutboundCredentialStore, roleStore *CustomRoleStore, audit AuditProvider) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET, POST")
		return
	}
	if !mayManageTargetPrivilege(pd, roleStore) {
		emitAuditEvent(r, audit, pd.ID, preflightAction, "target", id, AuditOutcomeDenied)
		writeForbidden(w, "discovery or certificate.renew permission required")
		return
	}
	target, err := store.Get(r.Context(), id)
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, preflightAction, "target", id, AuditOutcomeFailure)
		writeNotFound(w, "target not found")
		return
	}
	if !targetVisibleToTenant(pd, target) {
		emitAuditEvent(r, audit, pd.ID, preflightAction, "target", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	ps, ok := store.(targetPreflightStore)
	if !ok {
		writeServiceUnavailable(w, "preflight storage unavailable")
		return
	}
	if r.Method == http.MethodGet {
		raw, err := ps.GetLastPreflight(r.Context(), id)
		if err != nil || raw == "" {
			writeNotFound(w, "no preflight has run for this target")
			return
		}
		writeJSONData(w, json.RawMessage(raw))
		return
	}

	report, status, msg := runTargetPreflight(r.Context(), target, creds, pd, audit)
	if status != 0 {
		emitAuditEvent(r, audit, pd.ID, preflightAction, "target", id, AuditOutcomeFailure)
		if status == http.StatusBadRequest {
			writeBadRequest(w, msg)
		} else {
			writeServiceUnavailable(w, msg)
		}
		return
	}
	raw, _ := json.Marshal(report)
	if err := ps.SetLastPreflight(r.Context(), id, string(raw)); err != nil {
		logging.Warnf("preflight: store report for %s: %v", id, err)
	}
	outcome := AuditOutcomeSuccess
	if report.Rows[0].Status != "ok" {
		outcome = AuditOutcomeFailure
	}
	emitAuditEventDetail(r, audit, pd.ID, preflightAction, "target", id, outcome,
		fmt.Sprintf("mode=%s ok=%t privileged_all=%t", report.Mode, report.OK, report.PrivilegedAll))
	writeJSONData(w, report)
}

// runTargetPreflight returns the report, or a nonzero HTTP status and message
// when the request itself is unusable. A failed dial is a report row, not an
// error: the operator needs to see it next to the fix.
func runTargetPreflight(ctx context.Context, t ManagedTarget, creds OutboundCredentialStore, pd AuthPrincipal, audit AuditProvider) (preflightReport, int, string) {
	if t.InstallMode != "ssh" {
		return preflightReport{}, http.StatusBadRequest, "privilege preflight applies to ssh install-mode targets"
	}
	if t.CredentialRef == "" {
		return preflightReport{}, http.StatusBadRequest, "target has no credential_ref"
	}
	if creds == nil {
		return preflightReport{}, http.StatusServiceUnavailable, "outbound credential store not configured"
	}
	meta, err := creds.Get(ctx, t.CredentialRef)
	if err != nil || meta.CredentialType != CredentialTypeSSHKey || !stampedTenantVisible(pd, meta.Tenant) {
		return preflightReport{}, http.StatusBadRequest, "credential is missing, not an ssh_key, or not visible to this tenant"
	}
	plaintext, err := creds.Resolve(ctx, t.CredentialRef)
	if err != nil {
		return preflightReport{}, http.StatusServiceUnavailable, "credential could not be resolved"
	}
	defer zeroize(plaintext)
	var payload sshCredentialPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return preflightReport{}, http.StatusBadRequest, "credential is not the documented ssh_key JSON shape"
	}
	if err := payload.validatePrivilege(); err != nil {
		return preflightReport{}, http.StatusBadRequest, err.Error()
	}
	signer, credKey, err := payload.parse()
	if err != nil {
		return preflightReport{}, http.StatusBadRequest, "credential: " + err.Error()
	}
	mode, _ := privexec.ParseMode(payload.SudoMode)
	port := payload.Port
	if port == 0 {
		port = 22
	}
	report := preflightReport{CheckedAt: time.Now().UTC().Format(time.RFC3339), Mode: string(mode)}

	pinned := pinnedHostKeyFor(t, credKey)
	dialCtx, cancel := context.WithTimeout(ctx, preflightDialTimeout)
	defer cancel()
	exec, closeConn, err := preflightDial(dialCtx, agentinstall.SSHTarget{
		Host: t.Host, Port: port, User: payload.User, Signer: signer,
		HostKeyCallback:   agentinstall.PinnedHostKeyCallback(pinned),
		HostKeyAlgorithms: hostKeyAlgorithmsFor(pinned),
		DialTimeout:       preflightDialTimeout,
	})
	if err != nil {
		var mm *agentinstall.HostKeyMismatchError
		fix := "Check that the host is reachable on port " + fmt.Sprint(port) + " and the SSH user and key are authorized."
		if errors.As(err, &mm) {
			recordHostKeyMismatch(ctx, audit, t.ID, mm)
			fix = "The host key changed. Confirm the new key out of band, then re-pin it on the target."
		}
		report.Rows = []preflightRow{failRow("ssh_auth", boundInstallDetail(err.Error(), payload.SudoPassword), fix)}
		return report, 0, ""
	}
	defer func() { _ = closeConn() }()

	roles := []privexec.Role{privexec.RoleScan}
	if t.AutoRenew {
		roles = append(roles, privexec.RoleInstall)
	}
	pw := []byte(payload.SudoPassword)
	defer zeroize(pw)
	cfg := privexec.Config{Mode: mode, Password: pw, HelperSHA: payload.HelperSHA256}
	pctx, pcancel := context.WithTimeout(ctx, preflightTotalBudget)
	defer pcancel()
	reports := map[privexec.Role]privexec.Report{}
	for _, role := range roles {
		reports[role] = privexec.Preflight(pctx, exec, cfg, role)
	}
	for _, role := range roles {
		report.Roles = append(report.Roles, string(role))
	}
	report.Rows = buildPreflightRows(mode, payload.User, reports, roles)
	report.OK = true
	for _, row := range report.Rows {
		if row.Status == "fail" {
			report.OK = false
		}
	}
	report.PrivilegedAll = mode != privexec.ModeNone
	for _, role := range roles {
		report.PrivilegedAll = report.PrivilegedAll && reports[role].PrivilegedAll
	}
	reason := ""
	if payload.User == "root" {
		reason = "the ssh user is root (uid 0)"
	}
	for _, role := range roles {
		if reports[role].HighImpact && reason == "" {
			reason = reports[role].HighImpactReason
		}
	}
	if reason != "" {
		autoMarkPrivileged(ctx, creds, audit, meta, reason)
	}
	return report, 0, ""
}

// autoMarkPrivileged sets the credential's privileged flag from what the
// preflight observed and audits the transition once (source auto). A
// credential already flagged is left alone, so re-running the preflight
// neither rewrites the reason nor repeats the audit row.
func autoMarkPrivileged(ctx context.Context, creds OutboundCredentialStore, audit AuditProvider, meta OutboundCredentialMeta, reason string) {
	ps, ok := creds.(credentialPrivilegeStore)
	if !ok || meta.Privileged {
		return
	}
	if err := ps.SetPrivileged(ctx, meta.ID, true, reason, "auto:preflight"); err != nil {
		logging.Warnf("preflight: mark credential %s privileged: %v", meta.ID, err)
		return
	}
	if audit == nil {
		return
	}
	if err := audit.AppendEntry(context.WithoutCancel(ctx), AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "credential.privileged.set", ActorType: "system", ActorID: "preflight",
		ResourceType: "credential", ResourceID: meta.ID, Outcome: AuditOutcomeSuccess,
		ChangeSummary: fmt.Sprintf(`{"privileged":true,"reason":%q,"source":"auto"}`, reason),
	}); err != nil {
		logging.Warnf("audit append failed action=credential.privileged.set: %v", err)
	}
}

// handleTargetUnblock clears a rollback block after an operator has checked
// the host (W34-10). It needs the same permission as the privilege preflight.
// A privilege block is not cleared here: it follows the credential and the
// latest scan, so fixing either clears it on the next scheduler tick.
func handleTargetUnblock(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, id string, store ManagedTargetStore, roleStore *CustomRoleStore, audit AuditProvider) {
	const action = "target.renewal.unblock"
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !mayManageTargetPrivilege(pd, roleStore) {
		emitAuditEvent(r, audit, pd.ID, action, "target", id, AuditOutcomeDenied)
		writeForbidden(w, "discovery or certificate.renew permission required")
		return
	}
	target, err := store.Get(r.Context(), id)
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, action, "target", id, AuditOutcomeFailure)
		writeNotFound(w, "target not found")
		return
	}
	if !targetVisibleToTenant(pd, target) {
		emitAuditEvent(r, audit, pd.ID, action, "target", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	ss, ok := store.(targetStateStore)
	if !ok {
		writeServiceUnavailable(w, "target state storage unavailable")
		return
	}
	if err := ss.ClearTargetBlocked(r.Context(), id); err != nil {
		emitAuditEvent(r, audit, pd.ID, action, "target", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "could not unblock the target")
		return
	}
	emitAuditEvent(r, audit, pd.ID, action, "target", id, AuditOutcomeSuccess)
	w.WriteHeader(http.StatusNoContent)
}
