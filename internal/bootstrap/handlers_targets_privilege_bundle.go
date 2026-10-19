// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"net/http"
	"strings"

	"kryptkeeper/internal/privexec"
)

// W34-16 (D-210): GET /api/v1/targets/{id}/privilege-bundle?mode=&user=
// returns what the customer installs on the host for a privilege mode: the
// sudoers drop-in, the helper with its sha256, and the steps in plain words.

type privilegeBundle struct {
	Mode         string   `json:"mode"`
	User         string   `json:"user"`
	Sudoers      string   `json:"sudoers"`
	Helper       string   `json:"helper,omitempty"`
	HelperSHA256 string   `json:"helper_sha256,omitempty"`
	HelperPath   string   `json:"helper_path,omitempty"`
	Checklist    []string `json:"checklist"`
	Warnings     []string `json:"warnings"`
}

const defaultScanUser = "kkscan"

// mayManageTargetPrivilege is the permission for both privilege routes: the
// people who set up discovery or renewal on targets.
func mayManageTargetPrivilege(pd AuthPrincipal, roles *CustomRoleStore) bool {
	perms, admin := principalPermissions(pd, roles)
	return admin || perms["discovery.manage"] || perms["certificate.renew"]
}

// handleTargetPrivilegeBundle serves the bundle for one stored target
// (id != "") or, for the setup wizard before the target exists, from the
// install profile in the query (id == "": server_type, cert_path, key_path).
// maxBundleScanPaths bounds scan_paths so a sudoers drop-in stays reviewable.
const maxBundleScanPaths = 16

func handleTargetPrivilegeBundle(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, id string, store ManagedTargetStore, roles *CustomRoleStore, audit AuditProvider) {
	const action = "target.privilege_bundle.read"
	resource := id
	if resource == "" {
		resource = "-"
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !mayManageTargetPrivilege(pd, roles) {
		emitAuditEvent(r, audit, pd.ID, action, "target", resource, AuditOutcomeDenied)
		writeForbidden(w, "discovery or certificate.renew permission required")
		return
	}
	q := r.URL.Query()
	serverType, certPath, keyPath := q.Get("server_type"), q.Get("cert_path"), q.Get("key_path")
	if id != "" {
		target, err := store.Get(r.Context(), id)
		if err != nil {
			emitAuditEvent(r, audit, pd.ID, action, "target", resource, AuditOutcomeFailure)
			writeNotFound(w, "target not found")
			return
		}
		if !targetVisibleToTenant(pd, target) {
			emitAuditEvent(r, audit, pd.ID, action, "target", resource, AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		serverType, certPath, keyPath = target.InstallServerType, target.InstallCertPath, target.InstallKeyPath
	}
	modeStr := q.Get("mode")
	if modeStr == "" {
		modeStr = string(privexec.ModeHelper)
	}
	mode, err := privexec.ParseMode(modeStr)
	if err != nil || mode == privexec.ModeNone {
		emitAuditEvent(r, audit, pd.ID, action, "target", resource, AuditOutcomeFailure)
		writeBadRequest(w, "mode must be helper, nopasswd or password")
		return
	}
	user := q.Get("user")
	if user == "" {
		user = defaultScanUser
	}
	paths := make([]string, 0, 2)
	for _, p := range []string{certPath, keyPath} {
		if p != "" {
			paths = append(paths, p)
		}
	}
	// The install paths say where renewals write; scanning also reads wherever
	// keystores live (/opt/ssl, /etc/pki/...), which the raw allowlist cannot
	// guess. scan_paths names those directories or files so the drop-in covers
	// them; without it a nopasswd scan reports INSUFFICIENT_PRIVILEGE for every
	// keystore outside the install directory (found in W34-20).
	if sp := q.Get("scan_paths"); sp != "" {
		extra := strings.Split(sp, ",")
		if len(extra) > maxBundleScanPaths {
			emitAuditEvent(r, audit, pd.ID, action, "target", resource, AuditOutcomeFailure)
			writeBadRequest(w, fmt.Sprintf("scan_paths accepts at most %d paths", maxBundleScanPaths))
			return
		}
		for _, p := range extra {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
	}
	sudoers, err := privexec.Sudoers(user, mode, serverType, paths)
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, action, "target", resource, AuditOutcomeFailure)
		writeBadRequest(w, err.Error())
		return
	}
	b := privilegeBundle{Mode: string(mode), User: user, Sudoers: sudoers}
	steps, warnings := bundleGuidance(mode, user)
	b.Checklist, b.Warnings = append(steps, bundleTail(mode, user)...), warnings
	if mode == privexec.ModeHelper {
		b.Helper = privexec.HelperScript
		b.HelperSHA256 = privexec.HelperSHA256()
		b.HelperPath = privexec.DefaultHelperPath
	}
	emitAuditEvent(r, audit, pd.ID, action, "target", resource, AuditOutcomeSuccess)
	writeJSONData(w, b)
}

// bundleGuidance returns the leading checklist steps and the warnings; the
// trailing steps depend on the mode and come from bundleTail.
func bundleGuidance(mode privexec.Mode, user string) (steps, warnings []string) {
	steps = []string{
		fmt.Sprintf("On the host, create the account: sudo useradd -m %s", user),
		fmt.Sprintf("Add the Kryptkeeper SSH public key to /home/%s/.ssh/authorized_keys (key login only; password SSH login stays unsupported).", user),
	}
	switch mode {
	case privexec.ModeHelper:
		steps = append(steps, fmt.Sprintf("Download the helper and install it as root: sudo install -m 0755 -o root -g root kryptkeeper-helper %s", privexec.DefaultHelperPath),
			fmt.Sprintf("Check the hash: sha256sum %s must print %s.", privexec.DefaultHelperPath, privexec.HelperSHA256()))
	case privexec.ModeNoPasswd:
		steps = append(steps, "Review the cert directories in the sudoers file and tighten them to the exact paths on this host.")
		warnings = []string{
			"Command arguments in sudoers are matched with fnmatch without path separation: '*' also matches '/' and '..'. cat and install on a globbed path are therefore root read/write of the whole filesystem for anyone holding this account's key.",
			"Choose helper mode instead unless policy forbids installing the helper.",
		}
	case privexec.ModePassword:
		steps = append(steps, fmt.Sprintf("Make sure %s may use sudo (for example the sudo or wheel group).", user))
		warnings = []string{
			"The account is root while its sudo password is valid. Rotating the password breaks scans and renewals until the stored credential is updated.",
		}
	}
	return steps, warnings
}

func bundleTail(mode privexec.Mode, user string) []string {
	tail := []string{
		fmt.Sprintf("Save the sudoers text as /etc/sudoers.d/kryptkeeper-%s, then run: sudo chmod 0440 /etc/sudoers.d/kryptkeeper-%s && sudo visudo -cf /etc/sudoers.d/kryptkeeper-%s", user, user, user),
	}
	switch mode {
	case privexec.ModeHelper:
		tail = append(tail, "In Kryptkeeper, create the SSH credential with mode helper, paste the sha256 above, then press Test credential.")
	case privexec.ModePassword:
		tail = append(tail, "In Kryptkeeper, create the SSH credential with mode sudo password and enter the password, then press Test credential.")
	default:
		tail = append(tail, "In Kryptkeeper, create the SSH credential with mode raw sudo allowlist, then press Test credential.")
	}
	return tail
}
