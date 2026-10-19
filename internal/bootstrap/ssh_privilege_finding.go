// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"kryptkeeper/internal/discovery/scanner"
)

// W34-10: a scan that could not read paths for lack of privilege says so once,
// with the account it ran as, the mode, the paths and the fix for that mode,
// instead of one UNREADABLE_PATH per file. Errors that are not about access
// (a keystore that does not parse) stay UNREADABLE_PATH.

const (
	maxInsufficientPrivilegePaths = 10
	unreadablePathPrefix          = "UNREADABLE_PATH: "
)

// find quotes with curly quotes under a UTF-8 locale (‘/x’), so they end a
// path like the ASCII ones do.
var reAbsPath = regexp.MustCompile(`/[^\s:'"‘’“”]+`)

func isPermissionFinding(f string) bool {
	return strings.HasPrefix(f, unreadablePathPrefix) && strings.Contains(strings.ToLower(f), "permission denied")
}

// unreadablePathOf pulls the first absolute path out of an unreadable-path
// finding. The finding is "UNREADABLE_PATH: <host>:<path>: <error>", or find's
// own "<host>:find: '<path>': Permission denied".
func unreadablePathOf(f string) string {
	body := strings.TrimPrefix(f, unreadablePathPrefix)
	if m := reAbsPath.FindString(body); m != "" {
		return m
	}
	return ""
}

// privilegeRemediation is the fix text for the mode the scan ran with.
func privilegeRemediation(mode, user string, paths []string) string {
	if user == "" {
		user = "<scan-user>"
	}
	dir := "/path/to/dir"
	if len(paths) > 0 {
		dir = path.Dir(paths[0])
	}
	rule := fmt.Sprintf("%s ALL=(root) NOPASSWD: /usr/bin/find %s *, /usr/bin/stat -c * %s/*, /usr/bin/cat %s/*", user, dir, dir, dir)
	switch mode {
	case "helper":
		return "The helper refused these paths: it reads only pem, crt, cer, der, jks, p12, pfx, keystore and truststore files, never private keys or denylisted paths. " +
			"Check the extension, or switch to nopasswd mode with this sudoers rule: " + rule
	case "nopasswd":
		return "sudo -n works but its rule does not cover these paths. Extend the sudoers drop-in: " + rule
	case "password":
		return "sudo accepted the password but is not allowed to read these paths. Extend the sudoers rule: " + rule +
			" (remove NOPASSWD: for password mode), or switch to helper mode."
	default:
		return fmt.Sprintf("This credential has no sudo mode, so %s reads only what its own permissions allow. "+
			"Preferred: install the privilege helper and switch the credential to helper mode (see the target's privilege bundle). "+
			"Or add this sudoers rule and use nopasswd mode: %s. "+
			"Or run the scan once with a sudo password. As a last resort, grant read on a certificate directory: chgrp <group of %s> %s && chmod g+rX %s (never on private keys).",
			user, rule, user, dir, dir)
	}
}

// applyInsufficientPrivilege replaces the permission-denied UNREADABLE_PATH
// findings (and the NEEDS_PASSWORD hint they used to bring) on the scan's
// endpoint with one INSUFFICIENT_PRIVILEGE finding, and records the privilege
// mode and unreadable count on the host observations.
func applyInsufficientPrivilege(r *scanner.ScanResult, uid, user, mode string) {
	if len(r.Endpoints) == 0 {
		return
	}
	ep := &r.Endpoints[0]
	if mode == "" {
		mode = "none"
	}
	var kept, denied []string
	for _, f := range ep.Findings {
		switch {
		case isPermissionFinding(f):
			denied = append(denied, f)
		case strings.HasPrefix(f, "NEEDS_PASSWORD:"):
			// folded into the remediation text below
		default:
			kept = append(kept, f)
		}
	}
	seen := map[string]bool{}
	var paths []string
	for _, f := range denied {
		p := unreadablePathOf(f)
		if p == "" {
			p = "(unknown path)"
		}
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	total := len(paths)
	if ep.HostObs != nil {
		ep.HostObs.PrivilegeMode = mode
		ep.HostObs.UnreadableCount = total
	}
	if total == 0 {
		ep.Findings = kept
		return
	}
	finding := formatInsufficientPrivilege(uid, user, mode, paths, total)
	ep.Findings = append([]string{finding}, kept...)
}

// formatInsufficientPrivilege renders the one INSUFFICIENT_PRIVILEGE finding:
// the account, the mode, at most maxInsufficientPrivilegePaths paths with the
// true total, and the fix for that mode.
func formatInsufficientPrivilege(uid, user, mode string, paths []string, total int) string {
	if mode == "" {
		mode = "none"
	}
	if uid == "" {
		uid = "unknown"
	}
	shown, more := paths, ""
	if len(shown) > maxInsufficientPrivilegePaths {
		more = fmt.Sprintf(" (+%d more)", total-maxInsufficientPrivilegePaths)
		shown = shown[:maxInsufficientPrivilegePaths]
	}
	return fmt.Sprintf("%s: uid=%s; user=%s; mode=%s; unreadable=%d; paths=%s%s; fix=%s",
		scanner.FindingInsufficientPrivilege, uid, user, mode, total, strings.Join(shown, ", "), more,
		privilegeRemediation(mode, user, paths))
}
