// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// W18-11: say at credential-entry time what a Windows credential can do,
// instead of at install time after a renewal has already been issued.
// Nothing here mutates the host: the only command run is `whoami /groups`.

// Preflight levels, ordered by how far the credential gets.
const (
	PreflightUnreachable     = "unreachable"     // TLS/transport: no answer to classify
	PreflightUnauthenticated = "unauthenticated" // 401: wrong password OR account not admitted by the RootSDDL
	PreflightNoShell         = "no_shell"        // admitted, but may not create a shell
	PreflightDiscover        = "discover"        // shell works; token is not elevated
	PreflightInstall         = "install"         // shell works with an elevated token
)

// WinRMPreflight is the operator-facing verdict.
type WinRMPreflight struct {
	Level       string `json:"level"`
	CanDiscover bool   `json:"can_discover"`
	CanInstall  bool   `json:"can_install"`
	Detail      string `json:"detail"`
}

// Integrity-label SIDs are stable across every Windows locale; the
// "Group used for deny only" attribute text that would otherwise reveal a
// UAC-filtered administrator is not. A network logon of a local
// administrator carries a Medium token unless LocalAccountTokenFilterPolicy
// is set, and that filtered token is exactly what the install would run
// with -- so the label, not group membership, is the honest signal.
const (
	sidHighIntegrity   = "S-1-16-12288"
	sidSystemIntegrity = "S-1-16-16384"
)

// PreflightWinRM classifies what cfg's credential can do on the host. A
// nil client means production trust (cfg.RootCAs), as in NewWSManShell.
func PreflightWinRM(ctx context.Context, cfg WinRMConfig, client *http.Client) WinRMPreflight {
	out, err := NewWSManShell(cfg, client).Run(ctx, "whoami", "/groups", "/fo", "csv")
	if err != nil {
		var we *WinRMError
		switch {
		case errors.As(err, &we) && we.Status == http.StatusUnauthorized:
			return WinRMPreflight{Level: PreflightUnauthenticated, Detail: "the listener refused the credential: either the password is wrong, " +
				"or it is right and the account is not permitted to use WinRM (add it to Remote Management Users and make sure " +
				"the service RootSDDL grants that group -- Windows client editions omit it). The wire cannot tell these apart; " +
				"the host's Security log (event 4624 vs 4625) can"}
		case errors.As(err, &we) && we.ShellDenied():
			return WinRMPreflight{Level: PreflightNoShell, Detail: "the credential authenticated and may use WinRM, but the account may not open a remote shell" + we.Detail}
		default:
			return WinRMPreflight{Level: PreflightUnreachable, Detail: err.Error()}
		}
	}
	if strings.Contains(out, sidHighIntegrity) || strings.Contains(out, sidSystemIntegrity) {
		return WinRMPreflight{Level: PreflightInstall, CanDiscover: true, CanInstall: true,
			Detail: "the session runs with an elevated token: discovery_mode=winrm and install_mode=iis are both available"}
	}
	return WinRMPreflight{Level: PreflightDiscover, CanDiscover: true,
		Detail: "the session runs with a standard (Medium integrity) token: discovery_mode=winrm works, install_mode=iis will fail " +
			"writing to ProgramData and the LocalMachine store. Use a local Administrator for installs (a local admin over a " +
			"network logon is still filtered to Medium unless LocalAccountTokenFilterPolicy=1)"}
}
