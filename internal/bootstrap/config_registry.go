// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"strings"

	"kryptkeeper/internal/privexec"
)

// W34-14 (D-209): the privilege mode the credential form and the Target Setup
// wizard preselect. The consumer is the UI only; a stored credential carries
// its own sudo_mode, so changing this never alters an existing credential.
const (
	configKeyAgentlessPrivilegeMode = "agentless.default_privilege_mode"
	configCategoryAgentless         = "agentless"
	// defaultAgentlessPrivilegeMode applies when the key is unset in both the
	// database and the environment.
	defaultAgentlessPrivilegeMode = string(privexec.ModeHelper)
)

var agentlessPrivilegeModeDef = configKeyDef{
	Key:      configKeyAgentlessPrivilegeMode,
	EnvVar:   "KRYPTKEEPER_AGENTLESS_DEFAULT_PRIVILEGE_MODE",
	Category: configCategoryAgentless,
}

// validateAgentlessPrivilegeMode accepts exactly the four modes; the empty
// string is not a mode here (an unset key falls back to the default instead).
func validateAgentlessPrivilegeMode(value string) error {
	switch privexec.Mode(strings.TrimSpace(value)) {
	case privexec.ModeNone, privexec.ModeNoPasswd, privexec.ModePassword, privexec.ModeHelper:
		return nil
	}
	return fmt.Errorf("must be one of none, nopasswd, password, helper")
}
