// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"strings"

	"kryptkeeper/internal/logging"
)

const (
	windowsEnrollRole   = "protocol:wstep"
	enrollUpgradeMarker = ".d291-enroll-upgrade"
	adminEnrollRole     = "pki-admin"
)

// EnrollUpgradeResult is what UpgradeWindowsEnrollLists changed.
type EnrollUpgradeResult struct {
	Ran     bool
	Widened []string // template names that gained protocol:wstep
	Refused []string // role-only lists left as they are: refused on WSTEP now
}

// UpgradeWindowsEnrollLists is the one-time D-291 upgrade. Before D-291 XCEP
// and WSTEP ignored an enroll list with no protocol:wstep entry, so every
// template with a role-only list was enrollable by Windows clients. Now every
// non-empty list is enforced, so a template that is autoenrolled (the only
// signal a template is meant for Windows) gets protocol:wstep appended and
// keeps working. Any other role-only list, and anything naming pki-admin, is
// left alone and is refused on WSTEP from now on, which is the point of the
// change. It does not bump the template revision: that would make every
// Windows client re-enroll. A marker file beside the template store makes it
// run once, so a list an admin narrows later is never widened again. Only the
// file provider holds templates; other providers are untouched.
func UpgradeWindowsEnrollLists(tp TemplateProvider) EnrollUpgradeResult {
	var res EnrollUpgradeResult
	p, ok := tp.(*fileTemplateProvider)
	if !ok {
		return res
	}
	marker := p.filePath + enrollUpgradeMarker
	if _, err := os.Stat(marker); err == nil {
		return res
	}
	items, loaded := p.loadItems()
	if !loaded {
		if _, err := os.Stat(p.filePath); err == nil {
			return res // unreadable store: retry next start rather than mark done
		}
	}
	changed := false
	for i := range items {
		roles := items[i].EnrollRoles()
		if len(roles) == 0 || namesWindows(roles) {
			continue
		}
		if items[i].AutoEnroll && !containsRole(roles, adminEnrollRole) {
			items[i].EnrollmentPermissions = &EnrollmentPermissions{Enroll: append(append([]string(nil), roles...), windowsEnrollRole)}
			res.Widened = append(res.Widened, items[i].Name)
			changed = true
			continue
		}
		res.Refused = append(res.Refused, items[i].Name)
	}
	if changed {
		if err := p.saveItems(items); err != nil {
			logging.Warnf("template enroll-list upgrade (D-291) not saved: %v", err)
			return EnrollUpgradeResult{}
		}
	}
	if err := writeStateFile(marker, []byte("D-291 enroll-list upgrade done\n")); err != nil {
		logging.Warnf("template enroll-list upgrade (D-291): marker not written: %v", err)
	}
	res.Ran = true
	if len(res.Widened) > 0 {
		logging.Infof("D-291 upgrade: added %s to the enroll list of autoenrolled template(s) %s so Windows enrollment keeps working", windowsEnrollRole, strings.Join(res.Widened, ", "))
	}
	if len(res.Refused) > 0 {
		logging.Warnf("D-291 upgrade: template(s) %s have an enroll list with no %s entry and are now refused on WSTEP and not offered over XCEP; add %s (or %s:<host fqdn>) to allow Windows clients", strings.Join(res.Refused, ", "), windowsEnrollRole, windowsEnrollRole, windowsEnrollRole)
	}
	if len(res.Widened) == 0 && len(res.Refused) == 0 {
		logging.Infof("D-291 upgrade: no template enroll lists needed changes")
	}
	return res
}

func namesWindows(roles []string) bool {
	for _, r := range roles {
		if r == windowsEnrollRole || strings.HasPrefix(r, windowsEnrollRole+":") {
			return true
		}
	}
	return false
}

func containsRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
