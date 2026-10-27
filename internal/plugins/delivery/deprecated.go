// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

// Deprecation explains why a plugin is on its way out and when it goes.
type Deprecation struct {
	Reason  string
	Removal string
}

// deprecated lists plugins the project no longer develops or validates (D-329).
// It is keyed by plugin id rather than carried in the manifest because every
// hub parses manifests strictly: a new manifest field would make a 1.1.0 hub
// refuse the plugin outright instead of warning.
var deprecated = map[string]Deprecation{
	"kryptkeeper.opsgenie": {
		Reason:  "Atlassian stopped selling Opsgenie on 2025-06-04 and ends support on 2027-04-05; move alerts to Jira Service Management, PagerDuty or a webhook",
		Removal: "2.0",
	},
}

// Deprecated reports whether the plugin with this id is deprecated.
func Deprecated(id string) (Deprecation, bool) {
	d, ok := deprecated[id]
	return d, ok
}
