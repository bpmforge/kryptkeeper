// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"sort"

	"kryptkeeper/internal/logging"
)

// W34-11: the privileged-credentials section shared by the access-review
// report and the executive summary (D-208). It lists credentials flagged as
// high-impact on the hosts they reach, with those hosts, so a reviewer sees
// "N privileged credentials in use on M hosts".

// PrivilegedCredentialRow is one flagged credential.
type PrivilegedCredentialRow struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
	// Source is auto or manual, from privileged_set_by.
	Source string   `json:"source"`
	SetAt  string   `json:"set_at,omitempty"`
	Hosts  []string `json:"hosts"`
	// LastUsed is the latest scan of a target that uses the credential.
	LastUsed string `json:"last_used,omitempty"`
}

// PrivilegedCredentialsSummary is the report section.
type PrivilegedCredentialsSummary struct {
	Count       int                       `json:"count"`
	HostCount   int                       `json:"host_count"`
	Credentials []PrivilegedCredentialRow `json:"credentials"`
}

func privilegedSource(setBy string) string {
	if len(setBy) >= 5 && setBy[:5] == "auto:" {
		return "auto"
	}
	return "manual"
}

// buildPrivilegedCredentialsSummary reads the credential and target stores for
// the principal's tenant. A store that is absent or fails yields nil: this is
// context for a report, never a reason to fail it.
func buildPrivilegedCredentialsSummary(ctx context.Context, pd AuthPrincipal, creds OutboundCredentialStore, targets ManagedTargetStore) *PrivilegedCredentialsSummary {
	if creds == nil {
		return nil
	}
	metas, err := creds.List(ctx)
	if err != nil {
		logging.Infof("privileged credentials summary: list credentials: %v", err)
		return nil
	}
	byCred := map[string][]ManagedTarget{}
	var states map[string]TargetState
	if ss, ok := targets.(targetStateStore); ok {
		if st, err := ss.TargetStates(ctx); err == nil {
			states = st
		}
	}
	if targets != nil {
		ts, err := targets.List(ctx)
		if err != nil {
			logging.Infof("privileged credentials summary: list targets: %v", err)
		}
		for _, t := range ts {
			if t.CredentialRef != "" && stampedTenantVisible(pd, t.Tenant) {
				byCred[t.CredentialRef] = append(byCred[t.CredentialRef], t)
			}
		}
	}
	out := &PrivilegedCredentialsSummary{Credentials: []PrivilegedCredentialRow{}}
	hosts := map[string]bool{}
	for _, m := range metas {
		if !m.Privileged || !stampedTenantVisible(pd, m.Tenant) {
			continue
		}
		row := PrivilegedCredentialRow{ID: m.ID, Name: m.Name, Reason: m.PrivilegedReason, Source: privilegedSource(m.PrivilegedSetBy),
			SetAt: m.PrivilegedSetAt, Hosts: []string{}}
		for _, t := range byCred[m.ID] {
			row.Hosts = append(row.Hosts, t.Host)
			hosts[t.Host] = true
			if at := states[t.ID].LastScannedAt; at > row.LastUsed {
				row.LastUsed = at
			}
		}
		sort.Strings(row.Hosts)
		out.Credentials = append(out.Credentials, row)
	}
	out.Count, out.HostCount = len(out.Credentials), len(hosts)
	return out
}
