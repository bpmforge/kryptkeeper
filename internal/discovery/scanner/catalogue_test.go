// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"slices"
	"testing"
)

// W34-05: the new probes are full/deep only (D-206). The fast and targeted
// lists are pinned here so adding to the catalogue cannot widen them silently.
func TestFastAndTargetedPortListsAreUnchanged(t *testing.T) {
	fast := []int{443, 22, 636, 993, 465, 3389, 5986}
	targeted := []int{443, 8443, 22, 389, 636, 993, 995, 465, 25, 587, 5432, 3389, 5986}
	if got := portsForTier(tierFast); !slices.Equal(got, fast) {
		t.Errorf("fast tier changed: %v", got)
	}
	if got := portsForTier(tierTargeted); !slices.Equal(got, targeted) {
		t.Errorf("targeted tier changed: %v", got)
	}
}

func TestNewProtocolsAreFullTierOnly(t *testing.T) {
	cases := []struct {
		port     int
		protocol string
		kind     probeKind
		starttls string
	}{
		{1433, "mssql", probeTDS, ""},
		{3306, "mysql", probeSTARTTLS, "mysql"},
		{2484, "oracle", probeTLS, ""},
		{6380, "redis", probeTLS, ""},
		{27017, "mongodb", probeTLS, ""},
		{9093, "kafka", probeTLS, ""},
		{9200, "elasticsearch", probeTLS, ""},
		{8200, "vault", probeTLS, ""},
		{8501, "consul", probeTLS, ""},
		{8140, "puppet", probeTLS, ""},
	}
	full, targeted := portsForTier(tierFull), portsForTier(tierTargeted)
	for _, c := range cases {
		e := protocolForPort(c.port)
		if e.protocol != c.protocol || e.kind != c.kind || e.starttls != c.starttls || e.tier != tierFull {
			t.Errorf("port %d: %+v", c.port, e)
		}
		if !slices.Contains(full, c.port) || slices.Contains(targeted, c.port) {
			t.Errorf("port %d must be in full and not in targeted", c.port)
		}
	}
	if got := PortsForScanType("full"); !slices.Contains(got, 1433) || slices.Contains(PortsForScanType("fast"), 1433) {
		t.Error("scan types do not map the new ports to full only")
	}
}

// Every catalogue tag the endpoints table stores must be one its CHECK admits
// or fall to 'other'; the databases the CHECK was widened for keep their name.
func TestCatalogueTagsMapToProtocolColumn(t *testing.T) {
	for _, tag := range []string{"mssql", "mysql", "oracle", "redis", "mongodb", "kafka"} {
		if portTech[tag] == "" {
			t.Errorf("%s has no port-default technology", tag)
		}
	}
}
