// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"strings"
	"testing"
)

func TestExchangeInstallModeIsRegistered(t *testing.T) {
	if !validInstallModes["exchange"] {
		t.Fatal("exchange missing from validInstallModes")
	}
	if err := validateKeyHandlingMode(KeyModeHubGenerated, "exchange"); err != nil {
		t.Fatalf("hub_generated must be allowed for exchange: %v", err)
	}
	if err := validateKeyHandlingMode(KeyModeClientCSR, "exchange"); err == nil {
		t.Fatal("client_csr cannot ride on a push mode")
	}
	if m, _ := effectiveKeyHandlingMode(ManagedTarget{InstallMode: "exchange"}); m != KeyModeHubGenerated {
		t.Fatalf("derived mode = %s", m)
	}
}

func TestSMTPVerifyHostPorts(t *testing.T) {
	if got := strings.Join(smtpVerifyHostPorts("mail.example.com", nil), ","); got != "mail.example.com:25,mail.example.com:587" {
		t.Fatalf("defaults = %s", got)
	}
	if got := smtpVerifyHostPorts("h", []int{0, 70000, 2525}); len(got) != 1 || got[0] != "h:2525" {
		t.Fatalf("out-of-range ports must be dropped: %v", got)
	}
}
