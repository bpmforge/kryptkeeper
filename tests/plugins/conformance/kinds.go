// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"testing"

	"kryptkeeper/internal/plugins/delivery"
)

// Typed stubs for the kinds whose operations land later (D-321). Each takes
// the plugin and a mock of its service, so a plugin's conformance test can
// already name the suite it will be graded by; until the ticket named in the
// skip message fills it in, the suite skips rather than passing vacuously.
// The delivery suite is Suite, the notify suite NotifySuite, the ticket suite
// TicketSuite, the dns01 suite DNS01Suite and the credentials suite
// CredentialsSuite.

// InventoryDevice mocks a read-only inventory source (W38-05, W38-09).
type InventoryDevice interface{ Env() delivery.Env }

func InventorySuite(t *testing.T, _ *delivery.Plugin, _ InventoryDevice) {
	t.Skip("inventory kind conformance is filled in by W38-09")
}
