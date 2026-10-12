// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "kryptkeeper/internal/ca"

// activeCAStore is the process-wide CA store used by the raw keystore
// key-rotate handler (handlers_keys.go) to refuse rotating a key that
// backs a CA (W9-04/G-35) -- mirrors activeTenantStore's established
// package-level-setter pattern (handlers_tenants.go) rather than threading
// a new parameter through Run/RunWithProtocols/RegisterKeyHandlers and
// every test call site for a dependency that's nil whenever no crypto
// engine is active. nil (the zero value) is the correct default: when no
// ca.Store exists, no key can possibly back a CA, so the guard trivially
// never triggers.
var activeCAStore ca.Store

// SetActiveCAStore sets the process-wide CA store. Exported so
// cmd/kryptkeeper/main.go (a different package) can call it, mirroring
// RegisterKeyHandlers/RegisterBackupHandlers' cross-package-call convention.
func SetActiveCAStore(s ca.Store) { activeCAStore = s }
