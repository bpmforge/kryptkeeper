// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"kryptkeeper/internal/migration"
	"kryptkeeper/internal/migration/adcs"
	"kryptkeeper/internal/migration/certcentral"
	"kryptkeeper/internal/migration/keyfactor"
	"kryptkeeper/internal/migration/vault"
	"kryptkeeper/internal/migration/venafi"
)

// migrationImporters lists the template importers, one line each, alphabetical.
func migrationImporters() []migration.Importer {
	return []migration.Importer{
		adcs.New(),
		certcentral.New(),
		keyfactor.New(),
		vault.New(),
		venafi.New(),
	}
}
