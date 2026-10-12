package db

import "testing"

// The handler accepts these types (bootstrap.validInventorySourceTypes); the
// table's CHECK once allowed only two of them, so creating the rest failed
// with a 503 that no fake-store unit test could see.
func TestInventorySourcesAcceptsEveryHandlerType(t *testing.T) {
	db := openMigrated(t)
	for _, typ := range []string{"adcs_export", "adcs_live", "digicert", "sectigo", "entrust", "aws_pca", "gcp_cas"} {
		_, err := db.Exec(`INSERT INTO inventory_sources (id, name, type, created_at, updated_at) VALUES (?, ?, ?, 'x', 'x')`, "id-"+typ, typ, typ)
		if err != nil {
			t.Errorf("type %q rejected by migrated schema: %v", typ, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO inventory_sources (id, name, type, created_at, updated_at) VALUES ('bad', 'bad', 'nope', 'x', 'x')`); err == nil {
		t.Error("unknown type accepted")
	}
}
