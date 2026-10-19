// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"testing"

	"kryptkeeper/internal/discovery/scanner"
)

func TestHostFilesPersistAndInheritSQLite(t *testing.T)   { runHostFilesCase(t, false) }
func TestHostFilesPersistAndInheritPostgres(t *testing.T) { runHostFilesCase(t, true) }

func hostFile(path, kind, posture string, certs []string, findings ...string) scanner.HostFile {
	return scanner.HostFile{Path: path, Kind: kind, OwnerUID: 0, OwnerGID: 0, Owner: "root", Group: "root", Mode: "600",
		Statted: true, ServiceTech: "tomcat", ServiceName: "java", ServiceUID: 1001, Posture: posture,
		Findings: findings, CertFingerprints: certs}
}

func renewalRequired(t *testing.T, db *sql.DB, postgres bool, id string) bool {
	t.Helper()
	var v any
	if err := db.QueryRow(dialectQuery(postgres, `SELECT renewal_privilege_required FROM managed_targets WHERE id = ?`), id).Scan(&v); err != nil {
		t.Fatalf("read flag: %v", err)
	}
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	}
	t.Fatalf("flag type %T", v)
	return false
}

func runHostFilesCase(t *testing.T, postgres bool) {
	s, db := migratedLinkStore(t, postgres)
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO managed_targets (id, name, host, created_at, updated_at) VALUES ('mt1', 'n', 'app.example.com', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	cert := testDiscoveredCert("leaf-fp", 10)
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{
		{Host: "app.example.com", Port: 8443, Protocol: "https-alt", Reachable: true, Certs: []scanner.DiscoveredCert{cert}},
	}); err != nil {
		t.Fatal(err)
	}

	obs := &scanner.HostObservations{TargetID: "mt1", FilesScanned: true, Files: []scanner.HostFile{
		hostFile("/opt/tomcat/conf/keystore.jks", "jks", "privileged", []string{"leaf-fp"}, "PRIVILEGED_INSTALL_PATH: path=/opt/tomcat/conf/keystore.jks"),
		hostFile("/opt/tomcat/conf/other.jks", "jks", "standard", []string{"leaf-fp"}),
		{Path: "/opt/tomcat/conf/tls.key", Kind: "key", OwnerUID: 0, OwnerGID: 0, Owner: "root", Mode: "644", Statted: true, ServiceUID: -1, Posture: "standard",
			Findings: []string{"KEY_WORLD_READABLE: path=/opt/tomcat/conf/tls.key mode=644"}},
	}}
	if err := persistHostFiles(ctx, db, postgres, "", "app.example.com", obs); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM discovered_files`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("files = %d, %v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificate_files`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("one cert in two files must link to both: %d, %v", n, err)
	}
	if !renewalRequired(t, db, postgres, "mt1") {
		t.Fatal("a privileged file must set renewal_privilege_required")
	}

	e := endpointByPort(t, s, 8443)
	if e.InstallPosture == nil || e.InstallPosture.Posture != "privileged" || e.InstallPosture.Path != "/opt/tomcat/conf/keystore.jks" ||
		e.InstallPosture.ServiceTech != "tomcat" || len(e.InstallPosture.Findings) != 1 {
		t.Fatalf("the served leaf must inherit the file's posture: %+v", e.InstallPosture)
	}

	// A rescan that statted nothing leaves the flag alone.
	unstatted := &scanner.HostObservations{TargetID: "mt1", FilesScanned: true, Files: []scanner.HostFile{
		{Path: "/opt/tomcat/conf/keystore.jks", Kind: "jks", OwnerUID: -1, OwnerGID: -1, ServiceUID: -1, Posture: "unknown", CertFingerprints: []string{"leaf-fp"}},
	}}
	if err := persistHostFiles(ctx, db, postgres, "", "app.example.com", unstatted); err != nil {
		t.Fatal(err)
	}
	if !renewalRequired(t, db, postgres, "mt1") {
		t.Fatal("an unprivileged rescan that could not stat must not clear the flag")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM discovered_files`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("files no longer seen must be removed: %d, %v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificate_files WHERE file_id NOT IN (SELECT id FROM discovered_files)`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("orphan cert links: %d, %v", n, err)
	}

	// A later scan that sees the file standard clears the flag.
	std := &scanner.HostObservations{TargetID: "mt1", FilesScanned: true, Files: []scanner.HostFile{
		hostFile("/opt/tomcat/conf/keystore.jks", "jks", "standard", []string{"leaf-fp"}),
	}}
	if err := persistHostFiles(ctx, db, postgres, "", "app.example.com", std); err != nil {
		t.Fatal(err)
	}
	if renewalRequired(t, db, postgres, "mt1") {
		t.Fatal("standard posture must clear renewal_privilege_required")
	}
	if e := endpointByPort(t, s, 8443); e.InstallPosture == nil || e.InstallPosture.Posture != "standard" {
		t.Fatalf("posture should follow the latest scan: %+v", e.InstallPosture)
	}

	// A scan that did not run the posture pass changes nothing.
	if err := persistHostFiles(ctx, db, postgres, "", "app.example.com", &scanner.HostObservations{TargetID: "mt1"}); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM discovered_files`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("skipped pass deleted rows: %d, %v", n, err)
	}
}

func TestHostFilesTenantIsolation(t *testing.T) {
	s, db := migratedLinkStore(t, false)
	_ = s
	ctx := context.Background()
	obs := func(posture string) *scanner.HostObservations {
		return &scanner.HostObservations{FilesScanned: true, Files: []scanner.HostFile{hostFile("/p.jks", "jks", posture, nil)}}
	}
	if err := persistHostFiles(ctx, db, false, "a", "h", obs("privileged")); err != nil {
		t.Fatal(err)
	}
	if err := persistHostFiles(ctx, db, false, "b", "h", obs("standard")); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM discovered_files`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("tenants must not overwrite each other: %d, %v", n, err)
	}
}
