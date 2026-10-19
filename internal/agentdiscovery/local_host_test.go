// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W34-09: the walk reports what it could not open instead of skipping silently.
func TestWalkLinuxCertsDetailedReportsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.pem")
	locked := filepath.Join(dir, "locked.pem")
	lockedDir := filepath.Join(dir, "private")
	if err := os.WriteFile(ok, []byte(certPEM(t, "ok.example.com")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(locked, []byte(certPEM(t, "locked.example.com")), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lockedDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lockedDir, 0o755) })

	certs, unreadable, err := WalkLinuxCertsDetailed([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("want only the readable cert, got %d", len(certs))
	}
	got := map[string]bool{}
	for _, u := range unreadable {
		got[u.Path] = true
		if !strings.Contains(u.Error, "permission denied") {
			t.Errorf("error text: %q", u.Error)
		}
	}
	if !got[locked] || !got[lockedDir] || got[ok] {
		t.Fatalf("unreadable = %v", unreadable)
	}
	// The legacy entry point keeps its result and no longer drops them silently.
	if c, err := WalkLinuxCerts([]string{dir}); err != nil || len(c) != 1 {
		t.Fatalf("WalkLinuxCerts: %d %v", len(c), err)
	}
}

func TestHostInventoryFromReportsUnreadableAndFacts(t *testing.T) {
	res := AgentlessScanResult{
		Host: "localhost",
		Errors: []string{
			"localhost:/opt/tomcat/conf/keystore.jks: ssh executor: read /opt/tomcat/conf/keystore.jks: permission denied",
			"localhost:find: '/root/certs': Permission denied",
			"localhost:/etc/ssl/bad.p12: not a PKCS#12 keystore",
			"localhost:/opt/tomcat/conf/keystore.jks: permission denied",
		},
		Files:     []FileFact{{Path: "/opt/tomcat/conf/keystore.jks", Kind: FileKindJKS, UID: 0, GID: 0, Mode: "600", Owner: "root", Group: "root"}},
		Listeners: []Listener{{Port: 8443, PID: 9, UID: 1001, GID: 1001, Comm: "java", Tech: "tomcat", ConfigRefs: []string{"/opt/tomcat/conf/keystore.jks"}}},
	}
	h := HostInventoryFrom(res, "kryptkeeper-agent", "")
	if !h.Scanned || h.PrivilegeMode != "none" || h.UnreadableTotal != 2 || len(h.UnreadablePaths) != 2 {
		t.Fatalf("%+v", h)
	}
	if h.UnreadablePaths[0].Path != "/opt/tomcat/conf/keystore.jks" || h.UnreadablePaths[1].Path != "/root/certs" {
		t.Fatalf("paths: %+v", h.UnreadablePaths)
	}
	if len(h.Files) != 1 || h.Files[0].Mode != "600" || len(h.Listeners) != 1 || h.Listeners[0].Tech != "tomcat" {
		t.Fatalf("%+v", h)
	}
	for i := 0; i < maxReportedUnreadable+20; i++ {
		res.Errors = append(res.Errors, fmt.Sprintf("localhost:/srv/k/%d.jks: permission denied", i))
	}
	h = HostInventoryFrom(res, "u", "helper")
	if len(h.UnreadablePaths) != maxReportedUnreadable || h.UnreadableTotal != 2+maxReportedUnreadable+20 {
		t.Fatalf("cap/total: %d / %d", len(h.UnreadablePaths), h.UnreadableTotal)
	}
}
