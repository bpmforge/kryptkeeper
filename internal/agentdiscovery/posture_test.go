// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseStatLineHandlesSpacesAndRejectsNoise(t *testing.T) {
	f, ok := parseStatLine("0 0 600 root root /opt/my app/keystore.jks")
	if !ok || f.Path != "/opt/my app/keystore.jks" || f.UID != 0 || f.Mode != "600" || f.Owner != "root" || f.Group != "root" {
		t.Fatalf("%+v %v", f, ok)
	}
	for _, bad := range []string{"", "stat: cannot statx '/x': Permission denied", "a b c d e /x", "0 0 999 root root /x", "0 0 600 root root relative"} {
		if _, ok := parseStatLine(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseHelperStatNamesOnly(t *testing.T) {
	f, ok := parseHelperStat("regular file|600|root|root|2048|/opt/tomcat/conf/keystore.jks")
	if !ok || f.Owner != "root" || f.UID != 0 || f.GID != 0 || f.Mode != "600" {
		t.Fatalf("%+v %v", f, ok)
	}
	f, _ = parseHelperStat("regular file|640|tomcat|ssl-cert|2048|/x")
	if f.UID != UnknownID || f.GID != UnknownID {
		t.Fatalf("non-root names must not invent numeric ids: %+v", f)
	}
}

func fact(kind, p string, uid, gid int, mode, owner string) FileFact {
	return FileFact{Path: p, Kind: kind, UID: uid, GID: gid, Mode: mode, Owner: owner, Group: "g", Statted: true, ServiceUID: UnknownID}
}

func listener(tech, comm string, port, pid, uid, gid int) Listener {
	return Listener{Port: port, PID: pid, UID: uid, GID: gid, Comm: comm, Tech: tech}
}

func TestClassifyFilePosture(t *testing.T) {
	tomcat := serviceFor("tomcat", []Listener{listener("tomcat", "java", 8443, 1, 1001, 1001)})
	rootApp := serviceFor("tomcat", []Listener{listener("tomcat", "java", 8443, 1, 0, 0)})
	nginxMixed := serviceFor("nginx", []Listener{listener("nginx", "nginx", 443, 1, 0, 0), listener("nginx", "nginx", 443, 2, 33, 33)})
	nginxAllRoot := serviceFor("nginx", []Listener{listener("nginx", "nginx", 443, 1, 0, 0), listener("nginx", "nginx", 443, 2, 0, 0)})
	nginxMasterOnly := serviceFor("nginx", []Listener{listener("nginx", "nginx", 443, 1, 0, 0)})
	nginxUser := serviceFor("nginx", []Listener{listener("nginx", "nginx", 8080, 1, 33, 33)})

	cases := []struct {
		name     string
		f        FileFact
		svc      *service
		posture  string
		wantCode string // "" = no findings
	}{
		{"root-owned jks, tomcat as tomcat", fact(FileKindJKS, "/opt/tomcat/conf/keystore.jks", 0, 0, "600", "root"), &tomcat, PosturePrivileged, FindingPrivilegedInstallPath},
		{"jks owned by the service account", fact(FileKindJKS, "/opt/tomcat/conf/keystore.jks", 1001, 1001, "600", "tomcat"), &tomcat, PostureStandard, ""},
		{"group writable by the service group", fact(FileKindPEM, "/opt/x.pem", 0, 1001, "664", "root"), &tomcat, PostureStandard, ""},
		{"world writable", fact(FileKindPEM, "/opt/x.pem", 0, 0, "666", "root"), &tomcat, PostureStandard, ""},
		{"app server as root", fact(FileKindJKS, "/opt/tomcat/conf/keystore.jks", 0, 0, "600", "root"), &rootApp, PostureRootService, FindingServiceRunsAsRoot},
		{"nginx master root, worker www-data, root-owned cert", fact(FileKindPEM, "/etc/nginx/c.pem", 0, 0, "644", "root"), &nginxMixed, PostureStandard, ""},
		{"nginx entirely root", fact(FileKindPEM, "/etc/nginx/c.pem", 0, 0, "644", "root"), &nginxAllRoot, PostureRootService, FindingServiceRunsAsRoot},
		{"nginx master alone proves nothing", fact(FileKindPEM, "/etc/nginx/c.pem", 0, 0, "644", "root"), &nginxMasterOnly, PostureStandard, ""},
		{"nginx run as a user cannot write a root-owned cert", fact(FileKindPEM, "/etc/nginx/c.pem", 0, 0, "644", "root"), &nginxUser, PosturePrivileged, FindingPrivilegedInstallPath},
		{"home dir keystore for a service", fact(FileKindJKS, "/home/bob/ks.jks", 1001, 1001, "600", "tomcat"), &tomcat, PosturePrivileged, FindingHomeDirKeystore},
		{"key world readable", fact(FileKindKey, "/etc/ssl/k.key", 0, 0, "644", "root"), nil, PostureStandard, FindingKeyWorldReadable},
		{"key group readable by a broad group", fact(FileKindKey, "/etc/ssl/k.key", 0, 1000, "640", "root"), nil, PostureStandard, FindingKeyWorldReadable},
		{"key group readable by root group only", fact(FileKindKey, "/etc/ssl/k.key", 0, 0, "640", "root"), nil, PostureStandard, ""},
		{"key 0600", fact(FileKindKey, "/etc/ssl/k.key", 0, 0, "600", "root"), nil, PostureStandard, ""},
		{"no service tied", fact(FileKindPEM, "/etc/ssl/certs/ca.pem", 0, 0, "644", "root"), nil, PostureStandard, ""},
		{"not statted", FileFact{Path: "/x.pem", Kind: FileKindPEM, UID: UnknownID}, &tomcat, PostureUnknown, ""},
	}
	for _, c := range cases {
		f := c.f
		classifyFile(&f, c.svc)
		if f.Posture != c.posture {
			t.Errorf("%s: posture %q, want %q", c.name, f.Posture, c.posture)
		}
		switch {
		case c.wantCode == "" && len(f.Findings) != 0:
			t.Errorf("%s: unexpected findings %v", c.name, f.Findings)
		case c.wantCode != "" && (len(f.Findings) == 0 || !strings.HasPrefix(f.Findings[0], c.wantCode+": ")):
			t.Errorf("%s: findings %v, want %s", c.name, f.Findings, c.wantCode)
		}
	}
}

func TestFindingCodesAreNotSubstringsOfEachOther(t *testing.T) {
	codes := []string{FindingPrivilegedInstallPath, FindingServiceRunsAsRoot, FindingKeyWorldReadable, FindingHomeDirKeystore,
		"EXPIRED", "SELF_SIGNED", "WEAK_KEY", "WEAK_SIGNATURE", "HOSTNAME_MISMATCH", "UNTRUSTED_ROOT", "INCOMPLETE_CHAIN",
		"EXPIRING_7_DAYS", "EXPIRING_30_DAYS", "PQC_VULNERABLE", "NOT_TLS", "TLS_HANDSHAKE_FAILED", "POSTGRES_TLS_DISABLED",
		"DEPRECATED_TLS_VERSION", "UNREADABLE_PATH", "INSUFFICIENT_PRIVILEGE"}
	for i, a := range codes {
		for j, b := range codes {
			if i != j && strings.Contains(a, b) {
				t.Errorf("%s contains %s", a, b)
			}
		}
	}
}

func TestRefsFromConfigAndServerXML(t *testing.T) {
	nginx := "server {\n  ssl_certificate /etc/nginx/ssl/a.pem;\n  ssl_certificate_key /etc/nginx/ssl/a.key;\n}\n"
	got := refsFromConfigText(nginx)
	if len(got) != 2 || got[0] != "/etc/nginx/ssl/a.pem" || got[1] != "/etc/nginx/ssl/a.key" {
		t.Fatalf("%v", got)
	}
	xml := `<Connector port="8443" keystoreFile="conf/keystore.jks" keystorePass="s3cret"/>`
	refs := refsFromServerXML(xml, "/opt/tomcat")
	if len(refs) != 1 || refs[0] != "/opt/tomcat/conf/keystore.jks" {
		t.Fatalf("%v", refs)
	}
}

func TestExtraScanRootsSkipsCoveredAndShallow(t *testing.T) {
	ls := []Listener{{Tech: "tomcat", ConfigRefs: []string{"/opt/tomcat/conf/keystore.jks", "/etc/ssl/certs/x.pem"}, AppDirs: []string{"/opt/tomcat", "/"}}}
	got := extraScanRoots(ls, []string{"/etc/ssl"})
	if len(got) != 1 || got[0] != "/opt/tomcat/conf" {
		t.Fatalf("%v", got)
	}
}

// postureExec scripts a Tomcat host: a root-only keystore behind a tomcat user,
// a world-readable key, and a ReadFile log proving keys are never read.
type postureExec struct {
	reads []string
	stats map[string]string
}

func (e *postureExec) Exists(string) bool                          { return true }
func (e *postureExec) WriteFile(string, []byte, os.FileMode) error { return nil }
func (e *postureExec) ReadFile(p string) ([]byte, error) {
	e.reads = append(e.reads, p)
	switch p {
	case "/proc/9/status":
		return []byte("Name:\tjava\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n"), nil
	case "/proc/9/cmdline":
		return []byte("java\x00-Dcatalina.base=/opt/tomcat\x00org.apache.catalina.startup.Bootstrap\x00"), nil
	case "/opt/tomcat/conf/server.xml":
		return []byte(`<Connector keystoreFile="conf/keystore.jks"/>`), nil
	}
	return nil, fmt.Errorf("permission denied")
}
func (e *postureExec) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "ss":
		return []byte("LISTEN 0 1 *:8443 *:* users:((\"java\",pid=9,fd=1))\n"), nil
	case "readlink":
		if args[0] == "/proc/9/cwd" {
			return []byte("/opt/tomcat\n"), nil
		}
		return nil, fmt.Errorf("denied")
	case "id":
		return []byte("tomcat\n"), nil
	case "find":
		if args[0] == "/opt/tomcat/conf" {
			return []byte("/opt/tomcat/conf/keystore.jks\n/opt/tomcat/conf/tls.key\n"), nil
		}
		return []byte(fmt.Sprintf("find: '%s': No such file or directory\n", args[0])), fmt.Errorf("exit 1")
	case "stat":
		var b strings.Builder
		for _, p := range args[4:] {
			if l, ok := e.stats[p]; ok {
				b.WriteString(l + "\n")
			}
		}
		return []byte(b.String()), nil
	}
	return nil, fmt.Errorf("unexpected %s", name)
}

func TestScanPostureTomcatRootOwnedKeystore(t *testing.T) {
	x := &postureExec{stats: map[string]string{
		"/opt/tomcat/conf/keystore.jks": "0 0 600 root root /opt/tomcat/conf/keystore.jks",
		"/opt/tomcat/conf/tls.key":      "0 0 644 root root /opt/tomcat/conf/tls.key",
	}}
	res := NewAgentlessSSHScanner(x, "h", []string{"/etc/ssl"}).Scan(context.Background())
	if !res.FilesScanned || len(res.Files) != 2 {
		t.Fatalf("%+v / %v", res.Files, res.Errors)
	}
	by := map[string]FileFact{}
	for _, f := range res.Files {
		by[f.Path] = f
	}
	jks := by["/opt/tomcat/conf/keystore.jks"]
	if jks.Kind != FileKindJKS || jks.Posture != PosturePrivileged || jks.ServiceTech != "tomcat" || jks.ServiceUID != 1001 ||
		len(jks.Findings) != 1 || !strings.HasPrefix(jks.Findings[0], FindingPrivilegedInstallPath+": ") {
		t.Fatalf("jks = %+v", jks)
	}
	key := by["/opt/tomcat/conf/tls.key"]
	if key.Kind != FileKindKey || key.Posture != PosturePrivileged || len(key.Findings) != 2 || !strings.HasPrefix(key.Findings[0], FindingKeyWorldReadable) {
		t.Fatalf("key = %+v", key)
	}
	for _, r := range x.reads {
		if strings.HasSuffix(r, ".key") {
			t.Fatalf("a key file was read: %s", r)
		}
	}
}
