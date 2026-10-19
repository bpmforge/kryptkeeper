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

// scriptExec answers commands and file reads from maps, recording every read.
type scriptExec struct {
	run   map[string]string // "name arg arg" -> output
	files map[string]string
	reads []string
}

func (s *scriptExec) Exists(p string) bool { _, ok := s.files[p]; return ok }
func (s *scriptExec) ReadFile(p string) ([]byte, error) {
	s.reads = append(s.reads, p)
	c, ok := s.files[p]
	if !ok {
		return nil, fmt.Errorf("permission denied")
	}
	return []byte(c), nil
}
func (s *scriptExec) WriteFile(string, []byte, os.FileMode) error { return nil }
func (s *scriptExec) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	out, ok := s.run[strings.Join(append([]string{name}, args...), " ")]
	if !ok {
		return nil, fmt.Errorf("%s: not available", name)
	}
	return []byte(out), nil
}

const ssRoot = `State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*     users:(("nginx",pid=20,fd=6),("nginx",pid=21,fd=6))
LISTEN 0      100                *:8443            *:*     users:(("java",pid=300,fd=45))
LISTEN 0      128             [::]:22           [::]:*     users:(("sshd",pid=10,fd=3))
LISTEN 0      128      127.0.0.53%lo:53         0.0.0.0:*
`

func statusFile(name string, uid, gid int) string {
	return fmt.Sprintf("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n", name, uid, uid, uid, uid, gid, gid, gid, gid)
}

func TestListenersSweepBuildsPerPidRowsAndTech(t *testing.T) {
	x := &scriptExec{
		run: map[string]string{
			"ss -ltnp":               ssRoot,
			"readlink /proc/300/exe": "/usr/lib/jvm/java-17/bin/java\n",
			"readlink /proc/300/cwd": "/opt/tomcat\n",
			"readlink /proc/20/exe":  "/usr/sbin/nginx\n",
			"readlink /proc/21/exe":  "/usr/sbin/nginx\n",
			"id -nu 0":               "root\n",
			"id -nu 1001":            "tomcat\n",
			"id -nu 33":              "www-data\n",
		},
		files: map[string]string{
			"/proc/20/status":  statusFile("nginx", 0, 0),
			"/proc/21/status":  statusFile("nginx", 33, 33),
			"/proc/10/status":  statusFile("sshd", 0, 0),
			"/proc/300/status": statusFile("java", 1001, 1001),
			"/proc/300/cmdline": "java\x00-Dcatalina.base=/opt/tomcat\x00-Djavax.net.ssl.keyStore=/opt/tomcat/conf/keystore.jks\x00" +
				"-Djavax.net.ssl.keyStorePassword=hunter2\x00org.apache.catalina.startup.Bootstrap\x00",
		},
	}
	sweep, err := Listeners(context.Background(), x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sweep.Hidden != 1 {
		t.Fatalf("hidden = %d, want 1 (the pid-less :53 socket)", sweep.Hidden)
	}
	byKey := map[[2]int]Listener{}
	for _, l := range sweep.Listeners {
		byKey[[2]int{l.Port, l.PID}] = l
	}
	if len(sweep.Listeners) != 5 {
		t.Fatalf("got %d listeners, want one per (port,pid): %+v", len(sweep.Listeners), sweep.Listeners)
	}
	master, worker := byKey[[2]int{80, 20}], byKey[[2]int{80, 21}]
	if master.UID != 0 || worker.UID != 33 || master.Tech != "nginx" || worker.Tech != "nginx" || worker.User != "www-data" {
		t.Fatalf("nginx master/worker lost: %+v %+v", master, worker)
	}
	tc := byKey[[2]int{8443, 300}]
	if tc.Tech != "tomcat" || tc.UID != 1001 || tc.User != "tomcat" || tc.Cwd != "/opt/tomcat" || tc.Exe == "" {
		t.Fatalf("tomcat listener wrong: %+v", tc)
	}
	if len(tc.ConfigRefs) != 1 || tc.ConfigRefs[0] != "/opt/tomcat/conf/keystore.jks" || len(tc.AppDirs) == 0 || tc.AppDirs[0] != "/opt/tomcat" {
		t.Fatalf("config refs/app dirs: %+v", tc)
	}
	if hidden := byKey[[2]int{53, 0}]; hidden.UID != UnknownID || hidden.UIDKnown() {
		t.Fatalf("pid-less socket must have unknown uid: %+v", hidden)
	}
	blob := fmt.Sprintf("%+v", sweep)
	if strings.Contains(blob, "hunter2") {
		t.Fatal("command-line password leaked into the sweep")
	}
}

func TestListenersUnreadableStatusCountsAsHidden(t *testing.T) {
	x := &scriptExec{run: map[string]string{"ss -ltnp": ssRoot}, files: map[string]string{}}
	sweep, err := Listeners(context.Background(), x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sweep.Hidden != len(sweep.Listeners) {
		t.Fatalf("every pid unreadable: hidden %d of %d", sweep.Hidden, len(sweep.Listeners))
	}
	for _, l := range sweep.Listeners {
		if l.UIDKnown() {
			t.Fatalf("uid must be unknown: %+v", l)
		}
	}
	// The process name from ss still classifies, so evidence survives (at a lower weight, applied by the caller).
	var nginx int
	for _, l := range sweep.Listeners {
		if l.Tech == "nginx" {
			nginx++
		}
	}
	if nginx != 2 {
		t.Fatalf("comm from ss should still classify nginx, got %d", nginx)
	}
}

func TestListenersNetstatFallback(t *testing.T) {
	x := &scriptExec{
		run: map[string]string{"netstat -ltnp": "Active Internet connections (only servers)\n" +
			"Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n" +
			"tcp 0 0 0.0.0.0:1433 0.0.0.0:* LISTEN 77/sqlservr\n" +
			"tcp6 0 0 :::25 :::* LISTEN -\n"},
		files: map[string]string{"/proc/77/status": statusFile("sqlservr", 999, 999)},
	}
	sweep, err := Listeners(context.Background(), x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sweep.Listeners) != 2 || sweep.Hidden != 1 {
		t.Fatalf("%+v", sweep)
	}
	if l := sweep.Listeners[0]; l.Port != 25 && l.Tech != "mssql" {
		t.Fatalf("%+v", l)
	}
}

func TestListenersHelperOutputUsesTrailerAndPlainProc(t *testing.T) {
	helper := "LISTEN 0 100 *:8443 *:* users:((\"java\",pid=300,fd=4))\nproc pid=300 uid=1001 exe=/usr/bin/java\n"
	priv := &scriptExec{run: map[string]string{"ss -ltnp": helper}}
	plain := &scriptExec{files: map[string]string{
		"/proc/300/cmdline": "java\x00-jar\x00/opt/tomcat/lib/catalina.jar\x00",
	}}
	sweep, err := Listeners(context.Background(), priv, plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(sweep.Listeners) != 1 {
		t.Fatalf("%+v", sweep)
	}
	l := sweep.Listeners[0]
	if l.UID != 1001 || l.Exe != "/usr/bin/java" || l.Tech != "tomcat" {
		t.Fatalf("helper trailer + plain cmdline should give tomcat: %+v", l)
	}
	for _, r := range priv.reads {
		if strings.HasPrefix(r, "/proc/") {
			t.Fatalf("privileged executor must not be used for /proc when plain works: %s", r)
		}
	}
}

func TestListenersPlainJavaStaysUnclassified(t *testing.T) {
	x := &scriptExec{
		run:   map[string]string{"ss -ltnp": "LISTEN 0 1 *:9000 *:* users:((\"java\",pid=5,fd=1))\n"},
		files: map[string]string{"/proc/5/status": statusFile("java", 1, 1), "/proc/5/cmdline": "java\x00-jar\x00app.jar\x00"},
	}
	sweep, _ := Listeners(context.Background(), x, nil)
	if len(sweep.Listeners) != 1 || sweep.Listeners[0].Tech != "" {
		t.Fatalf("a bare java process must not be guessed as tomcat: %+v", sweep.Listeners)
	}
}

func TestListenersNothingAvailableIsAnError(t *testing.T) {
	if _, err := Listeners(context.Background(), &scriptExec{}, nil); err == nil {
		t.Fatal("neither ss nor netstat: want an error")
	}
}

func TestTechForProcessTable(t *testing.T) {
	cases := []struct {
		comm, exe, cmd string
		refs           []string
		want           string
	}{
		{"java", "", "java -Dcatalina.base=/x", nil, "tomcat"},
		{"java", "", "java -jar a.jar", []string{"/x/server.xml"}, "tomcat"},
		{"java", "", "java -jar a.jar", []string{"/x/ks.jks"}, "tomcat"},
		{"java", "", "java -jar jetty-start.jar", nil, "jetty"},
		{"java", "", "java -jar app.jar", nil, ""},
		{"httpd", "", "", nil, "apache"},
		{"apache2", "", "", nil, "apache"},
		{"nginx", "", "", nil, "nginx"},
		{"haproxy", "", "", nil, "haproxy"},
		{"slapd", "", "", nil, "ldap-openldap"},
		{"sqlservr", "", "", nil, "mssql"},
		{"master", "/usr/libexec/postfix/master", "", nil, "postfix"},
		{"master", "/usr/bin/other", "", nil, ""},
		{"dovecot", "", "", nil, "dovecot"},
		{"mysqld", "", "", nil, "mysql"},
		{"postgres", "", "", nil, "postgres"},
		{"redis-server", "", "", nil, "redis"},
		{"mongod", "", "", nil, "mongodb"},
		{"node", "", "", nil, "node"},
		{"dotnet", "", "", nil, "kestrel"},
		{"envoy", "", "", nil, "envoy"},
		{"caddy", "", "", nil, "caddy"},
		{"traefik", "", "", nil, "traefik"},
		{"vault", "", "", nil, "vault"},
		{"consul", "", "", nil, "consul"},
		{"etcd", "", "", nil, "etcd"},
		{"kube-apiserver", "", "", nil, "kubernetes-api"},
		{"", "/usr/sbin/nginx", "", nil, "nginx"},
		{"bash", "", "", nil, ""},
	}
	for _, c := range cases {
		if got := TechForProcess(c.comm, c.exe, c.cmd, c.refs); got != c.want {
			t.Errorf("%s %s %q: got %q want %q", c.comm, c.exe, c.cmd, got, c.want)
		}
	}
}

func TestPortOf(t *testing.T) {
	for in, want := range map[string]int{"0.0.0.0:443": 443, "*:80": 80, "[::]:22": 22, "[::1]:5432": 5432, "127.0.0.53%lo:53": 53, "junk": 0, "x:99999": 0} {
		if got := portOf(in); got != want {
			t.Errorf("portOf(%q) = %d, want %d", in, got, want)
		}
	}
}
