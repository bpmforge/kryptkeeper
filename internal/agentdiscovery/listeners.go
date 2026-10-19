// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"errors"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"kryptkeeper/internal/agentinstall"
)

// W34-07: the host-side half of service fingerprinting. A network scan can
// only guess what answers on a port; the host itself knows which process
// holds the socket, so a listener is the one signal that earns high
// confidence (W34-00-DESIGN section 1.2(8)).

// maxListenerPIDs bounds the per-process /proc reads so a host with
// thousands of sockets cannot turn one scan into thousands of SSH sessions.
const maxListenerPIDs = 128

// UnknownID marks a uid or gid the scan account could not read.
const UnknownID = -1

// Listener is one process holding one listening TCP port. A socket shared by
// a master and its workers yields one Listener per pid so the posture pass
// can classify by worker uid.
type Listener struct {
	Port int
	// PID is 0 for a socket whose owner the scan account could not see.
	PID  int
	UID  int // UnknownID when /proc/<pid>/status was unreadable
	GID  int // UnknownID when unreadable
	User string
	Exe  string
	Comm string
	Cwd  string
	// Tech is the vocabulary technology the process implies, "" when it implies none.
	Tech string
	// ConfigRefs are absolute keystore, certificate and server.xml paths named
	// on the process command line. AppDirs are its working directory and any
	// catalina.base/home. The command line itself is never kept: it can carry
	// passwords.
	ConfigRefs []string
	AppDirs    []string
}

// UIDKnown reports whether the owning uid was readable.
func (l Listener) UIDKnown() bool { return l.UID >= 0 }

// ListenerSweep is the result of one sweep. Hidden counts listeners whose
// owner the account could not see: sockets with no visible process plus
// processes whose uid was unreadable.
type ListenerSweep struct {
	Listeners []Listener
	Hidden    int
}

var (
	reSSProc    = regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)
	reNetstatPG = regexp.MustCompile(`^(\d+)/(.*)$`)
)

type listenSocket struct {
	port  int
	procs []sockProc
}

type sockProc struct {
	pid  int
	comm string
}

// Listeners sweeps the host's listening TCP sockets. priv is the executor the
// scan runs on (elevated when the scan is); plain, when set, is the
// unelevated one, used first for /proc reads because most of /proc is world
// readable and the helper allowlist cannot read it at all. With no privilege
// the sweep still returns the account's own listeners and counts the rest as
// hidden.
func Listeners(ctx context.Context, priv, plain agentinstall.Executor) (ListenerSweep, error) {
	if plain == nil {
		plain = priv
	}
	out, err := priv.Run(ctx, "ss", "-ltnp")
	socks, procInfo := parseListenOutput(string(out))
	if len(socks) == 0 {
		nout, nerr := priv.Run(ctx, "netstat", "-ltnp")
		if ns, _ := parseListenOutput(string(nout)); len(ns) > 0 {
			socks = ns
		} else if err != nil || nerr != nil {
			return ListenerSweep{}, errors.New("ss and netstat are unavailable or refused")
		}
	}

	var sweep ListenerSweep
	infos := map[int]*procFacts{}
	seen := map[[2]int]bool{}
	for _, s := range socks {
		if len(s.procs) == 0 {
			sweep.Listeners = append(sweep.Listeners, Listener{Port: s.port, UID: UnknownID, GID: UnknownID})
			continue
		}
		for _, p := range s.procs {
			if seen[[2]int{s.port, p.pid}] {
				continue
			}
			seen[[2]int{s.port, p.pid}] = true
			f, ok := infos[p.pid]
			if !ok {
				if len(infos) >= maxListenerPIDs {
					f = &procFacts{uid: UnknownID, gid: UnknownID}
				} else {
					h, ok := procInfo[p.pid]
					if !ok {
						h = procHelper{uid: UnknownID}
					}
					f = readProcFacts(ctx, priv, plain, p.pid, h)
				}
				infos[p.pid] = f
			}
			comm := f.comm
			if comm == "" {
				comm = p.comm
			}
			l := Listener{Port: s.port, PID: p.pid, UID: f.uid, GID: f.gid, Exe: f.exe, Comm: comm, Cwd: f.cwd,
				ConfigRefs: f.refs, AppDirs: f.appDirs}
			l.Tech = TechForProcess(l.Comm, l.Exe, f.cmd, l.ConfigRefs)
			sweep.Listeners = append(sweep.Listeners, l)
		}
	}

	users := map[int]string{}
	for i := range sweep.Listeners {
		l := &sweep.Listeners[i]
		if !l.UIDKnown() {
			sweep.Hidden++
			continue
		}
		u, ok := users[l.UID]
		if !ok {
			u = lookupUser(ctx, plain, l.UID)
			users[l.UID] = u
		}
		l.User = u
	}
	sort.SliceStable(sweep.Listeners, func(i, j int) bool {
		a, b := sweep.Listeners[i], sweep.Listeners[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.PID < b.PID
	})
	return sweep, nil
}

type procHelper struct {
	uid int
	exe string
}

// parseListenOutput reads ss -ltnp, netstat -ltnp and the privilege helper's
// "proc pid= uid= exe=" trailer, in any mix: the helper prints ss output
// followed by trailer lines.
func parseListenOutput(out string) ([]listenSocket, map[int]procHelper) {
	var socks []listenSocket
	helper := map[int]procHelper{}
	byPort := map[int]int{}
	add := func(port int, procs []sockProc) {
		if i, ok := byPort[port]; ok {
			socks[i].procs = append(socks[i].procs, procs...)
			return
		}
		byPort[port] = len(socks)
		socks = append(socks, listenSocket{port: port, procs: procs})
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "proc":
			pid, h := parseHelperProc(f[1:])
			if pid > 0 {
				helper[pid] = h
			}
		case f[0] == "LISTEN" && len(f) >= 5:
			port := portOf(f[3])
			if port == 0 {
				continue
			}
			var procs []sockProc
			for _, m := range reSSProc.FindAllStringSubmatch(line, -1) {
				pid, _ := strconv.Atoi(m[2])
				procs = append(procs, sockProc{pid: pid, comm: m[1]})
			}
			add(port, procs)
		case strings.HasPrefix(f[0], "tcp") && len(f) >= 6 && f[5] == "LISTEN":
			port := portOf(f[3])
			if port == 0 {
				continue
			}
			var procs []sockProc
			if len(f) >= 7 {
				if m := reNetstatPG.FindStringSubmatch(f[6]); m != nil {
					pid, _ := strconv.Atoi(m[1])
					procs = append(procs, sockProc{pid: pid, comm: m[2]})
				}
			}
			add(port, procs)
		}
	}
	return socks, helper
}

func parseHelperProc(fields []string) (int, procHelper) {
	h := procHelper{uid: UnknownID}
	pid := 0
	for _, kv := range fields {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "pid":
			pid, _ = strconv.Atoi(v)
		case "uid":
			if n, err := strconv.Atoi(v); err == nil {
				h.uid = n
			}
		case "exe":
			h.exe = v
		}
	}
	return pid, h
}

// portOf takes the port after the last colon, which holds for 0.0.0.0:443,
// *:443, [::]:443 and 127.0.0.53%lo:53 alike.
func portOf(local string) int {
	i := strings.LastIndex(local, ":")
	if i < 0 {
		return 0
	}
	p, err := strconv.Atoi(local[i+1:])
	if err != nil || p <= 0 || p > 65535 {
		return 0
	}
	return p
}

type procFacts struct {
	uid, gid       int
	comm, exe, cwd string
	cmd            string
	refs, appDirs  []string
}

// readProcFacts gathers one pid's identity. A read that fails leaves the
// field unknown rather than failing the sweep.
func readProcFacts(ctx context.Context, priv, plain agentinstall.Executor, pid int, helper procHelper) *procFacts {
	f := &procFacts{uid: UnknownID, gid: UnknownID}
	base := "/proc/" + strconv.Itoa(pid)
	if helper.exe != "" || helper.uid >= 0 {
		f.uid, f.exe = helper.uid, helper.exe
	}
	if f.uid < 0 {
		if raw, ok := readEither(plain, priv, base+"/status"); ok {
			f.uid, f.gid, f.comm = parseProcStatus(string(raw))
		}
	}
	if f.exe == "" {
		f.exe = readlinkEither(ctx, plain, priv, base+"/exe")
	}
	f.cwd = readlinkEither(ctx, plain, priv, base+"/cwd")
	if raw, ok := readEither(plain, priv, base+"/cmdline"); ok {
		args := splitCmdline(raw)
		f.cmd = strings.Join(args, " ")
		f.refs, f.appDirs = processReferences(args)
	}
	if f.cwd != "" {
		f.appDirs = appendUnique(f.appDirs, f.cwd)
	}
	return f
}

func readEither(first, second agentinstall.Executor, p string) ([]byte, bool) {
	if b, err := first.ReadFile(p); err == nil {
		return b, true
	}
	if second != nil {
		if b, err := second.ReadFile(p); err == nil {
			return b, true
		}
	}
	return nil, false
}

func readlinkEither(ctx context.Context, first, second agentinstall.Executor, p string) string {
	for _, e := range []agentinstall.Executor{first, second} {
		if e == nil {
			continue
		}
		if out, err := e.Run(ctx, "readlink", p); err == nil {
			if s := strings.TrimSpace(string(out)); strings.HasPrefix(s, "/") {
				return strings.TrimSuffix(s, " (deleted)")
			}
		}
	}
	return ""
}

// parseProcStatus returns the real uid and gid (first field, matching the
// helper's awk) and the process name.
func parseProcStatus(s string) (uid, gid int, comm string) {
	uid, gid = UnknownID, UnknownID
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		switch k {
		case "Name":
			comm = strings.TrimSpace(v)
		case "Uid":
			if len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil {
					uid = n
				}
			}
		case "Gid":
			if len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil {
					gid = n
				}
			}
		}
	}
	return uid, gid, comm
}

func splitCmdline(raw []byte) []string {
	var args []string
	for _, a := range strings.Split(string(raw), "\x00") {
		if a != "" {
			args = append(args, a)
		}
	}
	return args
}

var refExts = map[string]bool{
	".jks": true, ".p12": true, ".pfx": true, ".pem": true, ".crt": true, ".cer": true,
	".key": true, ".keystore": true, ".truststore": true,
}

// processReferences extracts absolute keystore/cert/server.xml paths and the
// catalina base/home directories from a command line. Every other token is
// dropped, so a -D...Password=... argument never leaves this function.
func processReferences(args []string) (refs, dirs []string) {
	addRef := func(p string) {
		if !strings.HasPrefix(p, "/") {
			return
		}
		if refExts[strings.ToLower(path.Ext(p))] || path.Base(p) == "server.xml" {
			refs = appendUnique(refs, p)
		}
	}
	for _, a := range args {
		a = strings.TrimPrefix(a, "-D")
		k, v, hasV := strings.Cut(a, "=")
		if hasV {
			switch k {
			case "catalina.base", "catalina.home":
				if strings.HasPrefix(v, "/") {
					dirs = appendUnique(dirs, path.Clean(v))
				}
				continue
			}
			a = v
		}
		addRef(a)
	}
	return refs, dirs
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func lookupUser(ctx context.Context, e agentinstall.Executor, uid int) string {
	out, err := e.Run(ctx, "id", "-nu", strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	u := strings.TrimSpace(string(out))
	if strings.ContainsAny(u, " \t\n:") {
		return ""
	}
	return u
}

// processRule maps a process to a technology. comm matches the process name
// (or the exe basename when the name is unreadable); the optional exe and
// cmd substrings disambiguate generic names such as "master" and "java".
type processRule struct {
	comm []string
	exe  string
	cmd  string
	tech string
}

// processRules is data, not code: add a row to teach the sweep a new process.
// First match wins. The java rows precede nothing generic on purpose: a plain
// java process stays unclassified rather than being guessed as Tomcat.
var processRules = []processRule{
	{comm: []string{"java"}, cmd: "catalina", tech: "tomcat"},
	{comm: []string{"java"}, cmd: "tomcat", tech: "tomcat"},
	{comm: []string{"java"}, cmd: "server.xml", tech: "tomcat"},
	{comm: []string{"java"}, cmd: ".jks", tech: "tomcat"},
	{comm: []string{"java"}, cmd: "jetty", tech: "jetty"},
	{comm: []string{"java"}, cmd: "wildfly", tech: "wildfly"},
	{comm: []string{"java"}, cmd: "jboss", tech: "wildfly"},
	{comm: []string{"java"}, cmd: "weblogic", tech: "weblogic"},
	{comm: []string{"java"}, cmd: "websphere", tech: "websphere"},
	{comm: []string{"httpd", "apache2"}, tech: "apache"},
	{comm: []string{"nginx"}, tech: "nginx"},
	{comm: []string{"haproxy"}, tech: "haproxy"},
	{comm: []string{"slapd"}, tech: "ldap-openldap"},
	{comm: []string{"sqlservr"}, tech: "mssql"},
	{comm: []string{"master"}, exe: "postfix", tech: "postfix"},
	{comm: []string{"master"}, cmd: "postfix", tech: "postfix"},
	{comm: []string{"dovecot"}, tech: "dovecot"},
	{comm: []string{"mysqld", "mariadbd"}, tech: "mysql"},
	{comm: []string{"postgres", "postmaster"}, tech: "postgres"},
	{comm: []string{"redis-server"}, tech: "redis"},
	{comm: []string{"mongod"}, tech: "mongodb"},
	{comm: []string{"node", "nodejs"}, tech: "node"},
	{comm: []string{"dotnet"}, tech: "kestrel"},
	{comm: []string{"envoy"}, tech: "envoy"},
	{comm: []string{"caddy"}, tech: "caddy"},
	{comm: []string{"traefik"}, tech: "traefik"},
	{comm: []string{"vault"}, tech: "vault"},
	{comm: []string{"consul"}, tech: "consul"},
	{comm: []string{"etcd"}, tech: "etcd"},
	{comm: []string{"kube-apiserver"}, tech: "kubernetes-api"},
}

// TechForProcess returns the technology a process implies, or "". refs are the
// keystore paths on its command line; a .jks among them counts like the
// substring in cmd, for callers that did not keep the command line.
func TechForProcess(comm, exe, cmd string, refs []string) string {
	name := comm
	if name == "" {
		name = path.Base(exe)
	}
	if name == "" || name == "." || name == "/" {
		return ""
	}
	cmdl := strings.ToLower(cmd)
	for _, r := range refs {
		cmdl += " " + strings.ToLower(r)
	}
	exel := strings.ToLower(exe)
	for _, r := range processRules {
		match := false
		for _, c := range r.comm {
			if name == c {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if r.exe != "" && !strings.Contains(exel, r.exe) {
			continue
		}
		if r.cmd != "" && !strings.Contains(cmdl, r.cmd) {
			continue
		}
		return r.tech
	}
	return ""
}
