// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"kryptkeeper/internal/agentinstall"
)

// W34-08: install posture. Who owns each certificate, key and keystore, and
// which service uses it, so an install done "the wrong way" (a root-owned JKS
// behind a non-root Tomcat) is surfaced instead of failing at renewal time.
// Key files are stat-ed by path only: their content is never read here.

// File kinds, matching discovered_files.kind.
const (
	FileKindPEM    = "pem"
	FileKindJKS    = "jks"
	FileKindP12    = "p12"
	FileKindKey    = "key"
	FileKindConfig = "config"
)

// Postures, matching discovered_files.posture.
const (
	PostureStandard    = "standard"
	PosturePrivileged  = "privileged"
	PostureRootService = "root_service"
	PostureUnknown     = "unknown"
)

// Finding codes. None is a substring of another flag or finding code: the
// risk SQL matches by LIKE.
const (
	FindingPrivilegedInstallPath = "PRIVILEGED_INSTALL_PATH"
	FindingServiceRunsAsRoot     = "SERVICE_RUNS_AS_ROOT"
	FindingKeyWorldReadable      = "KEY_WORLD_READABLE"
	FindingHomeDirKeystore       = "HOME_DIR_KEYSTORE"
)

const (
	maxStatFiles   = 1000
	statBatchSize  = 50
	maxConfigFiles = 60
	maxConfigBytes = 256 << 10
	maxExtraRoots  = 10
)

// FileFact is one certificate, key or keystore file on the host.
type FileFact struct {
	Path string
	Kind string
	// UID/GID are UnknownID when the stat output carried names only (helper
	// mode) or the file could not be stat-ed.
	UID, GID     int
	Mode         string // octal permission bits as printed by stat %a
	Owner, Group string
	Statted      bool
	// CertFingerprints are the certificates parsed out of this file, before
	// cross-file de-duplication, so one cert in two files links to both.
	CertFingerprints []string
	ServiceTech      string
	ServiceName      string
	ServiceUID       int
	Posture          string
	// Findings are "CODE: detail" strings.
	Findings []string
}

// IsKey reports whether the file holds private key material.
func (f FileFact) IsKey() bool { return f.Kind == FileKindKey }

type foundFile struct {
	path  string
	kind  string
	certs []string
}

func kindOfFile(file string, hadKey bool) string {
	switch {
	case hadKey || looksLikeKeyFile(file):
		return FileKindKey
	case keystoreKind(file) == "jks":
		return FileKindJKS
	case keystoreKind(file) == "p12":
		return FileKindP12
	}
	return FileKindPEM
}

// statFiles stats every path with `stat -L -c '%u %g %a %U %G %n'`, batched so
// a CA store of hundreds of files costs a handful of sessions. The unelevated
// executor goes first: stat needs directory search permission, not file read
// permission, so it usually works on a root-only 0600 key. Paths it could not
// stat are retried one by one through the scan executor, which in helper mode
// speaks the helper's own stat format.
func statFiles(ctx context.Context, priv, plain agentinstall.Executor, paths []string) map[string]FileFact {
	out := map[string]FileFact{}
	if plain == nil {
		plain = priv
	}
	for start := 0; start < len(paths); start += statBatchSize {
		batch := paths[start:min(start+statBatchSize, len(paths))]
		args := append([]string{"-L", "-c", "%u %g %a %U %G %n", "--"}, batch...)
		// stat exits non-zero when any path is missing but still prints the rest.
		raw, _ := plain.Run(ctx, "stat", args...)
		for _, line := range strings.Split(string(raw), "\n") {
			if f, ok := parseStatLine(line); ok {
				out[f.Path] = f
			}
		}
	}
	for _, p := range paths {
		if _, ok := out[p]; ok {
			continue
		}
		raw, err := priv.Run(ctx, "stat", "-L", "-c", "%u %g %a %U %G %n", "--", p)
		if err != nil && len(raw) == 0 {
			raw, err = priv.Run(ctx, "stat", p) // helper verb
		}
		if err != nil && len(raw) == 0 {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if f, ok := parseStatLine(line); ok {
				f.Path = p
				out[p] = f
				break
			}
			if f, ok := parseHelperStat(line); ok {
				f.Path = p
				out[p] = f
				break
			}
		}
	}
	return out
}

// parseStatLine reads "%u %g %a %U %G %n". The path is last because it may
// hold spaces.
func parseStatLine(line string) (FileFact, bool) {
	f := strings.SplitN(strings.TrimSpace(line), " ", 6)
	if len(f) != 6 || !strings.HasPrefix(f[5], "/") {
		return FileFact{}, false
	}
	uid, err1 := strconv.Atoi(f[0])
	gid, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || !isOctal(f[2]) {
		return FileFact{}, false
	}
	return FileFact{Path: f[5], UID: uid, GID: gid, Mode: f[2], Owner: f[3], Group: f[4], Statted: true}, true
}

// parseHelperStat reads the helper's "%F|%a|%U|%G|%s|%n": names, no numeric ids.
func parseHelperStat(line string) (FileFact, bool) {
	f := strings.Split(strings.TrimSpace(line), "|")
	if len(f) != 6 || !isOctal(f[1]) {
		return FileFact{}, false
	}
	uid, gid := UnknownID, UnknownID
	if f[2] == "root" {
		uid = 0
	}
	if f[3] == "root" {
		gid = 0
	}
	return FileFact{Path: f[5], UID: uid, GID: gid, Mode: f[1], Owner: f[2], Group: f[3], Statted: true}, true
}

func isOctal(s string) bool {
	if s == "" || len(s) > 4 {
		return false
	}
	_, err := strconv.ParseUint(s, 8, 16)
	return err == nil
}

func modeBits(mode string) uint32 {
	n, err := strconv.ParseUint(mode, 8, 16)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// service is the process family a file is attributed to.
type service struct {
	tech, name string
	// writerUID is the uid whose write access decides whether the service can
	// replace the file itself; UnknownID when it cannot be told.
	writerUID, writerGID int
	rootService          bool
}

// masterStyle techs start as root to bind a port and serve from unprivileged
// workers: uid 0 on the master is by design, so they are judged by the workers.
var masterStyle = map[string]bool{"nginx": true, "apache": true, "haproxy": true, "postfix": true}

// serviceFor derives the effective identity of a technology from every
// listener of that tech.
func serviceFor(tech string, ls []Listener) service {
	s := service{tech: tech, writerUID: UnknownID, writerGID: UnknownID}
	var uids []int
	for _, l := range ls {
		if l.Tech != tech {
			continue
		}
		if s.name == "" {
			s.name = l.Comm
		}
		if l.UIDKnown() {
			uids = append(uids, l.UID)
			if s.writerUID == UnknownID || (l.UID != 0 && s.writerUID == 0) {
				s.writerUID, s.writerGID = l.UID, l.GID
			}
		}
	}
	if len(uids) == 0 {
		return s
	}
	allRoot := true
	for _, u := range uids {
		if u != 0 {
			allRoot = false
		}
	}
	if masterStyle[tech] {
		// A root master can always replace the file; only an all-root process
		// family (workers included) is a root service. One pid alone is a master
		// whose workers we cannot see, which proves nothing.
		if allRoot && len(uids) > 1 {
			s.rootService = true
		}
		hasRoot := false
		for _, u := range uids {
			if u == 0 {
				hasRoot = true
			}
		}
		if hasRoot {
			s.writerUID, s.writerGID = 0, 0
		}
		return s
	}
	s.rootService = allRoot
	return s
}

// classifyFile fills posture and findings for one file. svc is nil when no
// service was tied to it.
func classifyFile(f *FileFact, svc *service) {
	f.Findings = nil
	if !f.Statted {
		f.Posture = PostureUnknown
		return
	}
	bits := modeBits(f.Mode)
	if f.IsKey() && (bits&0o004 != 0 || (bits&0o040 != 0 && f.GID != 0)) {
		f.Findings = append(f.Findings, fmt.Sprintf("%s: path=%s mode=%s", FindingKeyWorldReadable, f.Path, f.Mode))
	}
	f.Posture = PostureStandard
	if svc == nil {
		return
	}
	f.ServiceTech, f.ServiceName, f.ServiceUID = svc.tech, svc.name, svc.writerUID
	if svc.rootService {
		f.Posture = PostureRootService
		f.Findings = append(f.Findings, fmt.Sprintf("%s: path=%s service=%s uid=0", FindingServiceRunsAsRoot, f.Path, svc.name))
	}
	if strings.HasPrefix(f.Path, "/root/") || strings.HasPrefix(f.Path, "/home/") {
		if f.Posture == PostureStandard {
			f.Posture = PosturePrivileged
		}
		f.Findings = append(f.Findings, fmt.Sprintf("%s: path=%s service=%s", FindingHomeDirKeystore, f.Path, svc.name))
	}
	if svc.writerUID == UnknownID || svc.writerUID == 0 || svc.rootService {
		return
	}
	canWrite := f.UID == svc.writerUID ||
		(f.GID >= 0 && f.GID == svc.writerGID && bits&0o020 != 0) ||
		bits&0o002 != 0
	if !canWrite {
		if f.Posture == PostureStandard {
			f.Posture = PosturePrivileged
		}
		f.Findings = append(f.Findings, fmt.Sprintf("%s: path=%s owner=%s service=%s service_uid=%d",
			FindingPrivilegedInstallPath, f.Path, f.Owner, svc.name, svc.writerUID))
	}
}

var (
	reServerXMLRef = regexp.MustCompile(`(?:keystoreFile|certificateKeystoreFile|certificateFile|certificateKeyFile|SSLCertificateFile|SSLCertificateKeyFile)\s*=\s*"([^"]+)"`)
)

// refsFromConfigText returns the absolute certificate and key paths a
// web-server configuration names.
func refsFromConfigText(text string) []string {
	var out []string
	add := func(p string) {
		p = strings.Trim(p, `"'`)
		if strings.HasPrefix(p, "/") {
			out = appendUnique(out, path.Clean(p))
		}
	}
	for _, line := range strings.Split(text, "\n") {
		for _, re := range []*regexp.Regexp{reNginxCert, reNginxKey, reApacheCert, reApacheKey, reHAProxyCert} {
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				add(m[1])
			}
		}
	}
	return out
}

// refsFromServerXML resolves the keystore and certificate attributes of a
// Tomcat server.xml against its catalina base.
func refsFromServerXML(text, base string) []string {
	var out []string
	for _, m := range reServerXMLRef.FindAllStringSubmatch(text, -1) {
		p := m[1]
		if !strings.HasPrefix(p, "/") {
			p = path.Join(base, p)
		}
		out = appendUnique(out, path.Clean(p))
	}
	return out
}

var webConfigRoots = map[string][]string{
	"nginx":   {"/etc/nginx"},
	"apache":  {"/etc/apache2", "/etc/httpd"},
	"haproxy": {"/etc/haproxy"},
}

// configRefs maps each file path a service's configuration names to that
// service's technology. Configuration is read through the unelevated
// executor: it is rarely secret and the helper cannot list *.conf.
func configRefs(ctx context.Context, plain agentinstall.Executor, ls []Listener) map[string]string {
	refs := map[string]string{}
	techs := map[string]bool{}
	for _, l := range ls {
		techs[l.Tech] = true
		if l.Tech != "tomcat" {
			continue
		}
		for _, dir := range l.AppDirs {
			if b, err := plain.ReadFile(path.Join(dir, "conf", "server.xml")); err == nil {
				for _, p := range refsFromServerXML(string(b), dir) {
					refs[p] = "tomcat"
				}
			}
		}
	}
	for tech, roots := range webConfigRoots {
		if !techs[tech] {
			continue
		}
		read := 0
		for _, root := range roots {
			out, _ := plain.Run(ctx, "find", root, "-maxdepth", "3", "-type", "f", "(", "-name", "*.conf", "-o", "-name", "*.cfg", ")")
			for _, line := range strings.Split(string(out), "\n") {
				file := strings.TrimSpace(line)
				if !strings.HasPrefix(file, "/") || read >= maxConfigFiles {
					continue
				}
				read++
				b, err := plain.ReadFile(file)
				if err != nil || len(b) > maxConfigBytes {
					continue
				}
				for _, p := range refsFromConfigText(string(b)) {
					refs[p] = tech
				}
			}
		}
	}
	return refs
}

// attributeFiles ties each file to a service and classifies it: first by the
// exact path in a process argument or configuration, then by living under the
// process's application directory (catalina.base, cwd). A longest-prefix rule
// keeps "/" and shallow cwd values from claiming the filesystem.
func attributeFiles(files []FileFact, ls []Listener, cfg map[string]string) {
	svcByTech := map[string]*service{}
	svc := func(tech string) *service {
		if s, ok := svcByTech[tech]; ok {
			return s
		}
		s := serviceFor(tech, ls)
		svcByTech[tech] = &s
		return &s
	}
	for i := range files {
		f := &files[i]
		tech := cfg[f.Path]
		if tech == "" {
			tech = techByRef(f.Path, ls)
		}
		var s *service
		if tech != "" {
			s = svc(tech)
		}
		classifyFile(f, s)
	}
}

func techByRef(p string, ls []Listener) string {
	best, bestLen := "", 0
	for _, l := range ls {
		if l.Tech == "" {
			continue
		}
		for _, r := range l.ConfigRefs {
			if r == p {
				return l.Tech
			}
		}
		for _, d := range l.AppDirs {
			if len(d) > 1 && strings.Count(d, "/") >= 2 && strings.HasPrefix(p, d+"/") && len(d) > bestLen {
				best, bestLen = l.Tech, len(d)
			}
		}
	}
	return best
}

// extraScanRoots are directories named by running processes (keystore
// locations, catalina conf) that the default roots would miss.
func extraScanRoots(ls []Listener, have []string) []string {
	var out []string
	add := func(dir string) {
		if dir == "" || dir == "/" || !strings.HasPrefix(dir, "/") || len(out) >= maxExtraRoots {
			return
		}
		for _, h := range append(append([]string{}, have...), out...) {
			if dir == h || strings.HasPrefix(dir, strings.TrimSuffix(h, "/")+"/") {
				return
			}
		}
		out = append(out, dir)
	}
	for _, l := range ls {
		for _, r := range l.ConfigRefs {
			add(path.Dir(r))
		}
		if l.Tech == "tomcat" {
			for _, d := range l.AppDirs {
				if len(d) > 1 && strings.Count(d, "/") >= 2 {
					add(path.Join(d, "conf"))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// ClassifyHostFiles attributes files to services and sets posture and findings,
// from facts gathered elsewhere (an agent's inventory push). cfg maps a path a
// service's configuration names to its technology.
func ClassifyHostFiles(files []FileFact, listeners []Listener, cfg map[string]string) {
	attributeFiles(files, listeners, cfg)
}
