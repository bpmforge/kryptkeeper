// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package privexec

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	sudoersUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// Anything outside this set could end a sudoers token or add a second rule.
	sudoersPathRE = regexp.MustCompile(`^/[A-Za-z0-9._/+@-]*$`)
)

// serverCommands is the config-test and reload command set per install
// server type; the helper has the same table built in.
var serverCommands = map[string][]string{
	"nginx":   {"/usr/sbin/nginx -t", "/usr/bin/systemctl reload nginx"},
	"apache":  {"/usr/sbin/apachectl configtest", "/usr/bin/apachectl configtest", "/usr/bin/systemctl reload apache2", "/usr/bin/systemctl reload httpd"},
	"haproxy": {"/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg", "/usr/bin/systemctl reload haproxy"},
	"tomcat":  {"/opt/tomcat/bin/catalina.sh configtest", "/usr/bin/systemctl restart tomcat"},
}

// defaultSudoersDirs are searched when the caller names none.
var defaultSudoersDirs = []string{"/etc/ssl", "/etc/pki", "/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/haproxy", "/opt/tomcat/conf"}

// Sudoers renders the sudoers drop-in for user in the given mode. paths are
// certificate or key file paths (or directories) the raw allowlist should
// cover; their parent directories are used. An empty serverType covers nginx
// and apache, matching the agent's historical drop-in.
func Sudoers(user string, mode Mode, serverType string, paths []string) (string, error) {
	if !sudoersUserRE.MatchString(user) {
		return "", fmt.Errorf("privexec: invalid sudoers user %q", user)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Kryptkeeper privilege for %s (mode %s)\n", user, mode)
	file := user
	if !strings.HasPrefix(user, "kryptkeeper") {
		file = "kryptkeeper-" + user
	}
	fmt.Fprintf(&b, "# Install as /etc/sudoers.d/%s, chmod 0440, then: visudo -cf <file>\n", file)
	switch mode {
	case ModeHelper:
		fmt.Fprintf(&b, "# One rule: the account may run only the hash-pinned helper as root.\n")
		fmt.Fprintf(&b, "Defaults:%s !requiretty\n", user)
		fmt.Fprintf(&b, "%s ALL=(root) NOPASSWD: %s\n", user, DefaultHelperPath)
	case ModePassword:
		fmt.Fprintf(&b, "# The account must already be allowed to use sudo (for example the sudo or wheel group).\n")
		fmt.Fprintf(&b, "# The password arrives on stdin, which sudo cannot read without a tty unless requiretty is off.\n")
		fmt.Fprintf(&b, "Defaults:%s !requiretty\n", user)
	case ModeNoPasswd:
		if err := writeRawAllowlist(&b, user, serverType, paths); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("privexec: no sudoers for mode %q", mode)
	}
	return b.String(), nil
}

func writeRawAllowlist(b *strings.Builder, user, serverType string, paths []string) error {
	var cmds []string
	switch serverType {
	case "":
		cmds = append(append(cmds, serverCommands["nginx"]...), serverCommands["apache"]...)
	default:
		c, ok := serverCommands[serverType]
		if !ok {
			return fmt.Errorf("privexec: unknown server type %q", serverType)
		}
		cmds = c
	}
	dirs, err := allowlistDirs(paths)
	if err != nil {
		return err
	}
	// Arguments are matched with fnmatch(3) without FNM_PATHNAME, so '*' also
	// matches '/' and '..' segments: these globs are not a path boundary.
	b.WriteString("# WARNING: cat/find/install on globbed paths is effectively root read/write of the\n")
	b.WriteString("# filesystem for anyone holding this account's SSH key ('*' in an argument also matches '/').\n")
	b.WriteString("# Prefer helper mode unless policy forbids installing the helper.\n")
	fmt.Fprintf(b, "Defaults:%s !requiretty\n", user)
	join := func(tmpl string) string {
		out := make([]string, 0, len(dirs)*2)
		for _, d := range dirs {
			out = append(out, fmt.Sprintf(tmpl, d))
		}
		return strings.Join(out, ", ")
	}
	fmt.Fprintf(b, "Cmnd_Alias KK_LIST    = %s\n", join("/usr/bin/find %s *"))
	fmt.Fprintf(b, "Cmnd_Alias KK_STAT    = %s\n", join("/usr/bin/stat -c * %s/*"))
	fmt.Fprintf(b, "Cmnd_Alias KK_READ    = %s\n", join("/usr/bin/cat %s/*"))
	fmt.Fprintf(b, "Cmnd_Alias KK_INSTALL = %s\n", join("/usr/bin/install -m * %s/*"))
	fmt.Fprintf(b, "Cmnd_Alias KK_LISTEN  = /usr/bin/ss -ltnp, /usr/sbin/ss -ltnp\n")
	fmt.Fprintf(b, "Cmnd_Alias KK_SERVER  = %s\n", strings.Join(cmds, ", "))
	fmt.Fprintf(b, "%s ALL=(root) NOPASSWD: KK_LIST, KK_STAT, KK_READ, KK_INSTALL, KK_LISTEN, KK_SERVER\n", user)
	return nil
}

// allowlistDirs maps file or directory paths to the distinct directories the
// raw allowlist covers. Paths with a dot in the last element are treated as
// files.
func allowlistDirs(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return append([]string(nil), defaultSudoersDirs...), nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if !sudoersPathRE.MatchString(p) || strings.Contains(p, "..") {
			return nil, fmt.Errorf("privexec: path %q is not usable in a sudoers rule", p)
		}
		d := path.Clean(p)
		if strings.Contains(path.Base(d), ".") {
			d = path.Dir(d)
		}
		if d == "/" {
			return nil, fmt.Errorf("privexec: refusing to allow the filesystem root")
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out, nil
}
