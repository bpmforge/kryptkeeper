// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"path"
	"regexp"
	"strings"
)

// Without the elevated_exec grant a plugin may run concrete programs with an
// argv, nothing that escalates privilege and nothing that re-parses a command
// string (a shell or interpreter with an inline command can launch anything,
// including sudo). A plugin that needs a shell declares elevated_exec so the
// operator sees and approves it (OWASP-A08-001).

// escalationTools change identity or namespace, so they are elevated by nature.
var escalationTools = map[string]bool{
	"sudo": true, "sudoedit": true, "doas": true, "su": true, "pkexec": true,
	"runuser": true, "setpriv": true, "chroot": true, "nsenter": true,
}

// wrapperTools run another program given in their arguments.
var wrapperTools = map[string]bool{
	"env": true, "busybox": true, "nice": true, "nohup": true, "timeout": true,
	"setsid": true, "stdbuf": true, "ionice": true, "time": true, "command": true,
	"exec": true, "xargs": true, "flock": true, "watch": true, "chrt": true,
}

// inlineFlag matches a short-flag cluster (-c, -lc, -ec) containing one of
// the given letters.
func inlineFlag(letters string) *regexp.Regexp {
	return regexp.MustCompile(`^-[A-Za-z]*[` + letters + `][A-Za-z]*$`)
}

var (
	shellNames   = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "fish": true, "csh": true, "tcsh": true, "mksh": true}
	shellInline  = inlineFlag("c")
	pythonName   = regexp.MustCompile(`^python[0-9.]*$`)
	pythonInline = inlineFlag("c")
	perlRuby     = regexp.MustCompile(`^(perl[0-9.]*|ruby[0-9.]*)$`)
	perlInline   = inlineFlag("eE")
	nodeName     = regexp.MustCompile(`^(node|nodejs|deno|bun)$`)
	nodeInline   = inlineFlag("ep")
	phpInline    = inlineFlag("r")
	luaInline    = inlineFlag("e")
)

// programName is the lowercase basename of a program, handling / and \
// separators and a .exe suffix, so /usr/bin/sudo and C:\x\sudo.exe match.
func programName(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	return strings.TrimSuffix(strings.ToLower(path.Base(p)), ".exe")
}

// elevationReason returns why argv needs elevated_exec, or "" when it does
// not. It is a deny-list of well-known escalation and inline-command forms:
// it narrows what a plugin without elevated_exec can do, it does not sandbox
// a plugin that has remote_exec (remote_exec is itself a High capability).
func elevationReason(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	name := programName(argv[0])
	args := argv[1:]
	switch {
	case escalationTools[name]:
		return name + " escalates privilege"
	case wrapperTools[name]:
		for i := range args {
			// env -S "sudo x" packs a whole command into one argument.
			for _, sub := range strings.Fields(args[i]) {
				if escalationTools[programName(sub)] {
					return name + " launching " + programName(sub)
				}
			}
			if r := elevationReason(args[i:]); r != "" {
				return name + " launching a command that " + r
			}
		}
	case hasInline(name, args):
		return name + " with an inline command"
	}
	return ""
}

func hasInline(name string, args []string) bool {
	for _, a := range args {
		la := strings.ToLower(a)
		switch {
		case shellNames[name] && shellInline.MatchString(a):
			return true
		case name == "cmd" && (la == "/c" || la == "/k" || la == "/r"):
			return true
		case (name == "powershell" || name == "pwsh") &&
			(la == "-c" || la == "-e" || la == "-ec" || strings.HasPrefix(la, "-comm") || strings.HasPrefix(la, "-enc")):
			return true
		case pythonName.MatchString(name) && pythonInline.MatchString(a):
			return true
		case perlRuby.MatchString(name) && perlInline.MatchString(a):
			return true
		case nodeName.MatchString(name) && (a == "--eval" || a == "--print" || nodeInline.MatchString(a)):
			return true
		case name == "php" && phpInline.MatchString(a):
			return true
		case name == "lua" && luaInline.MatchString(a):
			return true
		}
	}
	return false
}
