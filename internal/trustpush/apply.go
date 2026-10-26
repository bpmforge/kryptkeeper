// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package trustpush

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Outcomes an agent reports per bundle (D-319).
const (
	OutcomeApplied    = "applied"
	OutcomeRefused    = "refused_not_opted_in"
	OutcomeFailed     = "failed"
	maxDetailBytes    = 1000
	linuxDebianDir    = "/usr/local/share/ca-certificates"
	linuxRHELDir      = "/etc/pki/ca-trust/source/anchors"
	macSystemKeychain = "/Library/Keychains/System.keychain"
	// HelperPath is the one binary the sudoers rule names. It must be owned by
	// root and not writable by the agent account (docs/ops/TRUST_STORE_PUSH.md).
	HelperPath = "/usr/local/bin/kryptkeeper-agent"
	// HelperArg is the exact argument the sudoers rule allows; sudoers matches
	// arguments literally when no wildcard is written.
	HelperArg = "--trust-store-apply"
)

// Request is one bundle application, and the JSON the unprivileged agent
// hands the root helper on stdin.
type Request struct {
	Action  Action `json:"action"`
	CertPEM string `json:"cert_pem"`
}

// Result is the per-host outcome of one Request.
type Result struct {
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// Runner executes a command, optionally feeding stdin, and returns combined
// output. It is the seam tests replace to assert the exact commands.
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// Applier performs the privileged half on this host. All fields except Runner
// have defaults; Root and TempDir exist so tests can run against a scratch
// directory while the commands stay the real ones.
type Applier struct {
	GOOS      string
	Root      string // prefix for the Linux anchor directories and /etc/os-release
	StatePath string
	TempDir   string
	Runner    Runner
	Now       func() time.Time
}

func (a *Applier) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Applier) tmp() string {
	if a.TempDir != "" {
		return a.TempDir
	}
	return os.TempDir()
}

func failed(format string, args ...any) Result {
	d := fmt.Sprintf(format, args...)
	if len(d) > maxDetailBytes {
		d = d[:maxDetailBytes]
	}
	return Result{Outcome: OutcomeFailed, Detail: d}
}

// ApplyLocal adds or removes the bundle's certificates on this host. It only
// ever removes certificates recorded in the state file as added by it.
func (a *Applier) ApplyLocal(ctx context.Context, req Request) Result {
	if !req.Action.Valid() {
		return failed("unknown action %q", req.Action)
	}
	cas, err := ParseCAs(req.CertPEM, a.now(), req.Action == ActionAdd)
	if err != nil {
		return failed("bundle refused: %v", err)
	}
	st, err := loadState(a.StatePath)
	if err != nil {
		return failed("trust state unreadable: %v", err)
	}
	var res Result
	switch a.GOOS {
	case "linux":
		res = a.applyLinux(ctx, req.Action, cas, st)
	case "windows":
		res = a.applyWindows(ctx, req.Action, cas, st)
	case "darwin":
		res = a.applyDarwin(ctx, req.Action, cas, st)
	default:
		return failed("trust store push is not supported on %s", a.GOOS)
	}
	if res.Outcome == OutcomeApplied {
		if err := st.save(a.StatePath); err != nil {
			return failed("applied but the trust state could not be saved: %v", err)
		}
	}
	return res
}

// Dispatch is what the unprivileged agent calls. Windows services already run
// privileged, so they apply directly; Linux and macOS go through the single
// sudoers-allowed helper invocation.
func (a *Applier) Dispatch(ctx context.Context, req Request) Result {
	if a.GOOS == "windows" {
		return a.ApplyLocal(ctx, req)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return failed("encode request: %v", err)
	}
	out, err := a.Runner.Run(ctx, body, "sudo", "-n", HelperPath, HelperArg)
	var res Result
	if jerr := json.Unmarshal(bytes.TrimSpace(out), &res); jerr == nil && res.Outcome != "" {
		return res
	}
	if err != nil {
		return failed("privileged helper failed: %v", err)
	}
	return failed("privileged helper returned no result")
}

func (a *Applier) run(ctx context.Context, name string, args ...string) error {
	out, err := a.Runner.Run(ctx, nil, name, args...)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return nil
}

// --- Linux ---------------------------------------------------------------

// linuxFamily reads ID and ID_LIKE from os-release (systemd os-release(5)).
func (a *Applier) linuxFamily() (dir string, update []string, err error) {
	raw, rerr := os.ReadFile(filepath.Join(a.Root, "/etc/os-release"))
	if rerr != nil {
		return "", nil, fmt.Errorf("cannot detect the distribution: %w", rerr)
	}
	ids := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (k != "ID" && k != "ID_LIKE") {
			continue
		}
		for _, f := range strings.Fields(strings.Trim(v, `"'`)) {
			ids[strings.ToLower(f)] = true
		}
	}
	switch {
	case ids["debian"] || ids["ubuntu"]:
		return linuxDebianDir, []string{"/usr/sbin/update-ca-certificates"}, nil
	case ids["rhel"] || ids["fedora"] || ids["centos"] || ids["rocky"] || ids["almalinux"]:
		return linuxRHELDir, []string{"/usr/bin/update-ca-trust", "extract"}, nil
	}
	return "", nil, errors.New("unsupported Linux distribution (Debian/Ubuntu and RHEL/Rocky families only)")
}

func (a *Applier) applyLinux(ctx context.Context, act Action, cas []CA, st *state) Result {
	dir, update, err := a.linuxFamily()
	if err != nil {
		return failed("%v", err)
	}
	dir = filepath.Join(a.Root, dir)
	file := func(c CA) string { return filepath.Join(dir, "kryptkeeper-"+c.SHA256+".crt") }
	var changed []string
	var rollback []string
	switch act {
	case ActionAdd:
		if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- a CA anchor directory is world-readable by design
			return failed("create %s: %v", dir, err)
		}
		for _, c := range cas {
			p := file(c)
			if _, ok := st.Certs[c.SHA256]; ok {
				if _, serr := os.Stat(p); serr == nil {
					continue
				}
			}
			if err := os.WriteFile(p, c.PEM(), 0o644); err != nil { // #nosec G306 -- public certificate
				for _, r := range rollback {
					_ = os.Remove(r)
				}
				return failed("write %s: %v", p, err)
			}
			rollback = append(rollback, p)
			changed = append(changed, c.SHA256)
		}
	case ActionRemove:
		for _, c := range cas {
			if _, ok := st.Certs[c.SHA256]; !ok {
				continue
			}
			if err := os.Remove(file(c)); err != nil && !os.IsNotExist(err) {
				return failed("remove %s: %v", file(c), err)
			}
			changed = append(changed, c.SHA256)
		}
	}
	if len(changed) > 0 {
		args := update[1:]
		if act == ActionRemove && len(update) == 1 {
			// --fresh rebuilds /etc/ssl/certs so the removed link is gone; a plain
			// run only reports it in hooks (update-ca-certificates(8)).
			args = []string{"--fresh"}
		}
		if err := a.run(ctx, update[0], args...); err != nil {
			for _, r := range rollback {
				_ = os.Remove(r)
			}
			return failed("%v", err)
		}
	}
	for _, fp := range changed {
		if act == ActionAdd {
			c := findCA(cas, fp)
			st.Certs[fp] = entry{SHA1: c.SHA1, Subject: c.Cert.Subject.String(), Path: file(c), AddedAt: a.now().UTC().Format(time.RFC3339)}
		} else {
			delete(st.Certs, fp)
		}
	}
	return Result{Outcome: OutcomeApplied, Detail: summarize(act, len(changed), len(cas))}
}

func findCA(cas []CA, fp string) CA {
	for _, c := range cas {
		if c.SHA256 == fp {
			return c
		}
	}
	return CA{}
}

func summarize(act Action, changed, total int) string {
	verb := "added"
	if act == ActionRemove {
		verb = "removed"
	}
	skipped := total - changed
	if skipped == 0 {
		return fmt.Sprintf("%s %d certificate(s)", verb, changed)
	}
	if act == ActionRemove {
		return fmt.Sprintf("%s %d; %d not added by Kryptkeeper, left in place", verb, changed, skipped)
	}
	return fmt.Sprintf("%s %d; %d already present", verb, changed, skipped)
}

// writeTemp places a certificate where a command line tool can read it.
func (a *Applier) writeTemp(c CA) (string, error) {
	p := filepath.Join(a.tmp(), "kryptkeeper-trust-"+c.SHA256+".pem")
	if err := os.WriteFile(p, c.PEM(), 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// --- Windows -------------------------------------------------------------

// Commands: certutil -addstore/-delstore/-store,
// https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
// (the machine store is the default; CertId matches by serial or SHA-1 hash).
func (a *Applier) applyWindows(ctx context.Context, act Action, cas []CA, st *state) Result {
	changed := 0
	for _, c := range cas {
		store := "CA"
		if c.IsRoot() {
			store = "Root"
		}
		_, tracked := st.Certs[c.SHA256]
		switch act {
		case ActionAdd:
			if tracked {
				continue
			}
			if a.run(ctx, "certutil", "-store", store, c.SHA1) == nil {
				continue // already trusted before us: never take ownership of it
			}
			p, err := a.writeTemp(c)
			if err != nil {
				return failed("stage certificate: %v", err)
			}
			err = a.run(ctx, "certutil", "-addstore", "-f", store, p)
			_ = os.Remove(p)
			if err != nil {
				return failed("%v", err)
			}
			st.Certs[c.SHA256] = entry{SHA1: c.SHA1, Subject: c.Cert.Subject.String(), Store: store, AddedAt: a.now().UTC().Format(time.RFC3339)}
			changed++
		case ActionRemove:
			if !tracked {
				continue
			}
			if err := a.run(ctx, "certutil", "-delstore", st.Certs[c.SHA256].Store, c.SHA1); err != nil {
				return failed("%v", err)
			}
			delete(st.Certs, c.SHA256)
			changed++
		}
	}
	return Result{Outcome: OutcomeApplied, Detail: summarize(act, changed, len(cas))}
}

// --- macOS ---------------------------------------------------------------

// Commands: security add-trusted-cert / add-certificates / remove-trusted-cert
// / delete-certificate / find-certificate (security help <command> on macOS 27;
// delete-certificate -Z takes a SHA-256 or SHA-1 hash, SHA-1 works on older
// releases too).
func (a *Applier) applyDarwin(ctx context.Context, act Action, cas []CA, st *state) Result {
	changed := 0
	var listing string
	for _, c := range cas {
		_, tracked := st.Certs[c.SHA256]
		switch act {
		case ActionAdd:
			if tracked {
				continue
			}
			if listing == "" {
				out, err := a.Runner.Run(ctx, nil, "/usr/bin/security", "find-certificate", "-a", "-Z", macSystemKeychain)
				if err != nil {
					return failed("security find-certificate: %v", err)
				}
				listing = strings.ToUpper(string(out)) + "\n"
			}
			if strings.Contains(listing, c.SHA1) {
				continue // already in the System keychain before us
			}
			p, err := a.writeTemp(c)
			if err != nil {
				return failed("stage certificate: %v", err)
			}
			if c.IsRoot() {
				err = a.run(ctx, "/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", macSystemKeychain, p)
			} else {
				err = a.run(ctx, "/usr/bin/security", "add-certificates", "-k", macSystemKeychain, p)
			}
			_ = os.Remove(p)
			if err != nil {
				return failed("%v", err)
			}
			st.Certs[c.SHA256] = entry{SHA1: c.SHA1, Subject: c.Cert.Subject.String(), Store: macSystemKeychain, Root: c.IsRoot(), AddedAt: a.now().UTC().Format(time.RFC3339)}
			changed++
		case ActionRemove:
			if !tracked {
				continue
			}
			if st.Certs[c.SHA256].Root {
				p, err := a.writeTemp(c)
				if err != nil {
					return failed("stage certificate: %v", err)
				}
				err = a.run(ctx, "/usr/bin/security", "remove-trusted-cert", "-d", p)
				_ = os.Remove(p)
				if err != nil {
					return failed("%v", err)
				}
			}
			if err := a.run(ctx, "/usr/bin/security", "delete-certificate", "-Z", c.SHA1, macSystemKeychain); err != nil {
				return failed("%v", err)
			}
			delete(st.Certs, c.SHA256)
			changed++
		}
	}
	return Result{Outcome: OutcomeApplied, Detail: summarize(act, changed, len(cas))}
}
