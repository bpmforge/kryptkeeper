// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/tetratelabs/wazero/api"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/agentinstall"
)

const (
	maxLogLine       = 300
	maxHTTPBody      = 1 << 20
	maxHostInput     = 4 << 20
	httpTimeout      = 30 * time.Second
	logLinesPerCall  = 200
	defaultHTTPSPort = 443
)

// Event is something a plugin did or tried that the hub should see: a log
// line, an HTTP call, or a refused host call. Audit rows come from these.
type Event struct {
	Kind   string // "log", "http", "exec", "refused"
	Detail string
}

// Env is everything one operation may use. The hub fills it from the
// target, its credential and its own trust settings.
type Env struct {
	// Credential holds the decrypted credential fields the manifest's
	// credential_schema names; Secrets lists which of them to redact.
	Credential map[string]string
	Secrets    []string
	Target     map[string]string
	// HTTPClient makes the plugin's HTTPS calls. Its TLS trust is the hub's,
	// never the plugin's. Nil uses system roots.
	HTTPClient *http.Client
	// Executor reaches the target host for remote_exec plugins.
	Executor agentinstall.Executor
	// Timeout bounds one operation; zero means two minutes.
	Timeout time.Duration
	// Events, when set, receives every Event.
	Events func(Event)
}

type callStateKey struct{}

// callState is one operation's view of Env and its grant.
type callState struct {
	env      Env
	granted  abi.Capabilities
	redact   []string
	logLines int
}

func (st *callState) event(kind, detail string) {
	if st.env.Events != nil {
		st.env.Events(Event{Kind: kind, Detail: detail})
	}
}

// hostCall is the kk_host import: decode, enforce, act, and write the reply
// into memory the plugin allocates.
func hostCall(ctx context.Context, m api.Module, opPtr, opLen, inPtr, inLen uint32) uint64 {
	st, _ := ctx.Value(callStateKey{}).(*callState)
	var reply abi.HostReply
	op, okOp := m.Memory().Read(opPtr, opLen)
	in, okIn := m.Memory().Read(inPtr, inLen)
	switch {
	case st == nil:
		reply.Error = "no call in progress"
	case !okOp || !okIn || inLen > maxHostInput:
		reply.Error = "bad host call arguments"
	default:
		result, err := st.dispatch(ctx, string(op), append([]byte(nil), in...))
		if err != nil {
			reply.Error = err.Error()
		} else if result != nil {
			raw, mErr := json.Marshal(result)
			if mErr != nil {
				reply.Error = mErr.Error()
			} else {
				reply.Result = raw
			}
		}
	}
	out, _ := json.Marshal(reply)
	res, err := m.ExportedFunction("kk_alloc").Call(ctx, uint64(len(out)))
	if err != nil {
		return 0
	}
	ptr := uint32(res[0])
	if !m.Memory().Write(ptr, out) {
		return 0
	}
	return uint64(ptr)<<32 | uint64(len(out))
}

// errRefused marks a call the grant does not allow; the plugin sees the
// message and the hub sees a "refused" event.
type errRefused struct{ msg string }

func (e errRefused) Error() string { return "refused: " + e.msg }

func (st *callState) refuse(format string, args ...any) error {
	err := errRefused{msg: fmt.Sprintf(format, args...)}
	st.event("refused", err.msg)
	return err
}

func (st *callState) dispatch(ctx context.Context, op string, in []byte) (any, error) {
	switch op {
	case abi.HostLog:
		var req abi.LogRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return nil, err
		}
		st.log(req.Message)
		return nil, nil
	case abi.HostHTTP:
		var req abi.HTTPRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return nil, err
		}
		return st.httpDo(ctx, req)
	case abi.HostExecRun, abi.HostExecWrite, abi.HostExecRead, abi.HostExecExists:
		return st.exec(ctx, op, in)
	}
	return nil, st.refuse("unknown host operation %q", op)
}

// log writes one sanitized line.
func (st *callState) log(msg string) {
	if st.logLines >= logLinesPerCall {
		return
	}
	st.logLines++
	st.event("log", sanitize(msg, st.redact))
}

// sanitize caps a plugin-supplied string, refuses PEM blocks outright (a
// key in a log line is the one leak that cannot be undone) and redacts the
// secret values the plugin was given.
func sanitize(s string, redact []string) string {
	if strings.Contains(s, "-----BEGIN") {
		return "[line withheld: it contained a PEM block]"
	}
	for _, secret := range redact {
		if len(secret) >= 4 {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
	if len(s) > maxLogLine {
		s = s[:maxLogLine] + "..."
	}
	return s
}

// lineWriter routes the plugin's stdout and stderr through log.
type lineWriter struct {
	st  *callState
	buf bytes.Buffer
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			w.buf.Reset()
			w.buf.WriteString(line)
			break
		}
		w.st.log(strings.TrimRight(line, "\n"))
	}
	if w.buf.Len() > maxLogLine*4 {
		w.st.log(w.buf.String())
		w.buf.Reset()
	}
	return len(p), nil
}

// allowedHost reports whether host:port is within the network grant.
func (st *callState) allowedHost(host string, port int) bool {
	n := st.granted.Network
	if n == nil {
		return false
	}
	ports := n.Ports
	if len(ports) == 0 {
		ports = []int{defaultHTTPSPort}
	}
	portOK := false
	for _, p := range ports {
		if p == port {
			portOK = true
		}
	}
	if !portOK {
		return false
	}
	host = strings.ToLower(host)
	if n.HostsFromCredential != "" {
		if u, err := url.Parse(st.env.Credential[n.HostsFromCredential]); err == nil && u.Hostname() != "" && strings.EqualFold(u.Hostname(), host) {
			return true
		}
	}
	for _, h := range n.Hosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

func hostPort(u *url.URL) (string, int, error) {
	port := defaultHTTPSPort
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, err
		}
		port = n
	}
	return u.Hostname(), port, nil
}

func (st *callState) httpDo(ctx context.Context, req abi.HTTPRequest) (*abi.HTTPResponse, error) {
	if st.granted.Network == nil {
		return nil, st.refuse("network capability not granted")
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return nil, st.refuse("only https:// URLs without credentials in them are allowed")
	}
	host, port, err := hostPort(u)
	if err != nil || !st.allowedHost(host, port) {
		return nil, st.refuse("%s is not a host this plugin was granted", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	hreq, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}
	base := st.env.HTTPClient
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	client.Timeout = httpTimeout
	client.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		h, p, err := hostPort(r.URL)
		if err != nil || r.URL.Scheme != "https" || !st.allowedHost(h, p) {
			return st.refuse("redirect to %s is outside the grant", r.URL.Host)
		}
		return nil
	}
	resp, err := client.Do(hreq)
	if err != nil {
		var ref errRefused
		if errors.As(err, &ref) {
			return nil, ref
		}
		return nil, fmt.Errorf("https request failed: %s", sanitize(err.Error(), st.redact))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return nil, err
	}
	// Scheme and host only: webhook-style services carry their credential in
	// the path or query (Teams Workflows sig=, Slack hooks), and an event
	// detail reaches logs.
	st.event("http", sanitize(fmt.Sprintf("%s %s://%s -> %d", method, u.Scheme, u.Host, resp.StatusCode), st.redact))
	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	return &abi.HTTPResponse{Status: resp.StatusCode, Headers: headers, Body: body}, nil
}

// pathAllowed reports whether p is inside one of the granted prefixes.
func (st *callState) pathAllowed(p string) bool {
	clean := path.Clean(strings.ReplaceAll(p, `\`, "/"))
	if strings.Contains(p, "..") {
		return false
	}
	for _, prefix := range st.granted.FileWrite {
		pre := path.Clean(strings.ReplaceAll(prefix, `\`, "/"))
		if clean == pre || strings.HasPrefix(clean, strings.TrimSuffix(pre, "/")+"/") {
			return true
		}
	}
	return false
}

func (st *callState) exec(ctx context.Context, op string, in []byte) (any, error) {
	if !st.granted.RemoteExec {
		return nil, st.refuse("remote_exec capability not granted")
	}
	if st.env.Executor == nil {
		return nil, errors.New("this target has no remote executor")
	}
	if op == abi.HostExecRun {
		var req abi.ExecRunRequest
		if err := json.Unmarshal(in, &req); err != nil || len(req.Argv) == 0 {
			return nil, errors.New("exec.run needs argv")
		}
		if !st.granted.ElevatedExec {
			if why := elevationReason(req.Argv); why != "" {
				return nil, st.refuse("elevated_exec capability not granted (%s)", why)
			}
		}
		st.event("exec", sanitize(strings.Join(req.Argv, " "), st.redact))
		out, err := st.env.Executor.Run(ctx, req.Argv[0], req.Argv[1:]...)
		if err != nil {
			return nil, fmt.Errorf("%s", sanitize(err.Error(), st.redact))
		}
		return abi.ExecRunResponse{Output: out}, nil
	}
	var req abi.ExecFileRequest
	if err := json.Unmarshal(in, &req); err != nil {
		return nil, err
	}
	if !st.pathAllowed(req.Path) {
		return nil, st.refuse("path %s is outside the granted file_write paths", req.Path)
	}
	switch op {
	case abi.HostExecWrite:
		st.event("exec", "write "+req.Path)
		mode := req.Mode
		if mode == 0 {
			mode = 0o600
		}
		return nil, st.env.Executor.WriteFile(req.Path, req.Content, osMode(mode))
	case abi.HostExecRead:
		b, err := st.env.Executor.ReadFile(req.Path)
		return abi.ExecFileResponse{Content: b}, err
	default:
		return abi.ExecFileResponse{Exists: st.env.Executor.Exists(req.Path)}, nil
	}
}
