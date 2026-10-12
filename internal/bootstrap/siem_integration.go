// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package bootstrap provides SIEM integration via:
//   - Webhook push (HTTP POST) — configurable with SIEM_WEBHOOK_URL
//   - RFC 5424 syslog output — configurable with SIEM_SYSLOG_ADDR
//
// Both targets emit either JSON (default) or ArcSight CEF (SIEM_FORMAT=cef,
// W19-27) — see formatCEF for the CEF encoding.
//
// Every audit action is forwarded under its own action name; seven keep their
// historical event types (cert.issued, cert.revoked, ca.created, ca.suspended,
// ca.activated, auth.login_success, auth.login_failed) so existing SIEM rules
// still match. KRYPTKEEPER_SIEM_ACTIONS narrows the set (see mapAuditActionToSIEM).
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/metrics"
)

// siemQueueSize bounds events awaiting delivery. When a SIEM sink is slow or
// down the queue fills and NEW events are dropped (counted), never blocking
// the audited request.
const siemQueueSize = 1024

// SIEMEvent is the canonical event payload sent to both webhook and syslog targets.
type SIEMEvent struct {
	EventType    string            `json:"event_type"`
	Timestamp    string            `json:"timestamp"`
	Severity     string            `json:"severity"` // info, warning, critical
	ActorID      string            `json:"actor_id"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	SourceIP     string            `json:"source_ip,omitempty"`
	TraceID      string            `json:"trace_id,omitempty"`
	Details      map[string]string `json:"details,omitempty"`
}

// SIEMRouter dispatches security events to configured SIEM targets.
// It is safe to call from multiple goroutines.
type SIEMRouter struct {
	webhookURL    string
	syslogAddr    string
	syslogNetwork string              // "udp" or "tcp"
	format        string              // "json" (default) or "cef" — W19-27
	actionFilter  map[string]struct{} // nil = forward every audit action
	httpClient    *http.Client

	mu         sync.Mutex
	syslogConn net.Conn

	// Forward queue: one worker drains it so a slow sink cannot spawn
	// unbounded goroutines. Started lazily on first Emit.
	queueOnce sync.Once
	queue     chan SIEMEvent
	queueSize int // 0 = siemQueueSize; test seam, set before first Emit
}

// NewSIEMRouterFromEnv creates a SIEMRouter from environment variables.
//
// SIEM_WEBHOOK_URL    — HTTP(S) endpoint to POST events to (e.g. Splunk HEC, Elastic).
// SIEM_SYSLOG_ADDR   — UDP/TCP syslog host:port (e.g. "192.168.1.50:514").
// SIEM_SYSLOG_PROTO  — "udp" (default) or "tcp".
// SIEM_FORMAT        — "json" (default) or "cef" (ArcSight Common Event Format, W19-27).
func NewSIEMRouterFromEnv() *SIEMRouter {
	return &SIEMRouter{
		webhookURL:    strings.TrimSpace(os.Getenv("SIEM_WEBHOOK_URL")),
		syslogAddr:    strings.TrimSpace(os.Getenv("SIEM_SYSLOG_ADDR")),
		syslogNetwork: syslogProtoFromEnv(),
		format:        siemFormatFromEnv(),
		actionFilter:  parseSIEMActionFilter(os.Getenv("KRYPTKEEPER_SIEM_ACTIONS")),
		// SEMGREP-007: the sink URL is operator-configured, so it goes
		// through the egress guard like every other outbound client. No
		// redirects: the Authorization token must never follow one.
		httpClient: egress.NewClient(egress.PolicyFromEnv(egress.Policy{
			AllowPrivate:  true, // SIEM collectors are usually internal
			AllowLoopback: egressAllowLoopback,
			Timeout:       5 * time.Second,
		})),
	}
}

func syslogProtoFromEnv() string {
	proto := strings.ToLower(strings.TrimSpace(os.Getenv("SIEM_SYSLOG_PROTO")))
	if proto == "tcp" {
		return "tcp"
	}
	return "udp"
}

// siemFormatFromEnv reads SIEM_FORMAT, defaulting to "json" (W19-27's
// acceptance bar: default unchanged) for anything other than a recognized
// "cef" (case-insensitive).
func siemFormatFromEnv() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SIEM_FORMAT")), "cef") {
		return "cef"
	}
	return "json"
}

// Enabled returns true if any SIEM output target is configured.
func (s *SIEMRouter) Enabled() bool {
	return s.webhookURL != "" || s.syslogAddr != ""
}

// SIEMStatus is an operator-facing summary of the SIEM configuration. Sensitive
// values (webhook path/query, token) are never exposed — only scheme+host.
type SIEMStatus struct {
	Enabled         bool   `json:"enabled"`
	WebhookEnabled  bool   `json:"webhook_enabled"`
	WebhookTarget   string `json:"webhook_target,omitempty"` // scheme://host, path/query masked
	WebhookHasToken bool   `json:"webhook_has_token"`
	SyslogEnabled   bool   `json:"syslog_enabled"`
	SyslogAddr      string `json:"syslog_addr,omitempty"`
	SyslogProto     string `json:"syslog_proto,omitempty"`
	// Format is "json" (default) or "cef" (W19-27) — applies to both the
	// webhook and syslog targets above.
	Format string `json:"format"`
}

// Status returns a sanitized summary of the configured SIEM targets.
func (s *SIEMRouter) Status() SIEMStatus {
	st := SIEMStatus{
		Enabled:        s.Enabled(),
		WebhookEnabled: s.webhookURL != "",
		SyslogEnabled:  s.syslogAddr != "",
		SyslogAddr:     s.syslogAddr,
		Format:         s.format,
	}
	if st.WebhookEnabled {
		st.WebhookTarget = maskWebhookURL(s.webhookURL)
		st.WebhookHasToken = strings.TrimSpace(os.Getenv("SIEM_WEBHOOK_TOKEN")) != ""
	}
	if st.SyslogEnabled {
		st.SyslogProto = s.syslogNetwork
	}
	return st
}

// maskWebhookURL returns scheme://host, dropping path and query which may carry
// tokens (e.g. Splunk HEC) — safe to surface in the UI.
func maskWebhookURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "(configured)"
}

// SIEMTestResult reports the outcome of a synchronous test emission per target.
type SIEMTestResult struct {
	Enabled       bool   `json:"enabled"`
	WebhookTested bool   `json:"webhook_tested"`
	WebhookOK     bool   `json:"webhook_ok"`
	WebhookError  string `json:"webhook_error,omitempty"`
	SyslogTested  bool   `json:"syslog_tested"`
	SyslogOK      bool   `json:"syslog_ok"`
	SyslogError   string `json:"syslog_error,omitempty"`
}

// Test synchronously sends a synthetic event to each configured target and
// reports per-target results. For UDP syslog, OK means the datagram was sent
// without error (connectionless — receipt cannot be confirmed).
func (s *SIEMRouter) Test(actorID string) SIEMTestResult {
	result := SIEMTestResult{Enabled: s.Enabled()}
	event := SIEMEvent{
		EventType:    "siem.test",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Severity:     "info",
		ActorID:      actorID,
		ResourceType: "integration",
		ResourceID:   "siem",
		Details:      map[string]string{"source": "settings_test"},
	}
	if s.webhookURL != "" {
		result.WebhookTested = true
		if err := s.sendWebhook(event); err != nil {
			result.WebhookError = err.Error()
		} else {
			result.WebhookOK = true
		}
	}
	if s.syslogAddr != "" {
		result.SyslogTested = true
		if err := s.sendSyslog(event); err != nil {
			result.SyslogError = err.Error()
		} else {
			result.SyslogOK = true
		}
	}
	return result
}

// Emit queues an event for asynchronous delivery to all configured SIEM
// targets. It never blocks: if the queue is full the event is dropped and
// counted (the audit log remains the system of record).
func (s *SIEMRouter) Emit(event SIEMEvent) {
	if !s.Enabled() {
		return
	}
	s.queueOnce.Do(func() {
		size := s.queueSize
		if size <= 0 {
			size = siemQueueSize
		}
		s.queue = make(chan SIEMEvent, size)
		go s.drain()
	})
	select {
	case s.queue <- event:
	default:
		metrics.SIEMEventsDropped.Inc()
	}
}

func (s *SIEMRouter) drain() {
	for event := range s.queue {
		s.deliver(event)
	}
}

func (s *SIEMRouter) deliver(event SIEMEvent) {
	if s.webhookURL != "" {
		if err := s.sendWebhook(event); err != nil {
			metrics.SIEMSendFailures.Inc()
			log.Printf("siem webhook: %v", err)
		} else {
			metrics.SIEMEventsForwarded.Inc()
		}
	}
	if s.syslogAddr != "" {
		if err := s.sendSyslog(event); err != nil {
			metrics.SIEMSendFailures.Inc()
			log.Printf("siem syslog: %v", err)
		} else {
			metrics.SIEMEventsForwarded.Inc()
		}
	}
}

func (s *SIEMRouter) sendWebhook(event SIEMEvent) error {
	var body []byte
	contentType := "application/json"
	if s.format == "cef" {
		body = []byte(formatCEF(event))
		contentType = "text/plain; charset=utf-8"
	} else {
		var err error
		body, err = json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshal failed: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request failed: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	// Standard Splunk HEC and Elastic headers.
	if token := strings.TrimSpace(os.Getenv("SIEM_WEBHOOK_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Splunk "+token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// sendSyslog formats the event as RFC 5424 and sends it over UDP/TCP. The
// RFC 5424 envelope (priority/timestamp/host/app/msgid) is unchanged by
// format; only the MSG payload switches between the ad hoc "event_type
// resource_id" text and a CEF line (W19-27).
func (s *SIEMRouter) sendSyslog(event SIEMEvent) error {
	msg := formatRFC5424(event, s.format)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Reconnect on each UDP send (connectionless), or reuse TCP connection.
	if s.syslogNetwork == "udp" {
		conn, err := net.DialTimeout("udp", s.syslogAddr, 2*time.Second)
		if err != nil {
			return fmt.Errorf("dial failed: %w", err)
		}
		defer conn.Close()
		if err := conn.SetWriteDeadline(time.Now().Add(syslogWriteTimeout)); err != nil {
			return err
		}
		_, err = conn.Write([]byte(msg))
		return err
	}

	// TCP: reuse connection, reconnect on error.
	if s.syslogConn == nil {
		conn, err := net.DialTimeout("tcp", s.syslogAddr, 2*time.Second)
		if err != nil {
			return fmt.Errorf("tcp dial failed: %w", err)
		}
		s.syslogConn = conn
	}
	if err := writeSyslogFrame(s.syslogConn, msg, syslogWriteTimeout); err != nil {
		// Stale connection — close and retry once.
		s.syslogConn.Close()
		s.syslogConn = nil
		conn, err2 := net.DialTimeout("tcp", s.syslogAddr, 2*time.Second)
		if err2 != nil {
			return fmt.Errorf("tcp reconnect failed: %w", err2)
		}
		s.syslogConn = conn
		if err3 := writeSyslogFrame(s.syslogConn, msg, syslogWriteTimeout); err3 != nil {
			return fmt.Errorf("tcp resend failed: %w", err3)
		}
	}
	return nil
}

// syslogWriteTimeout bounds a single syslog write. The drain worker is single
// and holds s.mu, so a collector that accepts the connection and then stops
// reading would otherwise wedge every later event once the socket buffer fills
// (RC2-N-03 / RC1-B-04).
const syslogWriteTimeout = 5 * time.Second

// writeSyslogFrame sends one octet-counted RFC 6587 frame under a write
// deadline.
func writeSyslogFrame(conn net.Conn, msg string, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(conn, "%d %s", len(msg), msg)
	return err
}

// syslogSafe makes a free-text field safe to place in a one-line syslog
// message: control characters (CR, LF, NUL, ESC, ...) and the Unicode line
// separators become spaces, so a resource id decoded from a URL path cannot
// start a second record at a line-splitting collector.
func syslogSafe(v string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, v)
}

// formatRFC5424 produces an RFC 5424 syslog message for the given event.
// Priority = facility Local0(16) << 3 | severity mapped from event.Severity.
// format selects the MSG payload: "cef" emits a CEF line (W19-27) in place
// of the structured-data element + free-text pair used for "json" (CEF is
// self-describing, so the separate kryptkeeper@99999 SD-ID would just
// duplicate what the CEF extensions already carry).
func formatRFC5424(event SIEMEvent, format string) string {
	event.EventType = syslogSafe(event.EventType)
	event.ResourceType = syslogSafe(event.ResourceType)
	event.ResourceID = syslogSafe(event.ResourceID)
	event.ActorID = syslogSafe(event.ActorID)
	event.Timestamp = syslogSafe(event.Timestamp)
	severity := 6 // informational
	switch event.Severity {
	case "warning":
		severity = 4 // warning
	case "critical":
		severity = 2 // critical
	}
	priority := (16 << 3) | severity // Local0 facility

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}
	appName := "kryptkeeper"
	msgID := strings.ReplaceAll(event.EventType, ".", "_")

	if format == "cef" {
		return fmt.Sprintf("<%d>1 %s %s %s - %s - %s",
			priority, event.Timestamp, hostname, appName, msgID, formatCEF(event))
	}

	// Structured data element with event fields.
	sd := fmt.Sprintf(`[kryptkeeper@99999 event_type=%q resource_type=%q resource_id=%q actor_id=%q]`,
		event.EventType, event.ResourceType, event.ResourceID, event.ActorID)

	msg := fmt.Sprintf("<%d>1 %s %s %s - %s %s %s",
		priority,
		event.Timestamp,
		hostname,
		appName,
		msgID,
		sd,
		event.EventType+" "+event.ResourceID,
	)
	return msg
}

// cefVersion is the CEF header's Device Version field, sourced from the same
// APP_VERSION env var /api/v1/meta reports (handlers_meta.go), defaulting to
// "dev" — there is no separate build-version plumbing for SIEM output.
func cefVersion() string {
	if v := strings.TrimSpace(os.Getenv("APP_VERSION")); v != "" {
		return v
	}
	return "dev"
}

// cefEventNames gives a human-readable CEF "Name" field for the event types
// this router has historically emitted (siemKnownActions, plus the synthetic
// siem.test event) — falls back to the raw event type for
// anything else so an unrecognized future event type still produces valid
// CEF rather than an empty Name.
var cefEventNames = map[string]string{
	"cert.issued":         "Certificate Issued",
	"cert.revoked":        "Certificate Revoked",
	"cert.expiry_warning": "Certificate Expiry Warning",
	"ca.created":          "CA Created",
	"ca.suspended":        "CA Suspended",
	"ca.activated":        "CA Activated",
	"auth.login_success":  "Login Success",
	"auth.login_failed":   "Login Failed",
	"siem.test":           "SIEM Test Event",
}

func cefEventName(eventType string) string {
	if name, ok := cefEventNames[eventType]; ok {
		return name
	}
	return eventType
}

// cefSeverity maps this router's three-value severity to the CEF spec's 0-10
// integer scale (0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very High).
func cefSeverity(severity string) int {
	switch severity {
	case "critical":
		return 9
	case "warning":
		return 6
	default:
		return 3
	}
}

// cefEscapeHeader escapes the two characters the CEF spec requires escaped
// in header fields (Device Vendor/Product/Version/Signature ID/Name):
// backslash and the pipe delimiter itself.
func cefEscapeHeader(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `|`, `\|`)
	return r.Replace(s)
}

// cefEscapeExtension escapes what the CEF spec requires escaped in an
// extension field's value: backslash and the "=" key/value delimiter.
// Newlines are additionally escaped (as \n) since raw newlines would break
// this router's own single-line webhook/syslog framing, not because the
// spec forbids them.
func cefEscapeExtension(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\n`)
	return r.Replace(s)
}

// cefTimestampMillis converts event.Timestamp (RFC3339, this router's own
// wire format) to the epoch-milliseconds string the CEF "rt" (Receipt Time)
// extension expects. Falls back to the raw string on a parse failure so a
// malformed timestamp degrades to "wrong format" rather than "field
// silently dropped".
func cefTimestampMillis(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return strconv.FormatInt(t.UnixMilli(), 10)
}

// formatCEF encodes event per the ArcSight CEF spec:
//
//	CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
//
// Header fields are pipe-delimited and escaped with cefEscapeHeader;
// extension key=value pairs are space-delimited and escaped with
// cefEscapeExtension. Device Event Class ID is the raw event type (a stable
// machine identifier); Name is the human-readable form from cefEventName.
// Resource type/id use the generic string extensions cs1/cs2 (with their
// required cs1Label/cs2Label) since CEF has no dedicated field for either.
func formatCEF(event SIEMEvent) string {
	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|",
		cefEscapeHeader("Kryptkeeper"),
		cefEscapeHeader("kryptkeeper"),
		cefEscapeHeader(cefVersion()),
		cefEscapeHeader(event.EventType),
		cefEscapeHeader(cefEventName(event.EventType)),
		cefSeverity(event.Severity),
	)

	var ext []string
	addExt := func(key, val string) {
		if val == "" {
			return
		}
		ext = append(ext, key+"="+cefEscapeExtension(val))
	}
	addExt("rt", cefTimestampMillis(event.Timestamp))
	addExt("suser", event.ActorID)
	addExt("act", event.EventType)
	addExt("outcome", event.Details["outcome"])
	addExt("src", event.SourceIP)
	addExt("cs1Label", "ResourceType")
	addExt("cs1", event.ResourceType)
	addExt("cs2Label", "ResourceID")
	addExt("cs2", event.ResourceID)
	if event.TraceID != "" {
		addExt("cs3Label", "TraceID")
		addExt("cs3", event.TraceID)
	}

	return header + strings.Join(ext, " ")
}

// EmitFromAuditEntry converts an AuditEntry into a SIEMEvent and dispatches it
// unless KRYPTKEEPER_SIEM_ACTIONS restricts the forwarded actions.
func (s *SIEMRouter) EmitFromAuditEntry(entry AuditEntry) {
	if !s.Enabled() {
		return
	}
	if !s.actionAllowed(entry.Action) {
		return
	}
	eventType, severity, ok := mapAuditActionToSIEM(entry.Action, entry.Outcome)
	if !ok {
		return
	}
	s.Emit(SIEMEvent{
		EventType:    eventType,
		Timestamp:    entry.Timestamp,
		Severity:     severity,
		ActorID:      entry.ActorID,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		SourceIP:     entry.SourceIP,
		TraceID:      entry.TraceID,
		Details:      map[string]string{"outcome": string(entry.Outcome), "actor_type": entry.ActorType},
	})
}

// siemKnownActions gives the established event type and base severity for the
// audit actions SIEM rules were already written against. Built once.
var siemKnownActions = map[string]struct{ eventType, severity string }{
	"certificate.issue":  {"cert.issued", "info"},
	"certificate.revoke": {"cert.revoked", "warning"},
	"ca.create":          {"ca.created", "info"},
	"ca.suspend":         {"ca.suspended", "warning"},
	"ca.activate":        {"ca.activated", "info"},
	"auth.login":         {"auth.login_success", "info"},
	"auth.login_failed":  {"auth.login_failed", "warning"},
}

// mapAuditActionToSIEM maps an audit action + outcome to a SIEM event type and
// severity. Every audit action is forwarded: the seven above keep their
// historical event types, anything else is sent under its own action name so a
// SIEM sees role changes, key operations, approvals and denials, not just
// issuance and login. The payload carries no change_summary, user agent or
// session (EmitFromAuditEntry), so widening the set does not widen what leaves.
func mapAuditActionToSIEM(action string, outcome AuditOutcome) (eventType, severity string, ok bool) {
	action = strings.TrimSpace(action)
	if action == "" {
		return "", "", false
	}
	failed := outcome.Adverse()
	if m, found := siemKnownActions[action]; found {
		sev := m.severity
		if failed {
			if m.eventType == "cert.issued" || m.eventType == "ca.created" {
				sev = "warning"
			} else {
				sev = "critical"
			}
		}
		return m.eventType, sev, true
	}
	if failed {
		return action, "warning", true
	}
	return action, "info", true
}

// parseSIEMActionFilter parses KRYPTKEEPER_SIEM_ACTIONS: comma-separated audit
// actions, each exact ("key.rotate") or a prefix ("key.*"). Empty means
// forward everything.
func parseSIEMActionFilter(raw string) map[string]struct{} {
	var out map[string]struct{}
	for _, a := range strings.Split(raw, ",") {
		if a = strings.TrimSpace(a); a != "" {
			if out == nil {
				out = map[string]struct{}{}
			}
			out[a] = struct{}{}
		}
	}
	return out
}

func (s *SIEMRouter) actionAllowed(action string) bool {
	if s.actionFilter == nil {
		return true
	}
	if _, ok := s.actionFilter[action]; ok {
		return true
	}
	for i := len(action) - 1; i > 0; i-- {
		if action[i] == '.' {
			if _, ok := s.actionFilter[action[:i]+".*"]; ok {
				return true
			}
		}
	}
	return false
}
