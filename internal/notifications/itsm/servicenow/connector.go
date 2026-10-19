// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package servicenow implements itsm.Connector on ServiceNow's Table API
// (incident and change_request tables). W32-13 (CMDB sync) reuses its authenticated client.
package servicenow

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
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/notifications/itsm"
)

const (
	incidentPath = "/api/now/table/incident"
	changePath   = "/api/now/table/change_request"
	approverPath = "/api/now/table/sysapproval_approver"
	maxBody      = 1 << 20
	maxErrBody   = 200

	stateResolved = "6"
	stateClosed   = "7"

	// change_request states: 3 = Closed, 4 = Canceled (the incident table uses
	// 6/7 for the same moments).
	changeStateClosed   = "3"
	changeStateCanceled = "4"

	ticketTypeChange = "change_request"
)

// table is the ServiceNow table a ticket lives in. A ticket's table is part of
// its TicketRef (the URL names it), so Exists/Resolve/Approval reach the right
// table without extra storage; refs stored before change_request support are
// incidents.
type table struct {
	name       string
	path       string
	doneStates []string // states in which Resolve has nothing left to do
}

var (
	incidentTable = table{name: "incident", path: incidentPath, doneStates: []string{stateResolved, stateClosed}}
	changeTable   = table{name: ticketTypeChange, path: changePath, doneStates: []string{changeStateClosed, changeStateCanceled}}
)

func tableForType(ticketType string) table {
	if ticketType == ticketTypeChange {
		return changeTable
	}
	return incidentTable
}

// tableOf reads the table out of a ref's URL (".../nav_to.do?uri=<table>.do?...").
func tableOf(ref itsm.TicketRef) table {
	if strings.Contains(ref.URL, "uri="+ticketTypeChange+".do") {
		return changeTable
	}
	return incidentTable
}

func (t table) done(state string) bool {
	for _, s := range t.doneStates {
		if s == state {
			return true
		}
	}
	return false
}

// sysIDRe guards the sys_id spliced into an encoded query.
var sysIDRe = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// Credentials are the integration user's basic-auth pair.
type Credentials struct{ Username, Password string }

// Connector talks to one ServiceNow instance.
type Connector struct {
	baseURL string
	creds   Credentials
	hc      *http.Client
}

var (
	_ itsm.Connector         = (*Connector)(nil)
	_ itsm.ApprovalConnector = (*Connector)(nil)
)

// New validates baseURL (https, or http for loopback hosts only, which keeps
// httptest usable) and returns a Connector using hc.
func New(baseURL string, creds Credentials, hc *http.Client) (*Connector, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("servicenow: invalid base URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("servicenow: base URL must be https")
		}
	default:
		return nil, fmt.Errorf("servicenow: base URL must be https")
	}
	if creds.Username == "" || creds.Password == "" {
		return nil, fmt.Errorf("servicenow: username and password are required")
	}
	if hc == nil {
		return nil, fmt.Errorf("servicenow: http client is required")
	}
	return &Connector{baseURL: strings.TrimRight(u.String(), "/"), creds: creds, hc: hc}, nil
}

// Factory adapts New to itsm.Factory; the credential is JSON
// {"username":"...","password":"..."}.
func Factory(baseURL string, credential []byte, hc *http.Client) (itsm.Connector, error) {
	var c struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(credential, &c); err != nil {
		return nil, fmt.Errorf("servicenow: credential must be JSON with username and password")
	}
	return New(baseURL, Credentials{Username: c.Username, Password: c.Password}, hc)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Kind implements itsm.Connector.
func (c *Connector) Kind() string { return "servicenow" }

type incident struct {
	SysID  string `json:"sys_id"`
	Number string `json:"number"`
	State  string `json:"state"`
}

func (c *Connector) ref(t table, in incident) itsm.TicketRef {
	u := c.baseURL + "/nav_to.do?uri=" + t.name + ".do?sys_id=" + url.QueryEscape(in.SysID)
	if in.Number != "" {
		u += "&number=" + url.QueryEscape(in.Number)
	}
	return itsm.TicketRef{Key: in.SysID, URL: u}
}

// do sends one request and returns the body on a 2xx. Failures wrap
// ErrTemporary or ErrPermanent; error text carries status and a truncated
// body, never credentials.
func (c *Connector) do(ctx context.Context, method, path string, q url.Values, body any) (status int, data []byte, err error) {
	var rd io.Reader
	if body != nil {
		b, merr := json.Marshal(body)
		if merr != nil {
			return 0, nil, fmt.Errorf("%w: encoding request", itsm.ErrPermanent)
		}
		rd = bytes.NewReader(b)
	}
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: building request", itsm.ErrPermanent)
	}
	req.SetBasicAuth(c.creds.Username, c.creds.Password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		// net/url errors carry the URL (no userinfo is set), not credentials.
		return 0, nil, fmt.Errorf("%w: servicenow request failed: %v", itsm.ErrTemporary, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, data, nil
	}
	return resp.StatusCode, data, statusErr(resp.StatusCode, data)
}

func statusErr(status int, body []byte) error {
	snippet := string(body)
	if len(snippet) > maxErrBody {
		snippet = snippet[:maxErrBody]
	}
	kind := itsm.ErrPermanent
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500 {
		kind = itsm.ErrTemporary
	}
	return fmt.Errorf("%w: servicenow returned %d: %s", kind, status, snippet)
}

// Find implements itsm.Connector.
//
// The ticket type is not known here, so the incident table is searched first
// and then change_request; the correlation id is unique to one event.
func (c *Connector) Find(ctx context.Context, eventID string) (*itsm.TicketRef, error) {
	for _, t := range []table{incidentTable, changeTable} {
		ref, err := c.findIn(ctx, t, eventID)
		if err != nil && t.name == changeTable.name && secondaryDenied(err) {
			// An integration user that cannot read change_request must still
			// open incidents: the secondary search is best effort.
			return nil, nil
		}
		if err != nil || ref != nil {
			return ref, err
		}
	}
	return nil, nil
}

// secondaryDenied reports a 403/404 from a table the integration user may not
// be allowed to read.
func secondaryDenied(err error) bool {
	return strings.Contains(err.Error(), "servicenow returned 403") || strings.Contains(err.Error(), "servicenow returned 404")
}

func (c *Connector) findIn(ctx context.Context, t table, eventID string) (*itsm.TicketRef, error) {
	q := url.Values{}
	q.Set("sysparm_query", "correlation_id="+eventID)
	q.Set("sysparm_limit", "1")
	q.Set("sysparm_fields", "sys_id,number,state")
	_, data, err := c.do(ctx, http.MethodGet, t.path, q, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Result []incident `json:"result"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%w: unreadable servicenow response", itsm.ErrTemporary)
	}
	if len(out.Result) == 0 {
		return nil, nil
	}
	r := c.ref(t, out.Result[0])
	return &r, nil
}

func prefix(class string) string {
	switch class {
	case "renewal_failed":
		return "Certificate renewal failed"
	case "approval_pending":
		return "Certificate approval pending"
	}
	return "Certificate alert"
}

// Create implements itsm.Connector. The correlation id is ev.ID.
func (c *Connector) Create(ctx context.Context, ev itsm.Event) (itsm.TicketRef, error) {
	sev := "3"
	if r := strings.ToLower(ev.Risk); r == "high" || r == "critical" {
		sev = "2"
	}
	t := tableForType(ev.TicketType)
	body := map[string]string{
		"short_description":   prefix(ev.Class) + ": " + ev.CN,
		"description":         fmt.Sprintf("CN: %s\nSerial: %s\nExpires: %s\nRisk: %s\nLink: %s", ev.CN, ev.Serial, ev.NotAfter.UTC().Format(time.RFC3339), ev.Risk, ev.DeepLink),
		"correlation_id":      ev.ID,
		"correlation_display": "Kryptkeeper",
		"urgency":             sev,
		"impact":              sev,
	}
	if t.name == incidentTable.name {
		body["category"] = "software"
	}
	_, data, err := c.do(ctx, http.MethodPost, t.path, nil, body)
	if err != nil {
		return itsm.TicketRef{}, err
	}
	var out struct {
		Result incident `json:"result"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Result.SysID == "" {
		// The incident may exist; Find adopts it by correlation id on retry.
		return itsm.TicketRef{}, fmt.Errorf("%w: unreadable servicenow create response", itsm.ErrTemporary)
	}
	return c.ref(t, out.Result), nil
}

func (c *Connector) get(ctx context.Context, t table, sysID string) (*incident, error) {
	q := url.Values{}
	q.Set("sysparm_fields", "sys_id,state")
	status, data, err := c.do(ctx, http.MethodGet, t.path+"/"+url.PathEscape(sysID), q, nil)
	if status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out struct {
		Result incident `json:"result"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%w: unreadable servicenow response", itsm.ErrTemporary)
	}
	return &out.Result, nil
}

// Exists implements itsm.Connector; closed and canceled incidents still exist.
func (c *Connector) Exists(ctx context.Context, ref itsm.TicketRef) (bool, error) {
	in, err := c.get(ctx, tableOf(ref), ref.Key)
	return in != nil, err
}

// Resolve moves the incident to Resolved with the comment as close and work
// notes, in one PATCH. An incident already resolved or closed is success.
func (c *Connector) Resolve(ctx context.Context, ref itsm.TicketRef, comment string) error {
	t := tableOf(ref)
	body := map[string]string{
		"state":       stateResolved,
		"close_code":  "Solved (Permanently)",
		"close_notes": comment,
		"work_notes":  comment,
	}
	if t.name == changeTable.name {
		// A change is closed, not resolved; "successful" is its close_code choice.
		body["state"], body["close_code"] = changeStateClosed, "successful"
	}
	status, _, err := c.do(ctx, http.MethodPatch, t.path+"/"+url.PathEscape(ref.Key), nil, body)
	if err == nil {
		return nil
	}
	if status == http.StatusBadRequest || status == http.StatusForbidden {
		if in, gerr := c.get(ctx, t, ref.Key); gerr == nil && in != nil && t.done(in.State) {
			return nil
		}
	}
	if status == http.StatusNotFound {
		return fmt.Errorf("%w: %s not found", itsm.ErrPermanent, t.name)
	}
	if errors.Is(err, itsm.ErrTemporary) || errors.Is(err, itsm.ErrPermanent) {
		return err
	}
	return fmt.Errorf("%w: %v", itsm.ErrPermanent, err)
}

// Approval implements itsm.ApprovalConnector: the incident's approval field
// (requested, approved, rejected, not requested) decides the state; once
// approved, the newest approved sysapproval_approver row names the approver by
// sys_user sys_id, which is the external id the principal map keys on.
func (c *Connector) Approval(ctx context.Context, ref itsm.TicketRef) (itsm.ApprovalState, string, error) {
	if !sysIDRe.MatchString(ref.Key) {
		return "", "", fmt.Errorf("%w: invalid ticket key", itsm.ErrPermanent)
	}
	q := url.Values{}
	q.Set("sysparm_fields", "sys_id,approval")
	status, data, err := c.do(ctx, http.MethodGet, tableOf(ref).path+"/"+url.PathEscape(ref.Key), q, nil)
	if status == http.StatusNotFound {
		return "", "", fmt.Errorf("%w: ticket not found", itsm.ErrPermanent)
	}
	if err != nil {
		return "", "", err
	}
	var inc struct {
		Result struct {
			Approval string `json:"approval"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &inc); err != nil {
		return "", "", fmt.Errorf("%w: unreadable servicenow response", itsm.ErrTemporary)
	}
	var state itsm.ApprovalState
	switch strings.ToLower(strings.TrimSpace(inc.Result.Approval)) {
	case "approved":
		state = itsm.ApprovalApproved
	case "rejected":
		state = itsm.ApprovalRejected
	default:
		return itsm.ApprovalPending, "", nil
	}
	who, err := c.approver(ctx, ref.Key)
	if err != nil {
		return "", "", err
	}
	return state, who, nil
}

// approver returns the sys_user sys_id of the newest approver whose own
// decision is approved.
func (c *Connector) approver(ctx context.Context, sysID string) (string, error) {
	q := url.Values{}
	q.Set("sysparm_query", "sysapproval="+sysID+"^state=approved^ORDERBYDESCsys_updated_on")
	q.Set("sysparm_limit", "1")
	q.Set("sysparm_fields", "approver")
	_, data, err := c.do(ctx, http.MethodGet, approverPath, q, nil)
	if err != nil {
		return "", err
	}
	var out struct {
		Result []struct {
			Approver json.RawMessage `json:"approver"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("%w: unreadable servicenow response", itsm.ErrTemporary)
	}
	if len(out.Result) > 0 {
		// A reference field is {"link":...,"value":"<sys_id>"}; a plain value is a string.
		var ref struct {
			Value string `json:"value"`
		}
		var plain string
		raw := out.Result[0].Approver
		if json.Unmarshal(raw, &ref) == nil && ref.Value != "" {
			return ref.Value, nil
		}
		if json.Unmarshal(raw, &plain) == nil && plain != "" {
			return plain, nil
		}
	}
	return "", fmt.Errorf("%w: approver unknown", itsm.ErrPermanent)
}
