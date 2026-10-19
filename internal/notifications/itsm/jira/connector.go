// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package jira implements itsm.Connector and itsm.ApprovalConnector on the
// Jira Cloud REST v3 API.
package jira

import (
	"bytes"
	"context"
	"encoding/json"
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
	maxBody    = 1 << 20
	maxErrBody = 200
	doneKey    = "done"
)

var (
	projectKeyRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	labelBadRe   = regexp.MustCompile(`[^A-Za-z0-9_-]`)
)

// Config is parsed by the caller from the credential-store JSON.
type Config struct {
	Email, APIToken string
	ProjectKey      string
	IssueType       string // default "Task"
	ApprovedStatus  string // status name that means approved
	RejectedStatus  string // optional
	DoneStatus      string // optional transition name; default: first to a "done" category
}

// Connector talks to one Jira Cloud site.
type Connector struct {
	baseURL string
	cfg     Config
	hc      *http.Client
}

var (
	_ itsm.Connector         = (*Connector)(nil)
	_ itsm.ApprovalConnector = (*Connector)(nil)
)

// New validates baseURL (https, or http for loopback hosts only) and cfg.
func New(baseURL string, cfg Config, hc *http.Client) (*Connector, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("jira: invalid base URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("jira: base URL must be https")
		}
	default:
		return nil, fmt.Errorf("jira: base URL must be https")
	}
	if !projectKeyRe.MatchString(cfg.ProjectKey) {
		return nil, fmt.Errorf("jira: project_key is required (letters, digits, underscore)")
	}
	if cfg.Email == "" || cfg.APIToken == "" {
		return nil, fmt.Errorf("jira: email and api_token are required")
	}
	if cfg.IssueType == "" {
		cfg.IssueType = "Task"
	}
	if hc == nil {
		return nil, fmt.Errorf("jira: http client is required")
	}
	return &Connector{baseURL: strings.TrimRight(u.String(), "/"), cfg: cfg, hc: hc}, nil
}

// Factory adapts New to itsm.Factory. The credential is JSON
// {"email","api_token","project_key","issue_type","approved_status",
// "rejected_status","done_status"}.
func Factory(baseURL string, credential []byte, hc *http.Client) (itsm.Connector, error) {
	var c struct {
		Email          string `json:"email"`
		APIToken       string `json:"api_token"`
		ProjectKey     string `json:"project_key"`
		IssueType      string `json:"issue_type"`
		ApprovedStatus string `json:"approved_status"`
		RejectedStatus string `json:"rejected_status"`
		DoneStatus     string `json:"done_status"`
	}
	if err := json.Unmarshal(credential, &c); err != nil {
		return nil, fmt.Errorf("jira: credential must be JSON with email, api_token and project_key")
	}
	return New(baseURL, Config{Email: c.Email, APIToken: c.APIToken, ProjectKey: c.ProjectKey, IssueType: c.IssueType,
		ApprovedStatus: c.ApprovedStatus, RejectedStatus: c.RejectedStatus, DoneStatus: c.DoneStatus}, hc)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Kind implements itsm.Connector.
func (c *Connector) Kind() string { return "jira" }

func (c *Connector) ref(key string) itsm.TicketRef {
	return itsm.TicketRef{Key: key, URL: c.baseURL + "/browse/" + key}
}

// label is the correlation label for an event id: Jira labels cannot hold
// spaces or most punctuation.
func label(eventID string) string { return "kk-" + labelBadRe.ReplaceAllString(eventID, "_") }

type apiError struct {
	ErrorMessages []string          `json:"errorMessages"`
	Errors        map[string]string `json:"errors"`
}

// do sends one request and returns the body on a 2xx. Failures wrap
// ErrTemporary or ErrPermanent; error text carries the status and Jira's own
// messages, never credentials or raw bodies.
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
	req.SetBasicAuth(c.cfg.Email, c.cfg.APIToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: jira request failed: %v", itsm.ErrTemporary, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, data, nil
	}
	return resp.StatusCode, data, statusErr(resp.StatusCode, data)
}

func statusErr(status int, body []byte) error {
	var ae apiError
	if err := json.Unmarshal(body, &ae); err != nil {
		ae = apiError{} // non-JSON error body: status alone is reported
	}
	msgs := ae.ErrorMessages
	for k, v := range ae.Errors {
		msgs = append(msgs, k+": "+v)
	}
	msg := strings.Join(msgs, "; ")
	if len(msg) > maxErrBody {
		msg = msg[:maxErrBody]
	}
	kind := itsm.ErrPermanent
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500 {
		kind = itsm.ErrTemporary
	}
	return fmt.Errorf("%w: jira returned %d: %s", kind, status, msg)
}

func unreadable() error { return fmt.Errorf("%w: unreadable jira response", itsm.ErrTemporary) }

// Find implements itsm.Connector, looking the issue up by its correlation label.
func (c *Connector) Find(ctx context.Context, eventID string) (*itsm.TicketRef, error) {
	q := url.Values{}
	q.Set("jql", fmt.Sprintf(`project = "%s" AND labels = "%s"`, c.cfg.ProjectKey, label(eventID)))
	q.Set("maxResults", "1")
	q.Set("fields", "key")
	_, data, err := c.do(ctx, http.MethodGet, "/rest/api/3/search/jql", q, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, unreadable()
	}
	if len(out.Issues) == 0 {
		return nil, nil
	}
	r := c.ref(out.Issues[0].Key)
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

// Create implements itsm.Connector. The correlation label is derived from ev.ID.
func (c *Connector) Create(ctx context.Context, ev itsm.Event) (itsm.TicketRef, error) {
	issueType := c.cfg.IssueType
	if ev.TicketType != "" {
		issueType = ev.TicketType
	}
	body := map[string]any{"fields": map[string]any{
		"project":   map[string]string{"key": c.cfg.ProjectKey},
		"issuetype": map[string]string{"name": issueType},
		"summary":   prefix(ev.Class) + ": " + ev.CN,
		"description": adfDoc([]string{
			"CN: " + ev.CN,
			"Serial: " + ev.Serial,
			"Expires: " + ev.NotAfter.UTC().Format(time.RFC3339),
			"Risk: " + ev.Risk,
			"Link: " + ev.DeepLink,
		}),
		"labels": []string{label(ev.ID), "kryptkeeper"},
	}}
	_, data, err := c.do(ctx, http.MethodPost, "/rest/api/3/issue", nil, body)
	if err != nil {
		return itsm.TicketRef{}, err
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Key == "" {
		// The issue may exist; Find adopts it by label on retry.
		return itsm.TicketRef{}, fmt.Errorf("%w: unreadable jira create response", itsm.ErrTemporary)
	}
	return c.ref(out.Key), nil
}

type statusInfo struct {
	Name           string `json:"name"`
	StatusCategory struct {
		Key string `json:"key"`
	} `json:"statusCategory"`
}

type issueResp struct {
	Fields struct {
		Status statusInfo `json:"status"`
	} `json:"fields"`
	Changelog struct {
		Histories []struct {
			Created string `json:"created"`
			Author  struct {
				AccountID string `json:"accountId"`
			} `json:"author"`
			Items []struct {
				Field    string `json:"field"`
				ToString string `json:"toString"`
			} `json:"items"`
		} `json:"histories"`
	} `json:"changelog"`
}

func issuePath(key string) string { return "/rest/api/3/issue/" + url.PathEscape(key) }

// getIssue returns nil, nil for a missing issue.
func (c *Connector) getIssue(ctx context.Context, key string, changelog bool) (*issueResp, error) {
	q := url.Values{}
	q.Set("fields", "status")
	if changelog {
		q.Set("expand", "changelog")
	}
	status, data, err := c.do(ctx, http.MethodGet, issuePath(key), q, nil)
	if status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out issueResp
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, unreadable()
	}
	return &out, nil
}

// Exists implements itsm.Connector.
func (c *Connector) Exists(ctx context.Context, ref itsm.TicketRef) (bool, error) {
	is, err := c.getIssue(ctx, ref.Key, false)
	return is != nil, err
}

// Resolve comments on the issue, then moves it through a done transition. An
// issue already in a done status category is success.
func (c *Connector) Resolve(ctx context.Context, ref itsm.TicketRef, comment string) error {
	is, err := c.getIssue(ctx, ref.Key, false)
	if err != nil {
		return err
	}
	if is == nil {
		return fmt.Errorf("%w: issue not found", itsm.ErrPermanent)
	}
	if is.Fields.Status.StatusCategory.Key == doneKey {
		return nil
	}
	if comment != "" {
		if _, _, err := c.do(ctx, http.MethodPost, issuePath(ref.Key)+"/comment", nil,
			map[string]any{"body": adfDoc([]string{comment})}); err != nil {
			return err
		}
	}
	_, data, err := c.do(ctx, http.MethodGet, issuePath(ref.Key)+"/transitions", nil, nil)
	if err != nil {
		return err
	}
	var ts struct {
		Transitions []struct {
			ID   string     `json:"id"`
			Name string     `json:"name"`
			To   statusInfo `json:"to"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(data, &ts); err != nil {
		return unreadable()
	}
	id := ""
	for _, t := range ts.Transitions {
		if c.cfg.DoneStatus != "" && strings.EqualFold(t.Name, c.cfg.DoneStatus) {
			id = t.ID
			break
		}
		if id == "" && t.To.StatusCategory.Key == doneKey {
			id = t.ID
		}
	}
	if id == "" {
		return fmt.Errorf("%w: no done transition", itsm.ErrPermanent)
	}
	_, _, err = c.do(ctx, http.MethodPost, issuePath(ref.Key)+"/transitions", nil,
		map[string]any{"transition": map[string]string{"id": id}})
	return err
}

// Approval implements itsm.ApprovalConnector: the issue's status name decides
// the state, and the changelog names who moved it there.
func (c *Connector) Approval(ctx context.Context, ref itsm.TicketRef) (itsm.ApprovalState, string, error) {
	is, err := c.getIssue(ctx, ref.Key, true)
	if err != nil {
		return "", "", err
	}
	if is == nil {
		return "", "", fmt.Errorf("%w: issue not found", itsm.ErrPermanent)
	}
	name := is.Fields.Status.Name
	var state itsm.ApprovalState
	switch {
	case c.cfg.ApprovedStatus != "" && strings.EqualFold(name, c.cfg.ApprovedStatus):
		state = itsm.ApprovalApproved
	case c.cfg.RejectedStatus != "" && strings.EqualFold(name, c.cfg.RejectedStatus):
		state = itsm.ApprovalRejected
	default:
		return itsm.ApprovalPending, "", nil
	}
	var who string
	var latest time.Time
	for _, h := range is.Changelog.Histories {
		moved := false
		for _, it := range h.Items {
			if it.Field == "status" && strings.EqualFold(it.ToString, name) {
				moved = true
			}
		}
		if !moved {
			continue
		}
		t, _ := time.Parse("2006-01-02T15:04:05.000-0700", h.Created)
		if who == "" || !t.Before(latest) {
			who, latest = h.Author.AccountID, t
		}
	}
	if who == "" {
		return "", "", fmt.Errorf("%w: approver unknown", itsm.ErrPermanent)
	}
	return state, who, nil
}
