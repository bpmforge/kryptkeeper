// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command freshservice is a ticket plugin for Freshservice.
//
// Create: POST {base_url}/api/v2/tickets with {subject, description, email,
// priority (1 low .. 4 urgent), status 2 (open), tags, optional type and
// workspace_id}; 201 returns {"ticket": {"id": N, ...}}. View: GET
// /api/v2/tickets/{id} (404 for an unknown id; a trashed ticket has
// "deleted": true). Resolve: PUT /api/v2/tickets/{id} with {"status": 4}
// (4 = Resolved), then POST /api/v2/tickets/{id}/notes with {body, private}.
// Notes are private unless "private" is false, so the hub's note never emails
// the requester.
// https://api.freshservice.com/#tickets
//
// Auth is basic auth with the API key as the username and any password ("X").
// A 429 carries Retry-After in seconds; the same page documents rate limits.
//
// base_url is the account's address (https://acme.freshservice.com); the
// manifest grants only that host.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/ticket"
)

func init() { ticket.Register(fs{}) }

func main() {}

type fs struct{}

const (
	maxSubject = 255
	maxBody    = 60000
	statusOpen = 2
	// statusResolved is Resolved (not Closed, which is 5): the service desk
	// closes it after its own grace period.
	statusResolved = 4
)

var errBadCredential = errors.New("credential base_url must be the https address of your Freshservice account, and api_key and requester_email are required")

type api struct {
	h    *delivery.Host
	base string
	auth string
	c    map[string]string
}

func connect(h *delivery.Host, c map[string]string) (api, error) {
	base := ticket.BaseURL(c["base_url"])
	if base == "" || c["api_key"] == "" || c["requester_email"] == "" {
		return api{}, errBadCredential
	}
	return api{h: h, base: base, c: c, auth: "Basic " + base64.StdEncoding.EncodeToString([]byte(c["api_key"]+":X"))}, nil
}

func (a api) do(method, path string, body any) (abi.HTTPResponse, error) {
	req := abi.HTTPRequest{Method: method, URL: a.base + path, Headers: map[string]string{"Authorization": a.auth, "Accept": "application/json"}}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return abi.HTTPResponse{}, err
		}
		req.Body = raw
		req.Headers["Content-Type"] = "application/json"
	}
	return a.h.HTTP(req)
}

// ticketPath refuses a key that is not a ticket id, so a key can never steer
// the request to another API path.
func ticketPath(key string) (string, bool) {
	if key == "" || len(key) > 18 || strings.Trim(key, "0123456789") != "" {
		return "", false
	}
	return "/api/v2/tickets/" + key, true
}

// priority maps the hub's risk vocabulary onto Freshservice's 1..4.
func priority(risk string) int {
	switch strings.ToLower(risk) {
	case "critical":
		return 4
	case "high":
		return 3
	case "low":
		return 1
	}
	return 2
}

func subject(ev abi.TicketEvent) string {
	name := ev.CN
	if name == "" {
		name = ev.Fingerprint
	}
	return ticket.Truncate(fmt.Sprintf("Kryptkeeper: %s - %s", strings.ReplaceAll(ev.Class, "_", " "), name), maxSubject)
}

// description is HTML (Freshservice's format); every value is escaped because
// a certificate's subject is attacker-influenced text.
func description(ev abi.TicketEvent) string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "<div>%s: %s</div>", k, html.EscapeString(v))
		}
	}
	line("Event", ev.Class)
	line("Certificate", ev.CN)
	line("Serial", ev.Serial)
	line("Fingerprint", ev.Fingerprint)
	line("Risk", ev.Risk)
	line("Expires", ev.NotAfter)
	line("Open in Kryptkeeper", ev.DeepLink)
	line("Kryptkeeper event id", ev.ID)
	return ticket.Truncate(b.String(), maxBody)
}

func (fs) Create(h *delivery.Host, req abi.TicketCreateRequest) (abi.TicketCreateResult, error) {
	a, err := connect(h, req.Credential)
	if err != nil {
		return abi.TicketCreateResult{}, err
	}
	t := map[string]any{
		"subject": subject(req.Event), "description": description(req.Event), "email": a.c["requester_email"],
		"priority": priority(req.Event.Risk), "status": statusOpen, "tags": []string{"kryptkeeper"},
	}
	switch strings.ToLower(strings.TrimSpace(req.Event.TicketType)) {
	case "incident":
		t["type"] = "Incident"
	case "service request":
		t["type"] = "Service Request"
	}
	if ws := a.c["workspace_id"]; ws != "" {
		var n int64
		if _, err := fmt.Sscan(ws, &n); err != nil || n <= 0 {
			return abi.TicketCreateResult{}, errors.New("credential workspace_id must be a number")
		}
		t["workspace_id"] = n
	}
	resp, err := a.do("POST", "/api/v2/tickets", t)
	if err != nil {
		return abi.TicketCreateResult{}, err
	}
	if resp.Status != 201 && resp.Status != 200 {
		return abi.TicketCreateResult{TicketFailure: ticket.Failed(resp, "Freshservice did not create the ticket")}, nil
	}
	var out struct {
		Ticket struct {
			ID int64 `json:"id"`
		} `json:"ticket"`
	}
	if json.Unmarshal(resp.Body, &out) != nil || out.Ticket.ID == 0 {
		return abi.TicketCreateResult{}, errors.New("Freshservice answered without a ticket id")
	}
	key := fmt.Sprint(out.Ticket.ID)
	return abi.TicketCreateResult{Key: key, URL: a.base + "/a/tickets/" + key}, nil
}

func (fs) Exists(h *delivery.Host, req abi.TicketExistsRequest) (abi.TicketExistsResult, error) {
	a, err := connect(h, req.Credential)
	if err != nil {
		return abi.TicketExistsResult{}, err
	}
	path, ok := ticketPath(req.Key)
	if !ok {
		return abi.TicketExistsResult{}, nil
	}
	resp, err := a.do("GET", path, nil)
	if err != nil {
		return abi.TicketExistsResult{}, err
	}
	switch resp.Status {
	case 200:
		var out struct {
			Ticket struct {
				Deleted bool `json:"deleted"`
			} `json:"ticket"`
		}
		if json.Unmarshal(resp.Body, &out) != nil {
			return abi.TicketExistsResult{}, errors.New("Freshservice answered with unreadable JSON")
		}
		return abi.TicketExistsResult{Exists: !out.Ticket.Deleted}, nil
	case 404, 410:
		return abi.TicketExistsResult{}, nil
	}
	return abi.TicketExistsResult{TicketFailure: ticket.Failed(resp, "Freshservice could not show the ticket")}, nil
}

func (fs) Resolve(h *delivery.Host, req abi.TicketResolveRequest) (abi.TicketResolveResult, error) {
	a, err := connect(h, req.Credential)
	if err != nil {
		return abi.TicketResolveResult{}, err
	}
	path, ok := ticketPath(req.Key)
	if !ok {
		return abi.TicketResolveResult{TicketFailure: abi.TicketFailure{Failure: abi.FailurePermanent, Detail: "ticket key is not a Freshservice ticket id"}}, nil
	}
	resp, err := a.do("PUT", path, map[string]any{"status": statusResolved})
	if err != nil {
		return abi.TicketResolveResult{}, err
	}
	if resp.Status != 200 {
		return abi.TicketResolveResult{TicketFailure: ticket.Failed(resp, "Freshservice did not resolve the ticket")}, nil
	}
	if c := strings.TrimSpace(req.Comment); c != "" {
		resp, err = a.do("POST", path+"/notes", map[string]any{"body": html.EscapeString(ticket.Truncate(c, maxBody)), "private": true})
		if err != nil {
			return abi.TicketResolveResult{}, err
		}
		if resp.Status != 201 && resp.Status != 200 {
			return abi.TicketResolveResult{TicketFailure: ticket.Failed(resp, "Freshservice resolved the ticket but did not take the note")}, nil
		}
	}
	return abi.TicketResolveResult{}, nil
}
