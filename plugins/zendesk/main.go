// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command zendesk is a ticket plugin for Zendesk Support.
//
// Create: POST {base_url}/api/v2/tickets.json with {"ticket": {subject,
// comment: {body}, priority, type, external_id, tags}}; 201 returns
// {"ticket": {"id": N, ...}}. Show: GET /api/v2/tickets/{id}.json (404 when the
// ticket is gone; a soft-deleted ticket reports status "deleted"). Solve:
// PUT /api/v2/tickets/{id}.json with {"ticket": {status: "solved", comment:
// {body, public: false}}}; the comment is an internal note so the requester is
// not emailed by the hub.
// https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/
//
// Auth is API-token basic auth: username "{email}/token", password the token.
// https://developer.zendesk.com/api-reference/introduction/security-and-auth/
// A 429 carries Retry-After in seconds:
// https://developer.zendesk.com/api-reference/introduction/rate-limits/
//
// base_url is the account's subdomain address (https://acme.zendesk.com); the
// manifest grants only that host.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/ticket"
)

func init() { ticket.Register(zd{}) }

func main() {}

type zd struct{}

const (
	maxSubject = 150
	maxBody    = 60000
)

var errBadCredential = errors.New("credential base_url must be the https address of your Zendesk account, and email and api_token are required")

type api struct {
	h    *delivery.Host
	base string
	auth string
}

func connect(h *delivery.Host, c map[string]string) (api, error) {
	base := ticket.BaseURL(c["base_url"])
	if base == "" || c["email"] == "" || c["api_token"] == "" {
		return api{}, errBadCredential
	}
	cred := base64.StdEncoding.EncodeToString([]byte(c["email"] + "/token:" + c["api_token"]))
	return api{h: h, base: base, auth: "Basic " + cred}, nil
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
	return "/api/v2/tickets/" + key + ".json", true
}

// priority maps the hub's risk vocabulary onto Zendesk's.
func priority(risk string) string {
	switch strings.ToLower(risk) {
	case "critical":
		return "urgent"
	case "high":
		return "high"
	case "low":
		return "low"
	}
	return "normal"
}

// ticketType keeps only the types Zendesk defines; the connection's free-text
// ticket type is otherwise ignored rather than failing every ticket.
func ticketType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "problem", "incident", "question", "task":
		return strings.ToLower(strings.TrimSpace(t))
	}
	return ""
}

func subject(ev abi.TicketEvent) string {
	name := ev.CN
	if name == "" {
		name = ev.Fingerprint
	}
	return ticket.Truncate(fmt.Sprintf("Kryptkeeper: %s - %s", strings.ReplaceAll(ev.Class, "_", " "), name), maxSubject)
}

func description(ev abi.TicketEvent) string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
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

func (zd) Create(h *delivery.Host, req abi.TicketCreateRequest) (abi.TicketCreateResult, error) {
	a, err := connect(h, req.Credential)
	if err != nil {
		return abi.TicketCreateResult{}, err
	}
	t := map[string]any{
		"subject": subject(req.Event), "comment": map[string]any{"body": description(req.Event)},
		"priority": priority(req.Event.Risk), "external_id": req.Event.ID, "tags": []string{"kryptkeeper"},
	}
	if ty := ticketType(req.Event.TicketType); ty != "" {
		t["type"] = ty
	}
	resp, err := a.do("POST", "/api/v2/tickets.json", map[string]any{"ticket": t})
	if err != nil {
		return abi.TicketCreateResult{}, err
	}
	if resp.Status != 201 && resp.Status != 200 {
		return abi.TicketCreateResult{TicketFailure: ticket.Failed(resp, "Zendesk did not create the ticket")}, nil
	}
	var out struct {
		Ticket struct {
			ID int64 `json:"id"`
		} `json:"ticket"`
	}
	if json.Unmarshal(resp.Body, &out) != nil || out.Ticket.ID == 0 {
		return abi.TicketCreateResult{}, errors.New("Zendesk answered without a ticket id")
	}
	key := fmt.Sprint(out.Ticket.ID)
	return abi.TicketCreateResult{Key: key, URL: a.base + "/agent/tickets/" + key}, nil
}

func (zd) Exists(h *delivery.Host, req abi.TicketExistsRequest) (abi.TicketExistsResult, error) {
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
				Status string `json:"status"`
			} `json:"ticket"`
		}
		if json.Unmarshal(resp.Body, &out) != nil {
			return abi.TicketExistsResult{}, errors.New("Zendesk answered with unreadable JSON")
		}
		return abi.TicketExistsResult{Exists: out.Ticket.Status != "deleted"}, nil
	case 404, 410:
		return abi.TicketExistsResult{}, nil
	}
	return abi.TicketExistsResult{TicketFailure: ticket.Failed(resp, "Zendesk could not show the ticket")}, nil
}

func (zd) Resolve(h *delivery.Host, req abi.TicketResolveRequest) (abi.TicketResolveResult, error) {
	a, err := connect(h, req.Credential)
	if err != nil {
		return abi.TicketResolveResult{}, err
	}
	path, ok := ticketPath(req.Key)
	if !ok {
		return abi.TicketResolveResult{TicketFailure: abi.TicketFailure{Failure: abi.FailurePermanent, Detail: "ticket key is not a Zendesk ticket id"}}, nil
	}
	t := map[string]any{"status": "solved"}
	if c := strings.TrimSpace(req.Comment); c != "" {
		t["comment"] = map[string]any{"body": ticket.Truncate(c, maxBody), "public": false}
	}
	resp, err := a.do("PUT", path, map[string]any{"ticket": t})
	if err != nil {
		return abi.TicketResolveResult{}, err
	}
	if resp.Status != 200 {
		return abi.TicketResolveResult{TicketFailure: ticket.Failed(resp, "Zendesk did not solve the ticket")}, nil
	}
	return abi.TicketResolveResult{}, nil
}
