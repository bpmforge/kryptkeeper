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
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultSlackAPI = "https://slack.com/api"

// Button contract with W32-21 (chatops.ActionApprove / chatops.ActionReject and
// the "<kind>:<id>" value format). Duplicated, not imported, so delivery stays
// dependency-free; TestButtonContractPinned guards the literals.
const (
	slackActionApprove = "kk_approve"
	slackActionReject  = "kk_reject"

	slackSummaryMax = 500
	slackRetryCap   = 5 * time.Second
)

// ErrNoTeamChannel means no channel is mapped for the owner team. The caller
// keeps the alert internal; there is deliberately no default/broadcast fallback.
var ErrNoTeamChannel = errors.New("slack: no channel mapped for owner team")

// ErrNoMessage means no posted message is remembered for the key.
var ErrNoMessage = errors.New("slack: no message recorded for key")

// TeamChannelResolver maps an owner team to a Slack channel ID. The production
// map lives in runtime config key notifications.slack_team_channels (follow-up).
type TeamChannelResolver interface {
	SlackChannelFor(ctx context.Context, ownerTeam string) (channelID string, ok bool)
}

// MapResolver is a static team -> channel ID resolver.
type MapResolver map[string]string

func (m MapResolver) SlackChannelFor(_ context.Context, ownerTeam string) (string, bool) {
	c, ok := m[ownerTeam]
	return c, ok && c != ""
}

type ApprovalPending struct {
	Kind, ID  string // "approval"|"action" + id => button value Kind+":"+ID
	OwnerTeam string
	Summary   string
	Requester string
	ExpiresAt time.Time
	DeepLink  string
}

type MessageRef struct{ Channel, TS string }

type Outcome struct {
	Result     string // approved|rejected|expired
	By         string
	ExternalBy string
	At         time.Time
}

// RefStore remembers posted messages so the outcome can edit them.
type RefStore interface {
	Put(ctx context.Context, key string, ref MessageRef) error
	Get(ctx context.Context, key string) (MessageRef, bool, error)
}

// MemRefStore is an in-memory RefStore; a durable store is a follow-up.
type MemRefStore struct {
	mu sync.Mutex
	m  map[string]MessageRef
}

func (s *MemRefStore) Put(_ context.Context, key string, ref MessageRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]MessageRef{}
	}
	s.m[key] = ref
	return nil
}

func (s *MemRefStore) Get(_ context.Context, key string) (MessageRef, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.m[key]
	return ref, ok, nil
}

// SlackInteractive posts approval messages via the Slack Web API (incoming
// webhooks cannot carry callbacks or be edited). It never decides anything.
type SlackInteractive struct {
	BotToken string // never logged or put in errors
	BaseURL  string
	Resolver TeamChannelResolver
	Refs     RefStore
	HTTP     *http.Client
}

var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func slackEsc(s string) string { return slackEscaper.Replace(s) }

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackBlock struct {
	Type     string        `json:"type"`
	BlockID  string        `json:"block_id,omitempty"`
	Text     *slackText    `json:"text,omitempty"`
	Elements []slackButton `json:"elements,omitempty"`
}

type slackButton struct {
	Type     string    `json:"type"`
	Text     slackText `json:"text"`
	Style    string    `json:"style,omitempty"`
	ActionID string    `json:"action_id"`
	Value    string    `json:"value"`
}

func mrkdwnSection(text string) slackBlock {
	return slackBlock{Type: "section", Text: &slackText{Type: "mrkdwn", Text: text}}
}

// PostApproval sends the Approve/Reject message to the owner team's channel.
func (s *SlackInteractive) PostApproval(ctx context.Context, p ApprovalPending) (MessageRef, error) {
	if p.OwnerTeam == "" || s.Resolver == nil {
		return MessageRef{}, ErrNoTeamChannel
	}
	channel, ok := s.Resolver.SlackChannelFor(ctx, p.OwnerTeam)
	if !ok || channel == "" {
		return MessageRef{}, ErrNoTeamChannel
	}
	value := p.Kind + ":" + p.ID
	body := "*Approval needed*\n" + slackEsc(truncateRunes(p.Summary, slackSummaryMax))
	if p.Requester != "" {
		body += "\nRequested by " + slackEsc(p.Requester)
	}
	if !p.ExpiresAt.IsZero() {
		body += "\nExpires " + p.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if p.DeepLink != "" {
		body += "\n<" + slackEsc(p.DeepLink) + "|Open in Kryptkeeper>"
	}
	blocks := []slackBlock{
		mrkdwnSection(body),
		{Type: "actions", BlockID: "kk_" + p.Kind + "_" + p.ID, Elements: []slackButton{
			{Type: "button", Text: slackText{"plain_text", "Approve"}, Style: "primary", ActionID: slackActionApprove, Value: value},
			{Type: "button", Text: slackText{"plain_text", "Reject"}, Style: "danger", ActionID: slackActionReject, Value: value},
		}},
	}
	var resp struct {
		Channel string `json:"channel"`
		TS      string `json:"ts"`
	}
	req := map[string]any{
		"channel": channel,
		"text":    "Approval needed: " + truncateRunes(p.Summary, slackSummaryMax),
		"blocks":  blocks,
	}
	if err := s.call(ctx, "chat.postMessage", req, &resp); err != nil {
		return MessageRef{}, err
	}
	ref := MessageRef{Channel: resp.Channel, TS: resp.TS}
	if ref.Channel == "" {
		ref.Channel = channel
	}
	if s.Refs != nil {
		if err := s.Refs.Put(ctx, value, ref); err != nil {
			return ref, fmt.Errorf("slack: remember message: %w", err)
		}
	}
	return ref, nil
}

// UpdateOutcome edits the remembered message to show the result. It touches
// only the Slack message and never any approval state.
func (s *SlackInteractive) UpdateOutcome(ctx context.Context, key string, o Outcome) error {
	if s.Refs == nil {
		return ErrNoMessage
	}
	ref, ok, err := s.Refs.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("slack: load message: %w", err)
	}
	if !ok {
		return ErrNoMessage
	}
	var text string
	switch o.Result {
	case "expired":
		text = "*Expired* — no decision was made before the request expired. Nothing was changed. Raise the request again if still needed."
	default:
		res := o.Result
		if len(res) > 0 {
			res = strings.ToUpper(res[:1]) + res[1:]
		}
		text = "*" + slackEsc(res) + "* by " + slackEsc(o.By)
		if o.ExternalBy != "" {
			text += " (via " + slackEsc(o.ExternalBy) + ")"
		}
		text += " at " + o.At.UTC().Format(time.RFC3339)
	}
	req := map[string]any{
		"channel": ref.Channel,
		"ts":      ref.TS,
		"text":    text,
		"blocks":  []slackBlock{mrkdwnSection(text)},
	}
	return s.call(ctx, "chat.update", req, nil)
}

func (s *SlackInteractive) call(ctx context.Context, method string, req any, out any) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("slack: encode %s: %w", method, err)
	}
	client := s.HTTP
	if client == nil {
		client = newHTTPClient()
	}
	base := strings.TrimRight(s.BaseURL, "/")
	if base == "" {
		base = defaultSlackAPI
	}
	for attempt := 0; ; attempt++ {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/"+method, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("slack: build %s request", method)
		}
		hreq.Header.Set("Authorization", "Bearer "+s.BotToken)
		hreq.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp, err := client.Do(hreq)
		if err != nil {
			// Do's error embeds the URL, never the token; still drop the chain.
			return fmt.Errorf("slack: %s request failed", method)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if retryable && attempt == 0 {
			wait := time.Second
			if resp.StatusCode == http.StatusTooManyRequests {
				if secs, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && secs >= 0 {
					wait = time.Duration(secs) * time.Second
				}
			}
			if wait > slackRetryCap {
				wait = slackRetryCap
			}
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("slack: %s http %d", method, resp.StatusCode)
		}
		var env struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return fmt.Errorf("slack: %s: malformed response", method)
		}
		if !env.OK {
			return fmt.Errorf("slack: %s", env.Error)
		}
		if out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("slack: %s: malformed response", method)
			}
		}
		return nil
	}
}
