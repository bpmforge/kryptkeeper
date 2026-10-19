// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package teams

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrNoTeamChannel means the owner team has no mapped Teams channel; nothing is sent.
var ErrNoTeamChannel = errors.New("teams: no channel mapped for owner team")

// DefaultTokenURL issues Bot Framework client-credentials tokens.
const DefaultTokenURL = "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"

// ChannelRef addresses a Teams channel conversation.
type ChannelRef struct{ ServiceURL, ConversationID string }

// ChannelResolver maps an owner team to its Teams channel. The config source
// (notifications.teams_team_channels) is a follow-up; MapResolver serves tests
// and static wiring.
type ChannelResolver interface {
	TeamsChannelFor(ctx context.Context, ownerTeam string) (ChannelRef, bool)
}

// MapResolver is a ChannelResolver backed by a map.
type MapResolver map[string]ChannelRef

func (m MapResolver) TeamsChannelFor(_ context.Context, ownerTeam string) (ChannelRef, bool) {
	r, ok := m[ownerTeam]
	return r, ok
}

// Poster sends the approval card to the owner team's channel.
type Poster struct {
	AppID, AppPassword string
	TokenURL           string // default DefaultTokenURL
	HTTP               *http.Client
	Resolver           ChannelResolver

	allowInsecureServiceURL bool // test seam (same package): httptest servers are http on an IP literal

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func (p *Poster) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return newHTTPClient()
}

// validServiceURL requires https and a hostname (no IP literals: SSRF).
func validServiceURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return false
	}
	h := strings.Trim(u.Hostname(), "[]")
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	return true
}

func (p *Poster) accessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" && time.Now().Before(p.tokenExp) {
		return p.token, nil
	}
	tu := p.TokenURL
	if tu == "" {
		tu = DefaultTokenURL
	}
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {p.AppID},
		"client_secret": {p.AppPassword}, "scope": {"https://api.botframework.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tu, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("teams token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("teams token: status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("teams token: bad response")
	}
	p.token = tr.AccessToken
	p.tokenExp = time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second - time.Minute)
	return p.token, nil
}

// PostApproval sends the adaptive card to ownerTeam's channel. An unmapped team
// makes zero HTTP calls and returns ErrNoTeamChannel. Errors never include the
// app password or token.
func (p *Poster) PostApproval(ctx context.Context, ownerTeam, kind, id, summary, requester string, expires time.Time) error {
	_, _, err := p.PostApprovalRef(ctx, ownerTeam, kind, id, summary, requester, expires)
	return err
}

// PostApprovalRef is PostApproval that also returns the channel it posted to
// and the activity id Teams assigned, so the card can be updated later.
func (p *Poster) PostApprovalRef(ctx context.Context, ownerTeam, kind, id, summary, requester string, expires time.Time) (ChannelRef, string, error) {
	if p.Resolver == nil {
		return ChannelRef{}, "", ErrNoTeamChannel
	}
	ref, ok := p.Resolver.TeamsChannelFor(ctx, ownerTeam)
	if !ok {
		return ChannelRef{}, "", ErrNoTeamChannel
	}
	if !p.allowInsecureServiceURL && !validServiceURL(ref.ServiceURL) {
		return ChannelRef{}, "", errors.New("teams: serviceUrl must be https with a hostname")
	}
	if ref.ConversationID == "" {
		return ChannelRef{}, "", ErrNoTeamChannel
	}
	tok, err := p.accessToken(ctx)
	if err != nil {
		return ChannelRef{}, "", err
	}
	body, err := json.Marshal(map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     ApprovalCard(kind, id, summary, requester, expires),
		}},
	})
	if err != nil {
		return ChannelRef{}, "", err
	}
	endpoint := strings.TrimRight(ref.ServiceURL, "/") + "/v3/conversations/" + url.PathEscape(ref.ConversationID) + "/activities"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ChannelRef{}, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := p.client().Do(req)
	if err != nil {
		return ChannelRef{}, "", fmt.Errorf("teams post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ChannelRef{}, "", fmt.Errorf("teams post: status %d", resp.StatusCode)
	}
	var out struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out) // an unreadable body only loses the update handle
	return ref, out.ID, nil
}

// UpdateActivity replaces a previously posted card with plain text (the
// outcome), removing the Approve/Reject buttons. It never touches approval
// state.
func (p *Poster) UpdateActivity(ctx context.Context, ref ChannelRef, activityID, text string) error {
	if !p.allowInsecureServiceURL && !validServiceURL(ref.ServiceURL) {
		return errors.New("teams: serviceUrl must be https with a hostname")
	}
	if ref.ConversationID == "" || activityID == "" {
		return ErrNoTeamChannel
	}
	tok, err := p.accessToken(ctx)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"type": "message", "id": activityID, "text": text, "attachments": []any{}})
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(ref.ServiceURL, "/") + "/v3/conversations/" + url.PathEscape(ref.ConversationID) + "/activities/" + url.PathEscape(activityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("teams update: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("teams update: status %d", resp.StatusCode)
	}
	return nil
}
