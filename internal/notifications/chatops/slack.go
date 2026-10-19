// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package chatops verifies and parses interactive approval callbacks from chat
// platforms (Slack today) and maps chat identities to Kryptkeeper users.
package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ErrBadSignature   = errors.New("chatops: bad signature")
	ErrStaleTimestamp = errors.New("chatops: stale timestamp")
	ErrMissingHeaders = errors.New("chatops: missing signature headers")
	ErrReplay         = errors.New("chatops: replayed request")
)

// MaxSkew is how far a request timestamp may differ from now (either way).
const MaxSkew = 5 * time.Minute

// Interactive action ids carried on the approve and reject buttons.
const (
	ActionApprove = "kk_approve"
	ActionReject  = "kk_reject"
)

// VerifySlackSignature checks X-Slack-Signature = "v0=" + hex(HMAC_SHA256(secret,
// "v0:"+ts+":"+rawBody)) against the raw, unparsed body. An empty secret fails
// closed. Compare is constant time over the full "v0=<hex>" string.
func VerifySlackSignature(secret string, h http.Header, rawBody []byte, now time.Time) error {
	if secret == "" {
		return ErrBadSignature
	}
	ts := h.Get("X-Slack-Request-Timestamp")
	sig := h.Get("X-Slack-Signature")
	if ts == "" || sig == "" {
		return ErrMissingHeaders
	}
	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrBadSignature
	}
	skew := now.Sub(time.Unix(secs, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxSkew {
		return ErrStaleTimestamp
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(rawBody)
	want := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return ErrBadSignature
	}
	return nil
}

// Interaction is the subset of a Slack block_actions payload we act on.
type Interaction struct {
	TeamID, UserID, UserName, ActionID, Value, ResponseURL string
}

// ParseInteraction decodes the form field "payload" (JSON). Call it only after
// the signature has been verified. The type must be block_actions.
func ParseInteraction(rawBody []byte) (Interaction, error) {
	form, err := url.ParseQuery(string(rawBody))
	if err != nil {
		return Interaction{}, errors.New("chatops: malformed form body")
	}
	payload := form.Get("payload")
	if payload == "" {
		return Interaction{}, errors.New("chatops: missing payload")
	}
	var p struct {
		Type string `json:"type"`
		Team struct {
			ID string `json:"id"`
		} `json:"team"`
		User struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Name     string `json:"name"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
		ResponseURL string `json:"response_url"`
	}
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return Interaction{}, errors.New("chatops: malformed payload")
	}
	if p.Type != "block_actions" {
		return Interaction{}, errors.New("chatops: unsupported interaction type")
	}
	if p.Team.ID == "" || p.User.ID == "" || len(p.Actions) == 0 {
		return Interaction{}, errors.New("chatops: payload missing team, user or action")
	}
	name := p.User.Username
	if name == "" {
		name = p.User.Name
	}
	a := p.Actions[0]
	return Interaction{TeamID: p.Team.ID, UserID: p.User.ID, UserName: name,
		ActionID: a.ActionID, Value: a.Value, ResponseURL: p.ResponseURL}, nil
}

var valueRE = regexp.MustCompile(`^(approval|action):([A-Za-z0-9_-]{1,64})$`)

// ParseValue splits a button value "approval:<id>" or "action:<id>".
func ParseValue(v string) (kind, id string, err error) {
	m := valueRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", "", errors.New("chatops: invalid action value")
	}
	return m[1], m[2], nil
}
