// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package teams

import (
	"encoding/json"
	"errors"
	"time"

	"kryptkeeper/internal/notifications/chatops"
)

var (
	// ErrIgnored marks a well-formed activity that is not an approval click.
	ErrIgnored = errors.New("teams: activity ignored")
	// ErrStale marks a missing, unparseable or out-of-window timestamp.
	ErrStale = errors.New("teams: stale activity")
)

// Activity holds only the Bot Framework activity fields this package uses.
type Activity struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	ServiceURL string `json:"serviceUrl"`
	Timestamp  string `json:"timestamp"`
	From       struct {
		ID          string `json:"id"`
		AADObjectID string `json:"aadObjectId"`
		Name        string `json:"name"`
	} `json:"from"`
	Conversation struct {
		ID string `json:"id"`
	} `json:"conversation"`
	ChannelData struct {
		Tenant struct {
			ID string `json:"id"`
		} `json:"tenant"`
	} `json:"channelData"`
	Value map[string]any `json:"value"` // Action.Submit data: kk_action, kind, id
}

// ParseActivity decodes an activity. Anything that is not a message carrying
// an Action.Submit payload (kk_action) yields ErrIgnored.
func ParseActivity(body []byte) (Activity, error) {
	var a Activity
	if err := json.Unmarshal(body, &a); err != nil {
		return Activity{}, err
	}
	if a.Type != "message" {
		return a, ErrIgnored
	}
	if _, ok := a.Value["kk_action"].(string); !ok {
		return a, ErrIgnored
	}
	return a, nil
}

// CheckFresh requires a parseable timestamp within chatops.MaxSkew of now.
func (a Activity) CheckFresh(now time.Time) error {
	ts, err := time.Parse(time.RFC3339Nano, a.Timestamp)
	if err != nil {
		return ErrStale
	}
	d := now.Sub(ts)
	if d < 0 {
		d = -d
	}
	if d > chatops.MaxSkew {
		return ErrStale
	}
	return nil
}

// Action returns the string value of an Action.Submit data key.
func (a Activity) Action(key string) string {
	s, _ := a.Value[key].(string)
	return s
}
