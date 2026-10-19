// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package teams

import "time"

// ApprovalCard builds the adaptive card with Approve and Reject buttons. Each
// button is an Action.Submit whose data comes back as activity.value.
func ApprovalCard(kind, id, summary, requester string, expires time.Time) map[string]any {
	btn := func(title, style, action string) map[string]any {
		return map[string]any{
			"type": "Action.Submit", "title": title, "style": style,
			"data": map[string]any{"kk_action": action, "kind": kind, "id": id},
		}
	}
	return map[string]any{
		"type":    "AdaptiveCard",
		"version": "1.4",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"body": []any{
			map[string]any{"type": "TextBlock", "text": "Kryptkeeper approval requested", "weight": "Bolder", "size": "Medium"},
			map[string]any{"type": "TextBlock", "text": summary, "wrap": true},
			map[string]any{"type": "FactSet", "facts": []any{
				map[string]any{"title": "Requested by", "value": requester},
				map[string]any{"title": "Request", "value": kind + ":" + id},
				map[string]any{"title": "Expires", "value": expires.UTC().Format(time.RFC3339)},
			}},
		},
		"actions": []any{btn("Approve", "positive", "approve"), btn("Reject", "destructive", "reject")},
	}
}
