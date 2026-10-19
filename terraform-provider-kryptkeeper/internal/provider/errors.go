package provider

import (
	"encoding/json"
	"fmt"
	"strings"
)

// formatAPIError renders a non-2xx hub response. Hub errors are
// {"error": "<code>", "message": "<detail>"}; surfacing both keeps the rule
// name of a policy_violation visible in Terraform diagnostics. A body that is
// not that JSON shape keeps the raw "op path: status: body" form.
func formatAPIError(op, path string, status int, body []byte) error {
	trimmed := strings.TrimSpace(string(body))
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && (e.Error != "" || e.Message != "") {
		return fmt.Errorf("%s %s: %d: %s: %s", op, path, status, e.Error, e.Message)
	}
	return fmt.Errorf("%s %s: %d: %s", op, path, status, trimmed)
}

// pendingApprovalError renders a 202 from a dual-controlled route. The hub
// answers 202 when the operation was only proposed; nothing changed yet, so a
// caller must treat it as a failure and show the pending action id so a second
// admin can approve it. Shapes: {"data":{"action_id"}} (key/CA routes) and
// {"approval_id"} (certificate issuance); pending_action_id and id are also read.
func pendingApprovalError(op, path string, body []byte) error {
	var v struct {
		ApprovalID      string `json:"approval_id"`
		PendingActionID string `json:"pending_action_id"`
		ID              string `json:"id"`
		Data            struct {
			ActionID        string `json:"action_id"`
			ApprovalID      string `json:"approval_id"`
			PendingActionID string `json:"pending_action_id"`
			ID              string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &v) // an unparsable body just leaves the id blank
	id := ""
	for _, c := range []string{v.Data.ActionID, v.Data.PendingActionID, v.Data.ApprovalID, v.Data.ID,
		v.PendingActionID, v.ApprovalID, v.ID} {
		if c != "" {
			id = c
			break
		}
	}
	if id == "" {
		return fmt.Errorf("%s %s: 202: pending approval (no action id in the response); nothing was changed", op, path)
	}
	return fmt.Errorf("%s %s: 202: pending approval, action id %s; nothing was changed until a second admin approves it", op, path, id)
}
