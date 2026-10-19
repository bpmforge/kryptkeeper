// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import "context"

// ApprovalState is the external decision recorded on a ticket.
type ApprovalState string

const (
	ApprovalPending  ApprovalState = "pending"
	ApprovalApproved ApprovalState = "approved"
	ApprovalRejected ApprovalState = "rejected"
)

// ApprovalConnector is implemented by servicenow/jira in addition to Connector.
type ApprovalConnector interface {
	// Approval returns the external decision for the ticket and the external
	// identity that made it.
	Approval(ctx context.Context, ref TicketRef) (state ApprovalState, approverExternalID string, err error)
}
