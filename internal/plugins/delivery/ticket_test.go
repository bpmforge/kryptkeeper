// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"errors"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// A ticket URL comes from a plugin and is stored and shown as a link, so only
// a plain https URL survives.
func TestSafeTicketURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://acme.zendesk.com/agent/tickets/5": "https://acme.zendesk.com/agent/tickets/5",
		"javascript:alert(1)":                      "",
		"http://acme.zendesk.com/agent/tickets/5":  "",
		"https://user:pw@acme.zendesk.com/x":       "",
		"https:///nohost":                          "",
		"":                                         "",
		"https://x.example/" + strings.Repeat("a", maxTicketURL): "",
	} {
		if got := safeTicketURL(in); got != want {
			t.Errorf("safeTicketURL(%.40q) = %q, want %q", in, got, want)
		}
	}
}

func TestTicketFailureClassesAndRedaction(t *testing.T) {
	if ticketFailure(abi.TicketFailure{}, nil) != nil {
		t.Fatal("no failure must be nil")
	}
	var te *TicketError
	err := ticketFailure(abi.TicketFailure{Failure: abi.FailurePermanent, Detail: "bad token s3cretvalue"}, []string{"s3cretvalue"})
	if !errors.As(err, &te) || te.Temporary || strings.Contains(te.Detail, "s3cretvalue") {
		t.Fatalf("permanent: %v", err)
	}
	// An unknown class from a plugin is retried, never silently dropped.
	if err := ticketFailure(abi.TicketFailure{Failure: "weird", RetryAfterSeconds: -4}, nil); !errors.As(err, &te) || !te.Temporary || te.RetryAfterSeconds != 0 {
		t.Fatalf("unknown class: %v", err)
	}
	long := ticketFailure(abi.TicketFailure{Failure: abi.FailureTemporary, Detail: strings.Repeat("x", 5000)}, nil)
	if !errors.As(long, &te) || len(te.Detail) > maxTicketDetail {
		t.Fatalf("detail not capped: %d", len(te.Detail))
	}
}
