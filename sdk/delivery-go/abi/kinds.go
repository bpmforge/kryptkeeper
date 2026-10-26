// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package abi

import "sort"

// Plugin kinds (D-321). A kind fixes the operations a plugin may be asked
// to run; the hub refuses any other op before it creates an instance.
const (
	KindDelivery    = "delivery"
	KindNotify      = "notify"
	KindTicket      = "ticket"
	KindDNS01       = "dns01"
	KindInventory   = "inventory"
	KindCredentials = "credentials"
	// KindIssuer is reserved for first-party CA plugins in 1.2; manifests
	// naming it are refused with a message that says so.
	KindIssuer = "issuer"
)

// Kinds is the set a manifest may name today.
var Kinds = map[string]bool{
	KindDelivery: true, KindNotify: true, KindTicket: true,
	KindDNS01: true, KindInventory: true, KindCredentials: true,
}

// KindNames lists Kinds sorted, for messages.
func KindNames() []string {
	out := make([]string, 0, len(Kinds))
	for k := range Kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// KindOps is the operation set per kind. Delivery keeps the bare op names it
// shipped with; every later kind namespaces its ops ("notify.send") so an op
// name identifies its kind. notify, ticket, dns01 and credentials run; the
// inventory set is empty and the hub does not run it yet.
var KindOps = map[string]map[string]bool{
	KindDelivery:    {OpValidate: true, OpPush: true, OpRollback: true, OpVerify: true},
	KindNotify:      {OpNotifySend: true},
	KindTicket:      {OpTicketCreate: true, OpTicketExists: true, OpTicketResolve: true},
	KindDNS01:       {OpDNS01Present: true, OpDNS01Cleanup: true},
	KindInventory:   {},
	KindCredentials: {OpCredentialsGet: true},
}

// Runnable reports whether the hub can run plugins of kind today.
func Runnable(kind string) bool { return len(KindOps[kind]) > 0 }

// OpAllowed reports whether a plugin of kind may be asked to run op. An empty
// kind is delivery.
func OpAllowed(kind, op string) bool {
	if kind == "" {
		kind = KindDelivery
	}
	return KindOps[kind][op]
}
