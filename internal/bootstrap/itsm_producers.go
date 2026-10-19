// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// ITSM event producers (W32-28). approval_pending lives in
// itsm_approval_producer.go; renewal_failed and expiry_no_owner are here. All
// three share announceITSM: one itsm message per enabled itsm notification
// rule whose tenant may see the subject, a no-op when the provider only
// records. itsm.Channel turns the message into a ticket; the producer-chosen
// event_id (carried in the message) makes a re-announcement leave one ticket.

const (
	itsmClassRenewalFailed = "renewal_failed"
	itsmClassExpiryNoOwner = "expiry_no_owner"
)

// announceITSM sends msg() once per enabled itsm rule for which visible(rule
// tenant) holds. msg is built lazily, at most once.
func announceITSM(ctx context.Context, notifs NotificationProvider, label string, visible func(ruleTenant string) bool, msg func() string) {
	if notifs == nil || !notifs.Delivers() {
		return // record-only providers have no itsm channel
	}
	rules, err := notifs.ListRules(ctx)
	if err != nil {
		logging.Warnf("itsm: %s: listing notification rules: %v", label, err)
		return
	}
	var body string
	for _, r := range rules {
		if !r.Enabled || r.Channel != itsmChannelName || !visible(r.Tenant) {
			continue
		}
		if body == "" {
			body = msg()
		}
		if _, err := notifs.TestDelivery(ctx, itsmChannelName, r.Target, body); err != nil {
			logging.Warnf("itsm: %s: rule %s delivery failed: %v", label, r.ID, err)
		}
	}
}

// itsmCertVisible reports whether a rule of ruleTenant may receive cert's
// events (a connection never sees another tenant's certificates).
func itsmCertVisible(ctx context.Context, cert CertificateItem) func(string) bool {
	return func(ruleTenant string) bool {
		return caVisibleToTenant(ctx, activeTenantStore, AuthPrincipal{Tenant: chatopsTenant(ruleTenant)}, cert.CAID)
	}
}

func itsmDeepLink(path string) string {
	if base := strings.TrimRight(strings.TrimSpace(os.Getenv("KRYPTKEEPER_BASE_URL")), "/"); base != "" {
		return base + path
	}
	return path
}

// itsmCertRisk grades by time left: the closer the expiry, the higher the risk.
func itsmCertRisk(cert CertificateItem, now time.Time) string {
	exp, err := time.Parse(time.RFC3339, cert.ValidUntil)
	if err != nil {
		return "medium"
	}
	switch left := exp.Sub(now); {
	case left <= 7*24*time.Hour:
		return "critical"
	case left <= 30*24*time.Hour:
		return "high"
	}
	return "medium"
}

// itsmCertMessage is the JSON itsm.Channel.Send reads. The fingerprint is the
// certificate's SHA-256, the contract ResolveByFingerprint uses, so a later
// verified renewal closes the ticket.
func itsmCertMessage(class, eventID string, cert CertificateItem, now time.Time) string {
	m := map[string]string{
		"class":       class,
		"event_id":    eventID,
		"cn":          cert.CommonName,
		"serial":      cert.SerialNumber,
		"risk":        itsmCertRisk(cert, now),
		"deep_link":   itsmDeepLink("/certificates/" + cert.FingerprintSHA256),
		"fingerprint": cert.FingerprintSHA256,
	}
	if exp, err := time.Parse(time.RFC3339, cert.ValidUntil); err == nil {
		m["not_after"] = exp.UTC().Format(time.RFC3339)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// renewalFailedEventID names one failure episode: the certificate plus the
// time of the attempt before the terminal one (stable for the episode, new
// after an operator retry or a successful renewal restarts the count).
func renewalFailedEventID(fingerprint string, episode time.Time) string {
	return itsmClassRenewalFailed + ":" + fingerprint + ":" + strconv.FormatInt(episode.Unix(), 10)
}

// announceRenewalFailed opens ITSM tickets for a renewal that failed
// terminally (attempts exhausted).
func announceRenewalFailed(ctx context.Context, notifs NotificationProvider, cert CertificateItem, episode, now time.Time) {
	id := renewalFailedEventID(cert.FingerprintSHA256, episode)
	announceITSM(ctx, notifs, fmt.Sprintf("renewal failed %s", cert.FingerprintSHA256), itsmCertVisible(ctx, cert),
		func() string { return itsmCertMessage(itsmClassRenewalFailed, id, cert, now) })
}

// noOwnerAnnouncer emits expiry_no_owner once per certificate. The event id
// is the certificate's fingerprint, so the ITSM store dedupes across restarts
// and replicas; the in-memory set only keeps the hourly sweep from re-queueing
// the same delivery for every tick.
type noOwnerAnnouncer struct{ sent sync.Map }

func (a *noOwnerAnnouncer) announce(ctx context.Context, notifs NotificationProvider, cert CertificateItem, now time.Time) {
	if cert.OwnerEmail != "" || cert.OwnerTeam != "" {
		return
	}
	if _, dup := a.sent.LoadOrStore(cert.FingerprintSHA256, struct{}{}); dup {
		return
	}
	id := itsmClassExpiryNoOwner + ":" + cert.FingerprintSHA256
	announceITSM(ctx, notifs, fmt.Sprintf("no owner %s", cert.FingerprintSHA256), itsmCertVisible(ctx, cert),
		func() string { return itsmCertMessage(itsmClassExpiryNoOwner, id, cert, now) })
}
