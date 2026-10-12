// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package ctmonitor watches Certificate Transparency for certificates
// issued against owned domains that the inventory does not know —
// rogue/shadow certificates (W6-06, D-053/FR-P15).
package ctmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// CTEntry is one certificate observed in CT for a monitored domain.
type CTEntry struct {
	EntryID    string // source-scoped id (crt.sh row id)
	CommonName string
	DNSNames   []string
	Issuer     string
	Serial     string
	NotBefore  time.Time
	NotAfter   time.Time
}

// CTSource searches CT for certificates covering a domain. The shipping
// implementation queries the crt.sh aggregator (which indexes the public
// RFC 6962 logs); raw per-log get-sth/get-entries tailing is a future
// source behind this same seam.
type CTSource interface {
	Name() string
	Search(ctx context.Context, domain string) ([]CTEntry, error)
}

// Inventory answers "do we know this certificate?". Narrow on purpose so
// ctmonitor depends on nothing in bootstrap; the adapter over the
// certificate provider lives with the wiring.
type Inventory interface {
	HasSerial(ctx context.Context, serial string) (bool, error)
}

// Notifier receives NEW findings. ChannelNotifier adapts the W4-01
// delivery channels.
type Notifier interface {
	NotifyFinding(ctx context.Context, f Finding) error
}

// ChannelNotifier sends findings through a notifications/delivery
// Channel — the same channel types the W4-01 alerting stack uses.
type ChannelNotifier struct {
	Channel delivery.Channel
	Target  string
}

func (c *ChannelNotifier) NotifyFinding(ctx context.Context, f Finding) error {
	return c.Channel.Send(ctx, delivery.Event{
		ID:      "ct-" + f.ID,
		Channel: c.Channel.Name(),
		Target:  c.Target,
		Subject: fmt.Sprintf("Rogue certificate detected for %s", f.Domain),
		Message: fmt.Sprintf("CT log entry %s: %q (SANs %v) issued by %q, serial %s, valid until %s — this certificate is NOT in the Kryptkeeper inventory.",
			f.ID, f.CommonName, f.DNSNames, f.Issuer, f.Serial, f.NotAfter.Format(time.RFC3339)),
		Priority:  "high",
		CreatedAt: time.Now().UTC(),
	})
}

// crtshSource queries the crt.sh JSON API.
type crtshSource struct {
	base   string
	client *http.Client
}

// NewCrtShSource returns the default CT source. base "" = https://crt.sh.
func NewCrtShSource(base string) CTSource {
	if base == "" {
		base = "https://crt.sh"
	}
	return &crtshSource{base: base, client: &http.Client{Timeout: 30 * time.Second}}
}

func (s *crtshSource) Name() string { return "crtsh" }

// crtshRow is crt.sh's JSON row shape.
type crtshRow struct {
	ID           int64  `json:"id"`
	IssuerName   string `json:"issuer_name"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"` // newline-separated SANs
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

func (s *crtshSource) Search(ctx context.Context, domain string) ([]CTEntry, error) {
	u := fmt.Sprintf("%s/?q=%s&output=json", s.base, url.QueryEscape("%."+domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh query for %s: %w", domain, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh query for %s: HTTP %d", domain, resp.StatusCode)
	}
	var rows []crtshRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("crt.sh response for %s: %w", domain, err)
	}
	entries := make([]CTEntry, 0, len(rows))
	for _, row := range rows {
		e := CTEntry{
			EntryID:    fmt.Sprintf("%d", row.ID),
			CommonName: row.CommonName,
			Issuer:     row.IssuerName,
			Serial:     strings.ToLower(row.SerialNumber),
		}
		for _, n := range strings.Split(row.NameValue, "\n") {
			if n = strings.TrimSpace(n); n != "" {
				e.DNSNames = append(e.DNSNames, n)
			}
		}
		// crt.sh timestamps: "2026-01-02T15:04:05" (no zone).
		if t, err := time.Parse("2006-01-02T15:04:05", row.NotBefore); err == nil {
			e.NotBefore = t.UTC()
		}
		if t, err := time.Parse("2006-01-02T15:04:05", row.NotAfter); err == nil {
			e.NotAfter = t.UTC()
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ScanReport is one scan's outcome.
type ScanReport struct {
	Domains     int
	Entries     int
	NewFindings []string
	Errors      map[string]string
}

// Monitor ties source, inventory, store and notifier together.
type Monitor struct {
	source    CTSource
	inventory Inventory
	store     *Store
	notifier  Notifier
	domains   []string
	now       func() time.Time
}

func NewMonitor(source CTSource, inventory Inventory, store *Store, notifier Notifier, domains []string) (*Monitor, error) {
	if source == nil || inventory == nil || store == nil {
		return nil, fmt.Errorf("ct monitor requires a source, an inventory and a store")
	}
	return &Monitor{source: source, inventory: inventory, store: store, notifier: notifier, domains: domains, now: time.Now}, nil
}

// NewMonitorFromEnv reads KRYPTKEEPER_CT_DOMAINS (CSV); nil when unset —
// CT monitoring is opt-in.
func NewMonitorFromEnv(inventory Inventory, store *Store, notifier Notifier) *Monitor {
	var domains []string
	for _, d := range strings.Split(os.Getenv("KRYPTKEEPER_CT_DOMAINS"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		return nil
	}
	m, err := NewMonitor(NewCrtShSource(""), inventory, store, notifier, domains)
	if err != nil {
		log.Printf("ct monitor disabled: %v", err)
		return nil
	}
	return m
}

// Scan sweeps every configured domain once. A CT entry whose serial the
// inventory does not know becomes a persisted finding; only NEW findings
// notify. Expired entries are skipped — the attack surface is live
// certs. Per-domain errors are reported, never fatal to the sweep.
func (m *Monitor) Scan(ctx context.Context) (ScanReport, error) {
	report := ScanReport{Domains: len(m.domains), Errors: map[string]string{}}
	for _, domain := range m.domains {
		entries, err := m.source.Search(ctx, domain)
		if err != nil {
			report.Errors[domain] = err.Error()
			continue
		}
		report.Entries += len(entries)
		for _, e := range entries {
			if !e.NotAfter.IsZero() && e.NotAfter.Before(m.now()) {
				continue
			}
			known, err := m.inventory.HasSerial(ctx, e.Serial)
			if err != nil {
				report.Errors[domain] = fmt.Sprintf("inventory check: %v", err)
				break
			}
			if known {
				continue
			}
			finding := Finding{
				ID:         m.source.Name() + ":" + e.EntryID,
				Domain:     domain,
				CommonName: e.CommonName,
				DNSNames:   e.DNSNames,
				Issuer:     e.Issuer,
				Serial:     e.Serial,
				NotBefore:  e.NotBefore,
				NotAfter:   e.NotAfter,
				Source:     m.source.Name(),
			}
			created, err := m.store.Record(ctx, finding)
			if err != nil {
				report.Errors[domain] = err.Error()
				continue
			}
			if !created {
				continue // already raised — never re-alert
			}
			report.NewFindings = append(report.NewFindings, finding.ID)
			if m.notifier != nil {
				if err := m.notifier.NotifyFinding(ctx, finding); err != nil {
					// Recorded, never silently dropped — but a broken
					// channel must not stop detection.
					report.Errors["notify:"+finding.ID] = err.Error()
				}
			}
		}
	}
	return report, nil
}

// Start runs Scan every interval until ctx ends.
func (m *Monitor) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	log.Printf("ct monitor: every %s — %d domain(s) via %s", interval, len(m.domains), m.source.Name())
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				report, err := m.Scan(ctx)
				if err != nil {
					log.Printf("ct monitor scan failed: %v", err)
					continue
				}
				if len(report.NewFindings) > 0 || len(report.Errors) > 0 {
					log.Printf("ct monitor: %d new finding(s), errors=%v", len(report.NewFindings), report.Errors)
				}
			}
		}
	}()
}
