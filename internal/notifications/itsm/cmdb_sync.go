// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W32-13: a daily job copies certificate ownership from CMDB CIs. This package
// cannot import internal/bootstrap (cycle), so the job names the three things
// it needs and bootstrap supplies adapters.

const (
	defaultCMDBSyncInterval = 24 * time.Hour
	actionOwnershipUpdate   = "certificate.ownership_update"
	cmdbSourceName          = "cmdb"
)

// CMDBOwner is the owner a CI records: owned_by email and support group.
type CMDBOwner struct{ OwnerEmail, OwnerTeam string }

// CMDBSource looks a host up in the CMDB.
type CMDBSource interface {
	LookupOwner(ctx context.Context, host string) (CMDBOwner, bool, error) // false = no CI or no owner
}

// CertHost is one certificate and the host the CMDB is asked about.
type CertHost struct {
	Fingerprint, Host, OwnerTeam, OwnerEmail, OwnershipSource, ServiceName string
}

// OwnershipWriter reads and writes certificate ownership. Writes must record
// the source as cmdb: only server code may claim that provenance.
type OwnershipWriter interface {
	ListCertHosts(ctx context.Context) ([]CertHost, error) // non-revoked, tenant-unscoped (system job)
	SetCMDBOwnership(ctx context.Context, fingerprint string, o CMDBOwner, serviceName string) error
}

// AuditSink records one ownership write.
type AuditSink interface {
	Record(ctx context.Context, action, resourceID string, success bool, detail string)
}

// SyncReport summarises one pass. NotFound hosts are reported, not errors.
type SyncReport struct {
	Hosts, Updated, SkippedManual, SkippedOther, Unchanged int
	NotFound                                               []string
	Errors                                                 int
}

// CMDBSyncJob writes CMDB ownership onto certificates, never over a person's
// choice. SourceFn, when set, resolves the source per pass (the connection may
// be configured after start); a nil source skips the pass.
type CMDBSyncJob struct {
	Source   CMDBSource
	SourceFn func(ctx context.Context) (CMDBSource, error)
	Writer   OwnershipWriter
	Audit    AuditSink
	Interval time.Duration // default 24h
	Now      func() time.Time
}

// overwriteClass mirrors bootstrap.cmdbOverwriteClass: "" is free to assign
// (unowned or a previous cmdb value); an owner with no recorded source predates
// ownership_source and counts as manual.
func overwriteClass(h CertHost) string {
	switch h.OwnershipSource {
	case "", cmdbSourceName:
		if h.OwnershipSource == "" && h.OwnerTeam != "" {
			return "manual"
		}
		return ""
	case "manual":
		return "manual"
	}
	return "other"
}

// RunOnce makes one pass; a failure on one host never aborts the others.
func (j *CMDBSyncJob) RunOnce(ctx context.Context) (SyncReport, error) {
	rep := SyncReport{NotFound: []string{}}
	src := j.Source
	if j.SourceFn != nil {
		s, err := j.SourceFn(ctx)
		if err != nil {
			return rep, err
		}
		src = s
	}
	if src == nil {
		return rep, nil
	}
	hosts, err := j.Writer.ListCertHosts(ctx)
	if err != nil {
		return rep, err
	}
	rep.Hosts = len(hosts)
	for _, h := range hosts {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		switch overwriteClass(h) {
		case "manual":
			rep.SkippedManual++
			continue
		case "other":
			rep.SkippedOther++
			continue
		}
		owner, found, err := src.LookupOwner(ctx, strings.ToLower(h.Host))
		if err != nil {
			rep.Errors++
			logging.Warnf("cmdb sync: lookup %s: %v", h.Host, err)
			continue
		}
		if found {
			if owner.OwnerTeam == "" {
				owner.OwnerTeam = h.OwnerTeam // an empty team would clear ownership
			}
			if owner.OwnerEmail == "" {
				owner.OwnerEmail = h.OwnerEmail
			}
			found = owner.OwnerTeam != ""
		}
		if !found {
			rep.NotFound = append(rep.NotFound, h.Host)
			continue
		}
		if h.OwnershipSource == cmdbSourceName && owner.OwnerTeam == h.OwnerTeam && owner.OwnerEmail == h.OwnerEmail {
			rep.Unchanged++
			continue
		}
		detail, _ := json.Marshal(map[string]string{
			"owner_email": owner.OwnerEmail, "owner_team": owner.OwnerTeam,
			"service_name": h.ServiceName, "ownership_source": cmdbSourceName,
		})
		if err := j.Writer.SetCMDBOwnership(ctx, h.Fingerprint, owner, h.ServiceName); err != nil {
			rep.Errors++
			logging.Warnf("cmdb sync: write %s: %v", h.Fingerprint, err)
			j.record(ctx, h.Fingerprint, false, string(detail))
			continue
		}
		rep.Updated++
		j.record(ctx, h.Fingerprint, true, string(detail))
	}
	return rep, nil
}

func (j *CMDBSyncJob) record(ctx context.Context, fp string, ok bool, detail string) {
	if j.Audit != nil {
		j.Audit.Record(ctx, actionOwnershipUpdate, fp, ok, detail)
	}
}

// Start runs immediately, then every Interval until ctx is done. Errors are
// logged; the loop never panics on a source failure.
func (j *CMDBSyncJob) Start(ctx context.Context) {
	interval := j.Interval
	if interval <= 0 {
		interval = defaultCMDBSyncInterval
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			rep, err := j.RunOnce(ctx)
			switch {
			case err != nil:
				logging.Warnf("cmdb sync: pass failed: %v", err)
			case rep.Updated > 0 || rep.Errors > 0 || len(rep.NotFound) > 0:
				logging.Infof("cmdb sync: hosts=%d updated=%d unchanged=%d not_found=%d skipped_manual=%d skipped_other=%d errors=%d",
					rep.Hosts, rep.Updated, rep.Unchanged, len(rep.NotFound), rep.SkippedManual, rep.SkippedOther, rep.Errors)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}
