// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/notifications/itsm"
	"kryptkeeper/internal/notifications/itsm/servicenow"
)

// cmdbSyncActor is the audit actor of the daily CMDB ownership sync (W32-13).
const cmdbSyncActor = "cmdb-sync"

// cmdbOwnershipAdapter supplies the itsm.OwnershipWriter and itsm.AuditSink the
// CMDB sync job needs, over the certificate provider and audit trail.
type cmdbOwnershipAdapter struct {
	certs   CertificateProvider
	audit   AuditProvider
	tenants TenantStore // may be nil: audit rows then carry the default tenant

	mu   sync.Mutex
	caOf map[string]string // fingerprint -> CA id, from the last ListCertHosts
}

var (
	_ itsm.OwnershipWriter = (*cmdbOwnershipAdapter)(nil)
	_ itsm.AuditSink       = (*cmdbOwnershipAdapter)(nil)
)

// cmdbHost is the name the CMDB is asked about: the CN, else the first DNS SAN.
func cmdbHost(item CertificateItem) string {
	names := append([]string{item.CommonName}, item.SubjectAltNames...)
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && net.ParseIP(n) == nil {
			return n
		}
	}
	return ""
}

// ListCertHosts collects first and mutates later: UpdateOwnership takes the
// provider lock a ForEachCertificate pass must not hold.
func (a *cmdbOwnershipAdapter) ListCertHosts(ctx context.Context) ([]itsm.CertHost, error) {
	var out []itsm.CertHost
	caOf := map[string]string{}
	err := ForEachCertificate(ctx, a.certs, CertificateListQuery{}, func(item CertificateItem) error {
		host := cmdbHost(item)
		if host == "" || item.RevokedAt != nil {
			return nil
		}
		caOf[item.FingerprintSHA256] = item.CAID
		out = append(out, itsm.CertHost{
			Fingerprint: item.FingerprintSHA256, Host: host, OwnerTeam: item.OwnerTeam, OwnerEmail: item.OwnerEmail,
			OwnershipSource: item.OwnershipSource, ServiceName: item.ServiceName,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.caOf = caOf
	a.mu.Unlock()
	return out, nil
}

// SetCMDBOwnership is the only place the cmdb source is claimed: it is set by
// server code, never from a request body. ServiceName is carried through
// because UpdateOwnership overwrites it with the request value.
func (a *cmdbOwnershipAdapter) SetCMDBOwnership(ctx context.Context, fingerprint string, o itsm.CMDBOwner, serviceName string) error {
	_, err := a.certs.UpdateOwnership(ctx, fingerprint, CertificateOwnershipRequest{
		OwnerTeam: o.OwnerTeam, OwnerEmail: o.OwnerEmail, ServiceName: serviceName, Source: OwnershipSourceCMDB,
	})
	return err
}

// Record appends the audit row for one write.
func (a *cmdbOwnershipAdapter) Record(ctx context.Context, action, resourceID string, success bool, detail string) {
	if a.audit == nil {
		return
	}
	outcome := AuditOutcomeSuccess
	if !success {
		outcome = AuditOutcomeFailure
	}
	tenant := DefaultTenant
	if a.tenants != nil {
		a.mu.Lock()
		ca := a.caOf[resourceID]
		a.mu.Unlock()
		if t, err := a.tenants.CATenant(ctx, ca); err == nil && t != "" {
			tenant = t
		}
	}
	err := a.audit.AppendEntry(ctx, AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "system", ActorID: cmdbSyncActor,
		ResourceType: "certificate", ResourceID: resourceID, Outcome: outcome, Tenant: tenant, ChangeSummary: detail,
	})
	if err != nil {
		logging.Errorf("cmdb sync: audit append failed action=%s id=%s: %v", action, resourceID, err)
	}
}

// cmdbSourceFromITSM resolves the first enabled ServiceNow connection at use
// time (it may be configured after start) and builds a connector from its
// stored credential. No such connection means nil, nil: the pass is skipped.
func cmdbSourceFromITSM(store *itsm.Store, creds itsm.CredentialResolver) func(context.Context) (itsm.CMDBSource, error) {
	return func(ctx context.Context) (itsm.CMDBSource, error) {
		conns, err := store.ListConnections(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range conns {
			if c.Kind != "servicenow" || !c.Enabled {
				continue
			}
			secret, err := creds.Resolve(ctx, c.CredentialRef)
			if err != nil {
				return nil, errors.New("resolving servicenow credential " + c.CredentialRef + ": " + err.Error())
			}
			conn, err := servicenow.Factory(c.BaseURL, secret, itsm.NewHTTPClient())
			if err != nil {
				return nil, err
			}
			src, ok := conn.(itsm.CMDBSource)
			if !ok {
				return nil, errors.New("servicenow connector has no CMDB lookup")
			}
			return src, nil
		}
		return nil, nil
	}
}

// StartCMDBSync starts the daily CMDB ownership sync. A nil ITSM store (no
// core database) or certificate provider means no job.
func StartCMDBSync(ctx context.Context, svc *itsm.Service, certs CertificateProvider, audit AuditProvider) {
	if svc == nil || certs == nil {
		return
	}
	ad := &cmdbOwnershipAdapter{certs: certs, audit: audit, tenants: NewTenantStoreFromEnv()}
	(&itsm.CMDBSyncJob{
		SourceFn: cmdbSourceFromITSM(svc.Store(), ITSMCredentialResolverFromEnv()),
		Writer:   ad,
		Audit:    ad,
	}).Start(ctx)
}
