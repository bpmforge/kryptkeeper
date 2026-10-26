// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"kryptkeeper/internal/logging"
	"time"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/notifications/delivery"
	"kryptkeeper/internal/notifications/itsm"
	"kryptkeeper/internal/notifications/itsm/jira"
	"kryptkeeper/internal/notifications/itsm/servicenow"
)

// itsmDrainInterval is how often due tickets and retries are processed.
const itsmDrainInterval = 60 * time.Second

// newITSMService builds the process's one ITSM service (W32-10) and starts
// its drain loop. No core database means no service: the API then answers 503
// and the "itsm" delivery channel is not registered.
//
// Connectors register by kind in the factories map; W32-11 (servicenow) and
// W32-14 (jira) add theirs; a "plugin" connection is built by the ticket plugin
// factory (W38-09) from the plugin manager. A connection whose kind has no factory keeps its
// events queued rather than losing them.
func newITSMService(coreDB *sql.DB, isPostgres bool, audit bootstrap.AuditProvider, plugins *bootstrap.DeliveryPluginManager) *itsm.Service {
	if coreDB == nil {
		return nil
	}
	store := itsm.NewStore(coreDB, isPostgres)
	factories := map[string]itsm.Factory{"servicenow": servicenow.Factory, "jira": jira.Factory}
	svc := itsm.NewService(itsm.Config{
		Store: store,
		Conns: itsm.NewConnectorSource(store, bootstrap.ITSMCredentialResolverFromEnv(), itsm.NewHTTPClient(), factories,
			bootstrap.NewITSMPluginConnectors(func() *bootstrap.DeliveryPluginManager { return plugins }, audit).Factory()),
		Audit: bootstrap.ITSMAuditSink(audit),
		Alert: func(_ context.Context, class, detail string) { logging.Warnf("ALERT itsm: %s %s", class, detail) },
	})
	go svc.Run(context.Background(), itsmDrainInterval, logging.Infof)
	bootstrap.SetRenewalVerifiedHook(itsmRenewalResolver(svc, itsmResolveTimeout))
	logging.Infof("itsm: on (/api/v1/itsm; drain every %s)", itsmDrainInterval)
	return svc
}

// itsmResolveTimeout bounds one auto-resolve pass (connector calls included).
const itsmResolveTimeout = 2 * time.Minute

// itsmRenewalResolver closes the tickets of a certificate whose replacement
// was installed and verified (W32-26). It runs off the renewal path and
// outlives the caller's context, so a slow ITSM never stalls a renewal and a
// finished request does not cancel the resolve.
func itsmRenewalResolver(svc *itsm.Service, timeout time.Duration) bootstrap.RenewalVerifiedFunc {
	return func(ctx context.Context, predecessor, successor string) {
		ctx = context.WithoutCancel(ctx)
		go func() {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			resolveRenewed(ctx, svc, predecessor, successor)
		}()
	}
}

func resolveRenewed(ctx context.Context, svc *itsm.Service, predecessor, successor string) {
	n, err := svc.ResolveByFingerprint(ctx, predecessor, "Certificate replaced and verified by Kryptkeeper (new fingerprint "+successor+")")
	if err != nil {
		logging.Warnf("itsm: auto-resolve for %s: %v", predecessor, err)
	}
	if n > 0 {
		logging.Infof("itsm: auto-resolved %d ticket(s) for renewed certificate %s", n, predecessor)
	}
}

// itsmChannels returns the "itsm" delivery channel, or none when ITSM is off.
func itsmChannels(svc *itsm.Service) []delivery.Channel {
	if svc == nil {
		return nil
	}
	return []delivery.Channel{itsm.Channel{Svc: svc}}
}
