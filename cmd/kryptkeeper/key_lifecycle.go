// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"kryptkeeper/internal/logging"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

const defaultKeyRotationSweepInterval = time.Hour

// keyLifecycleOption builds the per-key lifecycle manager (W23-38), publishes
// it for the key handlers' ACL checks, starts the max-age rotation sweep and
// returns the executors for the actions it proposes. The returned stop func is
// always non-nil.
//
// On Postgres the sweep is gated on the HA lease, so only the lease holder
// rotates; KRYPTKEEPER_KEY_ROTATION_SCHEDULER=false still switches it off on
// this replica outright. Overdue CA-backing keys are proposed, not rotated
// (dual control).
func keyLifecycleOption(keys keystore.Store, db *sql.DB, isPostgres bool, caStore ca.Store, caProvider bootstrap.CAProvider, certs bootstrap.CertificateProvider, audit bootstrap.AuditProvider, plugins *bootstrap.DeliveryPluginManager) (bootstrap.ServerOption, func()) {
	noop := func() {}
	if keys == nil || db == nil {
		logging.Info("key lifecycle disabled: needs the crypto engine and a core DB")
		return nil, noop
	}
	opts := []bootstrap.KeyLifecycleOption{
		bootstrap.WithLifecycleProposals(bootstrap.NewPendingActionStoreFromEnv()),
		bootstrap.WithLifecycleAlerts(lifecycleAlertSink(audit)),
	}
	if certs != nil {
		// W23-39: re-issue on each certificate's managed target through the
		// same executor the renewal sweep uses.
		executor := bootstrap.NewRenewalExecutorFromEnv(certs).WithPluginDeliverer(plugins, audit)
		reissuer := bootstrap.NewRenewalCertReissuer(certs, bootstrap.NewManagedTargetStoreFromEnv(), executor)
		opts = append(opts, bootstrap.WithLifecycleReissue(certs, reissuer), bootstrap.WithLifecycleRevoker(certs))
	}
	if rotator, ok := caProvider.(bootstrap.CARotator); ok && caStore != nil {
		opts = append(opts, bootstrap.WithLifecycleCARotation(rotator, caStore))
	}
	if isPostgres {
		// nil (no shared HA DB) degrades to sweeping unconditionally, as the
		// other schedulers do.
		if leader := bootstrap.NewHACoordinatorFromEnvLogged(); leader != nil {
			opts = append(opts, bootstrap.WithLifecycleLeader(leader))
		}
	}
	m, err := bootstrap.NewKeyLifecycleManager(db, isPostgres, keys, opts...)
	if err != nil {
		logging.Infof("key lifecycle disabled: %v", err)
		return nil, noop
	}
	bootstrap.SetActiveKeyLifecycle(m)

	stop := noop
	if strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_KEY_ROTATION_SCHEDULER")), "false") {
		logging.Info("key rotation sweep disabled by KRYPTKEEPER_KEY_ROTATION_SCHEDULER=false")
	} else {
		interval := defaultKeyRotationSweepInterval
		if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_KEY_ROTATION_SWEEP_INTERVAL")); raw != "" {
			if d, err := time.ParseDuration(raw); err == nil && d > 0 {
				interval = d
			} else {
				logging.Infof("ignoring KRYPTKEEPER_KEY_ROTATION_SWEEP_INTERVAL=%q: want a positive Go duration; using %s", raw, interval)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		m.StartRotationScheduler(ctx, interval)
		stop = cancel
		logging.Infof("key rotation sweep every %s", interval)
	}
	return func(c *bootstrap.ServerConfig) {
		bootstrap.WithActionExecutor(bootstrap.ActionKeyCompromise, bootstrap.NewKeyCompromiseExecutor(m, audit))(c)
		bootstrap.WithActionExecutor(bootstrap.ActionScheduledCAKeyRotate, bootstrap.NewScheduledCARotationExecutor(m))(c)
	}, stop
}

// lifecycleAlertSink records the compromise flow's alerts (key.compromised,
// key.reissue_deferred, key.reissue_failed) as "alert.<kind>" audit entries
// and logs them, so SIEM forwarding picks them up. The I01 notifier replaces
// this when it lands.
func lifecycleAlertSink(audit bootstrap.AuditProvider) func(context.Context, string, string, map[string]any) {
	return func(ctx context.Context, kind, keyID string, detail map[string]any) {
		summary, _ := json.Marshal(detail) // plain values: cannot fail
		outcome := bootstrap.AuditOutcomeSuccess
		switch kind {
		case "key.reissue_deferred":
			outcome = bootstrap.AuditOutcomeSkipped
		case "key.reissue_failed":
			outcome = bootstrap.AuditOutcomeFailure
		}
		logging.Infof("ALERT %s key=%s %s", kind, keyID, summary)
		if audit == nil {
			return
		}
		if err := audit.AppendEntry(context.WithoutCancel(ctx), bootstrap.AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "alert." + kind, ActorType: "system", ActorID: "key-lifecycle",
			ResourceType: "key", ResourceID: keyID, Outcome: outcome, ChangeSummary: string(summary),
		}); err != nil {
			logging.Errorf("alert %s for %s: audit row not written: %v", kind, keyID, err)
		}
	}
}
