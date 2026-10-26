// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"net/http"

	"kryptkeeper/internal/keystore"
)

// readinessProbeFromDependencies builds a ReadinessProbe (W10-02/G-37) from
// dependencies RegisterHandlers already has, rather than threading a new raw
// *sql.DB parameter through Run/RunWithProtocols/RegisterHandlers just for
// this check — certSummaryProvider.LoadSummary already round-trips the
// configured storage backend (DB-backed when APP_CERTS_SUMMARY_PROVIDER=db,
// a cheap file read otherwise), matching this codebase's existing
// provider-abstraction convention instead of a DB-specific one. keys is
// checked the same way whenever it's non-nil (APP_CERTIFICATE_PROVIDER=ca).
func readinessProbeFromDependencies(certSummaryProvider CertSummaryProvider, keys keystore.Store) ReadinessProbe {
	return func(ctx context.Context) error {
		if _, err := certSummaryProvider.LoadSummary(ctx); err != nil {
			return fmt.Errorf("cert summary storage unreachable: %w", err)
		}
		if keys != nil {
			if _, err := keys.List(); err != nil {
				return fmt.Errorf("keystore unreachable: %w", err)
			}
		}
		return nil
	}
}

// RegisterKeyHandlers wires the key management API if a keystore is available.
// Called separately from RegisterHandlers so the keystore dependency stays
// optional. keyBackend identifies which keystore.Store backend `store` is
// (W19-19: injected here, not held as package-level state, so the raw
// key-generate handler can refuse ML-DSA/hybrid on hardware backends
// citing docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md).
func RegisterKeyHandlers(mux *http.ServeMux, auth *Authenticator, store keystore.Store, auditProvider AuditProvider, keyBackend string) {
	registerKeyHandlers(mux, auth, store, auditProvider, keyBackend)
	registerKeyEscrowHandlers(mux, auth, store, auditProvider)
}

// RegisterHandlers wires the hub's main API surface. keys (the keystore
// backing key generation/signing) is optional and may be nil -- it is only
// nil when APP_CERTIFICATE_PROVIDER != "ca" (no crypto engine active), and
// no handler registered here requires it today; it is threaded through so a
// future handler group (e.g. PQC migrate-wave EXECUTE, W4-03) can generate
// fresh keys without a second, duplicate keystore-construction path.
func RegisterHandlers(mux *http.ServeMux, auth *Authenticator, certSummaryProvider CertSummaryProvider, auditProvider AuditProvider, caProvider CAProvider, templateProvider TemplateProvider, certificateProvider CertificateProvider, protocolProvider ProtocolProvider, discoveryProvider DiscoveryProvider, notificationProvider NotificationProvider, dashboardActionProvider DashboardActionProvider, keys keystore.Store) {
	registerHandlers(&ServerConfig{Mux: mux}, auth, certSummaryProvider, auditProvider, caProvider, templateProvider, certificateProvider, protocolProvider, discoveryProvider, notificationProvider, dashboardActionProvider, keys)
}

// registerHandlers is RegisterHandlers with the options' configuration:
// pending-action executors and the delivery plugin manager (W20-20).
func registerHandlers(cfg *ServerConfig, auth *Authenticator, certSummaryProvider CertSummaryProvider, auditProvider AuditProvider, caProvider CAProvider, templateProvider TemplateProvider, certificateProvider CertificateProvider, protocolProvider ProtocolProvider, discoveryProvider DiscoveryProvider, notificationProvider NotificationProvider, dashboardActionProvider DashboardActionProvider, keys keystore.Store) {
	mux := cfg.Mux
	if auth == nil {
		panic("auth must not be nil")
	}
	if certSummaryProvider == nil {
		panic("certSummaryProvider must not be nil")
	}
	if auditProvider == nil {
		panic("auditProvider must not be nil")
	}
	if caProvider == nil {
		panic("caProvider must not be nil")
	}
	if templateProvider == nil {
		panic("templateProvider must not be nil")
	}
	if certificateProvider == nil {
		panic("certificateProvider must not be nil")
	}
	if protocolProvider == nil {
		panic("protocolProvider must not be nil")
	}
	if discoveryProvider == nil {
		panic("discoveryProvider must not be nil")
	}
	if notificationProvider == nil {
		panic("notificationProvider must not be nil")
	}
	if dashboardActionProvider == nil {
		panic("dashboardActionProvider must not be nil")
	}

	// FB-06: the router main wrapped the audit provider with; the fallback
	// serves callers (tests) that did not supply one.
	siemRouter := cfg.siem
	if siemRouter == nil {
		siemRouter = NewSIEMRouterFromEnv()
	}

	approvalStore, _ := newApprovalStoreFromEnv()
	approvalStore = withApprovalPendingNotifier(approvalStore, notificationProvider) // W32-26
	postureSnapshotStore, _ := NewPostureSnapshotStoreFromEnv()
	// eventBus is process-local, in-memory state constructed here rather
	// than threaded in as a RegisterHandlers parameter (CLAUDE.md: no new
	// global state) -- it follows the same in-func construction pattern as
	// approvalStore/tenantStore above so RegisterHandlers' exported
	// signature, which server.go (outside this ticket's write_scope) calls
	// directly, does not need to change.
	roleStore := NewCustomRoleStoreFromEnv()
	auth.roleStore = roleStore
	eventBus := NewEventBus(sseMaxStreamsPerPrincipalFromEnv())

	baseReady := readinessProbeFromDependencies(certSummaryProvider, keys)
	registerMetaHandlers(mux, withDrainProbe(cfg.draining, func(ctx context.Context) error {
		if err := baseReady(ctx); err != nil {
			return err
		}
		if err := auth.requiredStoresReady(); err != nil {
			return fmt.Errorf("required store down: %w", err)
		}
		for _, p := range cfg.extraReadiness {
			if err := p(ctx); err != nil {
				return err
			}
		}
		return nil
	}))
	registerOpenAPIHandlers(mux)
	registerAuthHandlers(mux, auth, auditProvider)
	registerProtocolHandlers(mux, auth, protocolProvider, auditProvider)
	registerSSEHandlers(mux, auth, eventBus, auditProvider, sseConfigFromEnv())
	registerDiscoveryHandlers(mux, auth, discoveryProvider, eventBus, auditProvider)
	// W6-05: the always-current CycloneDX CBOM export.
	RegisterCBOMHandlers(mux, auth, certificateProvider, keys, discoveryProvider, auditProvider)
	registerNotificationHandlersWithPlugins(mux, auth, notificationProvider, auditProvider, newITSMConnectionVisible(cfg.itsm),
		newPluginChannelTarget(NewPluginNotifyChannel(func() *DeliveryPluginManager { return cfg.plugins }, nil)),
		newSilenceTargetVisible(certificateProvider, caProvider, templateProvider))
	registerOwnerlessHandler(mux, auth, certificateProvider, auditProvider) // W32-30
	registerDashboardHandlers(mux, auth, certSummaryProvider, discoveryProvider, notificationProvider, dashboardActionProvider, auditProvider)
	registerAuditHandlers(mux, auth, roleStore, auditProvider, auditNameSources{
		certs: certificateProvider, cas: caProvider, templates: templateProvider,
		approvals: approvalStore, notifs: notificationProvider, discovery: discoveryProvider,
	})
	tenantStore := NewTenantStoreFromEnv()
	setActiveTenantStore(tenantStore)
	registerCAHandlers(mux, auth, caProvider, tenantStore, auditProvider)
	registerTenantHandlers(mux, auth, tenantStore, auditProvider)
	managedTargetStore := newManagedTargetStoreFromEnv()
	RegisterTargetHandlers(mux, auth, managedTargetStore, tenantStore, auditProvider, newOutboundCredentialStoreFromEnv(), cfg.plugins)
	// W27-02: explicit cert-to-target bindings drive auto-renew.
	RegisterCertTargetBindingHandlers(mux, auth, managedTargetStore, certificateProvider, newCertTargetBindingStoreFromEnv(), auditProvider)
	// W27-04: fleet-level renewal thresholds by target group.
	RegisterTargetGroupHandlers(mux, auth, managedTargetStore, newTargetGroupStoreFromEnv(), auditProvider)
	// W24-19: CT findings triage API.
	RegisterCTFindingsHandlers(mux, auth, newCTStoreFromEnv(), caProvider, auditProvider)
	// W18-12: give the discovery provider its WinRM runner, so a "winrm"
	// scan of a managed target reaches the host with its stored credential.
	if s, ok := discoveryProvider.(winRMScanSetter); ok {
		s.SetWinRMScanner(newWinRMTargetScanner(managedTargetStore, newOutboundCredentialStoreFromEnv(), liveWinRMEnumerator))
	}
	// W24-08: and its SSH runner, for "ssh" scans of ssh-mode managed targets.
	if s, ok := discoveryProvider.(sshScanSetter); ok {
		s.SetSSHScanner(newSSHTargetScanner(managedTargetStore, newOutboundCredentialStoreFromEnv(), auditProvider, liveSSHDial))
	}
	// Discovered chains are classified against this hub's own CAs, so the
	// scan store needs to read them through the CA provider.
	if s, ok := discoveryProvider.(hubCASetter); ok {
		s.SetHubCASource(hubCAsFromProvider(caProvider))
	}
	// W24-06: scan-to-scan certificate changes go out through the notification provider.
	if s, ok := discoveryProvider.(scanDiffNotifierSetter); ok {
		s.SetScanDiffNotifier(newProviderScanDiffNotifier(notificationProvider, auditProvider))
	}
	// W5-13: hub-side renewal execution — key/CSR hub-side, renew, SSH install.
	registerRenewalExecuteHandler(mux, auth, certificateProvider, managedTargetStore, newOutboundCredentialStoreFromEnv(), auditProvider, cfg.plugins, notificationProvider)
	registerTemplateHandlers(mux, auth, templateProvider, auditProvider, approvalStore)
	if activeTeamEnforcer != nil {
		activeTeamEnforcer.templates = templateProvider // W33-21
	}
	registerCertificateHandlers(mux, auth, certificateProvider, auditProvider, approvalStore)
	registerCertificateOBOHandlers(mux, auth, auditProvider, approvalStore) // W33-23
	registerBulkHandlers(mux, auth, certificateProvider, auditProvider)
	// W11-02: bulk import — a cert pile becomes a risk-scored estate in one call.
	RegisterBulkImportHandler(mux, auth, certificateProvider, auditProvider)
	// W11-03/W11-04: issuer connectors + the estate takeover API.
	connectorStore := newConnectorStoreFromEnv()
	connectorCreds := newOutboundCredentialStoreFromEnv()
	registerConnectorHandlers(mux, auth, connectorStore, certificateProvider, connectorCreds, auditProvider, caProvider)
	// W36-02: external CAs sign through these connectors.
	registerExternalCAHandlers(mux, auth, caProvider, connectorStore, connectorCreds, tenantStore, auditProvider)
	wireExternalCA(caProvider, certificateProvider, connectorStore, connectorCreds, tenantStore, auditProvider)
	RegisterEstateHandlers(mux, auth, certificateProvider, connectorStore, auditProvider)
	// W11-05: direct-CA inventory sources (ADCS export, DigiCert).
	RegisterInventorySourceHandlers(mux, auth, newInventorySourceStoreFromEnv(), certificateProvider, newOutboundCredentialStoreFromEnv(), auditProvider)
	registerApprovalHandlers(mux, auth, approvalStore, certificateProvider, templateProvider, auditProvider)
	registerSearchHandlers(mux, auth, certificateProvider, caProvider, templateProvider, discoveryProvider, auditProvider)
	registerProtectedHandlers(mux, auth, certSummaryProvider, auditProvider)
	// Reuse auth.userProvider (set by NewAuthenticatorFromEnv, auth_config.go)
	// rather than minting a third, disconnected NewUserProviderFromEnv()
	// instance -- same fix and same reason as registerAuthHandlers
	// (handlers_auth.go): AuthenticatePrincipalDetails/Refresh enforce
	// deprovisioning against auth.userProvider, so the admin console's DELETE
	// /api/v1/users/{id} (handlers_users.go, DeactivateUser) must write to
	// that same store or deactivation revokes nothing in the default
	// (non-DB) in-memory configuration. APP_USER_PROVIDER=db is unaffected
	// either way since all instances read/write the same physical tables.
	userProvider := auth.userProvider
	if userProvider == nil {
		userProvider = NewUserProviderFromEnv()
	}
	registerUserHandlers(mux, auth, userProvider, roleStore, auditProvider)
	registerIntegrationsHandlers(mux, auth, auditProvider, siemRouter, cfg.scepOffReason)
	configStore := newConfigStoreFromEnv()
	registerConfigHandlers(mux, auth, configStore, auditProvider)
	registerDemoStatusHandler(mux, auth, configStore)
	registerUserPrefsHandlers(mux, auth, newUserPrefsStoreFromEnv(), auditProvider)
	registerReportsHandlers(mux, auth, certificateProvider, caProvider, templateProvider, keys, auditProvider)
	registerPostureTrendHandler(mux, auth, postureSnapshotStore, auditProvider)
	registerSchedulerStatusHandler(mux, auth, auditProvider)
	registerCodeSigningHandler(mux, auth, certificateProvider, auditProvider)
	initCodesignAttestation(approvalStore, auditProvider)
	registerCodeSigningIssueHandler(mux, auth, certificateProvider, templateProvider, approvalStore, keys, auditProvider)
	// W17-03: unified cloud KMS key inventory — the PQC denominator for
	// KEYS, completing the cert-side inventory story.
	registerKeyInventoryHandler(mux, auth, roleStore, auditProvider, discoveryProvider)
	// W17-04: RFC 6962 transparency surface over the audit trail — a plain
	// log proves nothing to anyone who can edit the rows.
	registerAuditTrustHandlers(mux, auth, roleStore, auditProvider)
	// W17-05: what-breaks-if pre-flight over the live inventory.
	registerBlastRadiusHandler(mux, auth, certificateProvider, caProvider, auditProvider)
	// W17-06: crypto-agility roadmap — PQC is one instance of the
	// transition pattern, not a special case.
	WarnIfKeyDualControlDisabled()
	registerAgilityHandler(mux, auth, certificateProvider, auditProvider)
	// W17-07: cluster-atomic rollout — ONE renewal pushed to every node.
	registerRolloutHandler(mux, auth, certificateProvider, managedTargetStore, newOutboundCredentialStoreFromEnv(), auditProvider, cfg.plugins)
	agentStore := NewAgentStoreFromEnv()
	// W24-15: out-of-band replacements and silent agents go out via the scan-diff notifier.
	if s, ok := agentStore.(agentChangeSinkSetter); ok {
		s.SetAgentChangeSink(agentChangeSinkFrom(newProviderScanDiffNotifier(notificationProvider, auditProvider)))
	}
	auth.requireStore(agentStore)
	agentRoutes := gateRoutes(mux, agentStore)
	registerAgentHandlers(agentRoutes, auth, agentStore, auditProvider)
	// W40-03: trust bundles; registers its approval executor, so it runs before the queue.
	registerTrustBundleHandlers(cfg, mux, agentRoutes, auth, agentStore, NewTrustBundleStoreFromEnv(), NewPendingActionStoreFromEnv(), certificateProvider, caProvider, auditProvider)
	registerRenewalSLOHandler(agentRoutes, auth, agentStore, certificateProvider, auditProvider)
	registerEvidenceHandlers(mux, auth, certificateProvider, caProvider, NewEvidenceScheduleStoreFromEnv(), NewEvidenceMailerFromEnv(), auditProvider)
	RegisterComplianceAttestationHandlers(mux, auth, NewComplianceAttestationStoreFromEnv(), auditProvider)
	RegisterReportScheduleHandlers(mux, auth, NewReportScheduleStoreFromEnv(), auditProvider)
	// W24-38: template migration; registers its approval executor, so it runs before the queue.
	registerMigrationHandlers(cfg, mux, auth, templateProvider, newOutboundCredentialStoreFromEnv(), NewPendingActionStoreFromEnv(), auditProvider)
	// v2.0: generalized approval queue for AI-proposed (and other) writes.
	registerPendingActionHandlers(mux, auth, certificateProvider, NewPendingActionStoreFromEnv(), auditProvider, cfg.actionExecutors, keys)
	// W20-20: community certificate delivery plugins.
	registerDeliveryPluginHandlers(mux, auth, cfg.plugins, auditProvider)
	// W38-11: install first-party plugins from the signed catalogue.
	registerPluginCatalogueHandlers(mux, auth, cfg.plugins, auditProvider)
	// v2.1: SPIFFE SVID mint + trust bundle (enabled when a CA engine + trust domain are set).
	registerSPIFFEHandlers(mux, auth, caProvider, auditProvider)
	// W7-01: workload attestation (join-token) extending the SVID mint.
	// W7-02 shares the SAME registry so approved NHI join tokens redeem
	// against the registry the SVID endpoint consults.
	workloadRegistry := NewWorkloadRegistry()
	registerSPIFFEWorkloadHandlers(mux, auth, workloadRegistry, auditProvider)
	registerNHIHandlers(mux, auth, NewNHIStoreFromEnv(), workloadRegistry, auditProvider)
	// W7-05: CSV/XLSX report export over the same visibility path as
	// every other report.
	registerReportExportHandlers(mux, auth, certificateProvider, auditProvider)
	// W12-06: custom-roles admin API over the W6-08 store.
	registerCustomRoleHandlers(mux, auth, roleStore, auditProvider)
	// W15-02: key-custody evidence report (keystore backend + rotation/
	// access from the audit trail).
	registerKeyCustodyHandler(mux, auth, keys, managedTargetStore, auditProvider, NewPendingActionStoreFromEnv())
	// W17-08: leaf-escrow ceremonies (per-tenant opt-in, off by default).
	registerKeyCustodyOpsHandlers(mux, auth, keys, auditProvider)
	// W17-12: BYOK export of an escrow-recovered root into a customer KMS.
	registerBYOKHandlers(mux, auth, auditProvider)
	// W17-09: the gRPC Workload API and the operator API MUST share one
	// SelectorRegistry — a listener nobody can register against serves
	// nothing, and bindings with no listener attest nothing.
	selectorRegistry := NewSelectorRegistry()
	registerWorkloadSelectorHandlers(mux, auth, selectorRegistry, auditProvider)
	startWorkloadAPIIfConfigured(selectorRegistry, auditProvider)
	// W17-10: AD directory sync, now that adsync has a real LDAP client.
	registerADSyncHandlers(mux, auth, newOutboundCredentialStoreFromEnv(), auditProvider)
	// Credentials CRUD: the store existed since W5-10 but nothing could
	// CREATE one outside tests, which dead-ended every credential_ref
	// consumer (push installs, adcs_live, AD sync) for real deployments.
	registerCredentialHandlers(mux, auth, newOutboundCredentialStoreFromEnv(), auditProvider, ProductionWinRMPreflighter)
	// W38-07: where external credentials fetch their secrets from.
	registerCredentialSourceHandlers(mux, auth, newCredentialSourceStoreFromEnv(), newOutboundCredentialStoreFromEnv(), auditProvider, cfg.plugins)
	// W32-10: ITSM connections and ticket-link queue.
	registerITSMHandlers(mux, auth, cfg.itsm, newOutboundCredentialStoreFromEnv(), auditProvider,
		newITSMPluginCheck(NewITSMPluginConnectors(func() *DeliveryPluginManager { return cfg.plugins }, nil)))
	// W32-12: approve via ITSM ticket; maps external approvers to hub users.
	registerITSMApprovalHandlers(mux, auth, cfg.itsm, auditProvider)
}
