// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 required by RFC 6960 OCSP IssuerKeyHash
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/acme"
	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/cmp"
	"kryptkeeper/internal/crl"
	"kryptkeeper/internal/ctmonitor"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/est"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/metrics"
	"kryptkeeper/internal/notifications/delivery"
	"kryptkeeper/internal/ocsp"
	"kryptkeeper/internal/ratelimit"
	"kryptkeeper/internal/scep"
	"kryptkeeper/internal/wstep"
	"kryptkeeper/internal/xcep"
)

// version/commit/date are injected by .goreleaser.yaml's ldflags at release
// build time (W20-02); "dev"/"unknown" is what a plain `go build` or `go run`
// leaves in place. `kryptkeeper --version` prints all three; handlers_meta.go's
// GET /api/v1/meta (pre-existing, W1-05 era) reports version/commit only, via
// APP_VERSION/APP_COMMIT env vars main() seeds from these below -- until now
// those env vars were the only way that endpoint reported anything but "dev"
// (env.example documented them as manual, operator-set overrides).
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// W20-02: seed APP_VERSION/APP_COMMIT from the linker-injected build
	// stamp so GET /api/v1/meta (handlers_meta.go) reports the real release
	// version -- but never override an operator who already set these
	// explicitly (env.example documents both as optional overrides).
	if os.Getenv("APP_VERSION") == "" {
		os.Setenv("APP_VERSION", version)
	}
	if os.Getenv("APP_COMMIT") == "" {
		os.Setenv("APP_COMMIT", commit)
	}

	// S-42: databases that applied migration 000007 before it was gated are
	// carrying CI seed rows — a fake root CA, a fake certificate, two active
	// privileged users and an API key — which inflate inventory counts and
	// compliance reports. Removing them deletes a CA and a certificate, so it
	// is an explicit operator action, never something a boot decides.
	if len(os.Args) > 1 && os.Args[1] == "--remove-ci-seed" {
		removeCISeedAndExit()
	}
	if len(os.Args) > 1 && os.Args[1] == "--hash-password" {
		hashPasswordAndExit()
	}
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("kryptkeeper %s (commit %s, built %s)\n", version, commit, date)
		os.Exit(0)
	}

	certMode := strings.ToLower(strings.TrimSpace(os.Getenv("APP_CERTIFICATE_PROVIDER")))
	needsCrypto := certMode == "ca"

	// --- Core DB (shared by CA store, revocation store, and cert persistence) ---
	var coreDB *sql.DB
	var isPostgres bool
	if needsCrypto {
		var err error
		coreDB, isPostgres, err = bootstrap.OpenCoreDB()
		if fatal := bootstrap.CoreDBStartupDecision(certMode, err); fatal != nil {
			log.Fatal(fatal)
		}
	}

	// --- Crypto engine (only when APP_CERTIFICATE_PROVIDER=ca) ---
	var caEngine ca.Service
	var keys keystore.Store
	var defaultCAID string
	var revStore ca.RevocationStore
	// W19-19: declared at function scope (not `:=` inside the block below)
	// so it survives to the RunWithProtocols/Run call below, which injects
	// it into the raw keys handler instead of the handler reading
	// package-level state.
	var keyBackend string

	if needsCrypto {
		keystoreDir, keystoreWarn := bootstrap.ResolveKeystoreDir(os.Getenv)
		if keystoreWarn != "" {
			log.Print(keystoreWarn)
		}
		if err := bootstrap.EnsureWritableKeystoreDir(keystoreDir); err != nil {
			log.Fatalf("keystore directory %q unusable: %v (set KRYPTKEEPER_KEYSTORE_DIR to a writable path on a persistent volume, or put KRYPTKEEPER_DATA_DIR on one)", keystoreDir, err)
		}
		log.Printf("keystore directory: %s", keystoreDir)

		keyBackend = strings.ToLower(strings.TrimSpace(os.Getenv("KRYPTKEEPER_KEY_BACKEND")))

		// W9-11/NFR-011: under FIPS posture the CA role must not come up
		// on a non-HSM keystore at all — fatal, not a warning.
		if err := keystore.CheckRootKeyCustody(keyBackend); err != nil {
			log.Fatalf("FIPS posture: %v", err)
		}

		var err error
		switch keyBackend {
		case "pkcs11":
			keys, err = keystore.NewPKCS11StoreFromEnv()
			if err != nil {
				log.Fatalf("pkcs11 keystore init: %v", err)
			}
			log.Print("key backend: PKCS#11 (HSM)")
		case "vault":
			keys, err = keystore.NewVaultStoreFromEnv()
			if err != nil {
				log.Fatalf("vault keystore init: %v", err)
			}
			log.Print("key backend: HashiCorp Vault transit")
		case "cloudkms":
			// W9-02: previously dead code — no path ever constructed the
			// cloud KMS store, and its key references were memory-only.
			keys, err = buildCloudKMSStore(os.Getenv("KRYPTKEEPER_KMS_PROVIDER"), coreDB, isPostgres)
			if err != nil {
				log.Fatalf("cloud kms keystore init: %v", err)
			}
			log.Printf("key backend: cloud KMS (%s)", os.Getenv("KRYPTKEEPER_KMS_PROVIDER"))
		default:
			keystorePass := os.Getenv("KRYPTKEEPER_KEYSTORE_PASSPHRASE")
			if keystorePass == "" {
				log.Fatal("KRYPTKEEPER_KEYSTORE_PASSPHRASE is required when APP_CERTIFICATE_PROVIDER=ca")
			}
			if err := bootstrap.RejectPlaceholderSecret("KRYPTKEEPER_KEYSTORE_PASSPHRASE", keystorePass); err != nil {
				log.Fatal(err)
			}
			keys, err = keystore.NewSoftwareStore(keystoreDir, []byte(keystorePass))
			if err != nil {
				log.Fatalf("keystore init: %v", err)
			}
			log.Print("key backend: software (AES-GCM + Argon2id)")
		}

		// Choose CA store: DB-backed when available, in-memory otherwise.
		var caStore ca.Store
		if coreDB != nil {
			caStore = ca.NewDBStore(coreDB, isPostgres)
			revStore = ca.NewDBRevocationStore(coreDB, isPostgres)
			log.Print("CA store: database")
		} else {
			caStore = ca.NewMemStore()
			revStore = ca.NewMemRevocationStore()
			log.Print("CA store: in-memory (no DB)")
		}

		engine := ca.NewEngine(keys, caStore)
		// W19-08: tell the engine which keystore.Store backend `keys` is so
		// CA.KeyStorageType is truthful and PQC keygen is refused on
		// hardware/remote backends per docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md.
		if keyBackend != "" {
			engine.SetKeyBackend(keyBackend)
		}
		// W5-05: attach the data-driven issuance policy gate when the
		// core DB (and so the issuance_policies table) exists.
		if coreDB != nil {
			if err := attachPolicyEngine(engine, coreDB, isPostgres, os.Getenv); err != nil {
				log.Fatalf("startup: %v", err)
			}
		}
		caEngine = engine
		// W9-04/G-35: give the raw keystore key-rotate handler visibility
		// into which keys back a CA, so it can refuse rotating one directly
		// instead of silently breaking the CA.
		bootstrap.SetActiveCAStore(caStore)
		// v2.1: wire the CA engine for SPIFFE SVID issuance + trust bundle.
		bootstrap.SetSPIFFEEngine(caEngine)

		// G-78: catch the RotateCA crash-window residual -- a process crash
		// between keystore.Store.RotateKey succeeding and the re-issued
		// certificate persisting leaves a CA's keystore key out of sync with
		// its recorded certificate, with no Go error handling ever having run.
		findings, checkErr := ca.CheckKeyConsistency(keys, caStore)
		if checkErr == nil {
			ca.LogKeyConsistencyFindings(findings)
		}
		allowMissing := strings.EqualFold(strings.TrimSpace(os.Getenv(ca.AllowMissingCAKeysEnv)), "true")
		if err := ca.StartupKeyCheckDecision(findings, checkErr, allowMissing); err != nil {
			log.Fatalf("startup: %v", err)
		}

		if defaultCAID, err = resolveDefaultCA(caEngine, os.Getenv); err != nil {
			log.Fatalf("startup: %v", err)
		}
	}

	// Multi-tenancy is experimental (audit A01-001/002/004/005/006, A01S-3):
	// refuse to start unless the operator acknowledged it.
	if err := bootstrap.MultiTenancyExperimentalCheck(os.Getenv); err != nil {
		log.Fatal(err)
	}
	if bootstrap.MultiTenancyEnabled() {
		log.Print(bootstrap.MultiTenancyExperimentalWarning)
	}

	// --- Providers ---
	auth := bootstrap.NewAuthenticatorFromEnv()
	switch {
	case coreDB != nil:
		if err := auth.SetAPIKeyStore(context.Background(), bootstrap.NewAPIKeyStore(coreDB, isPostgres)); err != nil {
			log.Fatalf("api key store: %v", err)
		}
	case auth.APIKeyMintingAvailable():
		log.Print("WARNING: no core database (APP_CERTIFICATE_PROVIDER is not ca): API keys minted via POST /api/v1/api-keys are held in memory and do NOT survive a restart; keys in APP_API_KEYS_JSON do")
	}
	// Opened lazily: the custom-role store is only touched when
	// APP_AUTH_ROLE_MAP_JSON names a role that is not a compiled one.
	auth.SetCustomRoleLookup(func(name string) (bool, error) {
		store := bootstrap.NewCustomRoleStoreFromEnv()
		if store == nil {
			return false, nil
		}
		_, found, err := store.GetRole(name)
		return found, err
	})
	report := auth.ValidationReport()
	for _, warn := range report.Warnings {
		log.Printf("startup warning: %s", warn)
	}
	// An auth misconfiguration that leaves tokens forgeable or unscoped must
	// stop the hub, not scroll past in the log (A07-6 / A2A7-009).
	if err := report.FatalError(); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	certSummaryProvider := bootstrap.NewCertSummaryProviderFromEnv()
	// One router + one wrap at the construction point so every audit writer
	// (handlers, protocol servers, scheduler, ceremonies) is SIEM-forwarded.
	siemRouter := bootstrap.NewSIEMRouterFromEnv()
	// Fail closed: a hub without a working audit trail does not start.
	rawAudit, auditDesc, auditErr := bootstrap.ResolveAuditProvider(coreDB != nil)
	if auditErr != nil {
		log.Fatalf("refusing to start: audit store unavailable: %v", auditErr)
	}
	log.Printf("audit provider: %s", auditDesc)
	auditProvider := bootstrap.WithSIEMForwarding(rawAudit, siemRouter)
	templateProvider := bootstrap.NewTemplateProviderFromEnv()

	var certificateProvider bootstrap.CertificateProvider
	if needsCrypto {
		certificateProvider = bootstrap.WithTemplateProvider(
			bootstrap.NewCACertificateProvider(caEngine, revStore, coreDB, isPostgres),
			templateProvider,
		)
		log.Print("certificate provider: ca engine")
	} else {
		certificateProvider = bootstrap.NewCertificateProviderFromEnv()
	}
	// Handlers and protocol bridges read templates through the decorator so
	// issued_count reflects the certificate inventory.
	templateProvider = bootstrap.WithIssuedCounts(templateProvider, certificateProvider)

	var caProvider bootstrap.CAProvider
	if needsCrypto {
		// S-72: the engine knows CAs but not inventory. The certificate
		// provider keeps per-CA active counts current as it issues and
		// revokes (M1); the DB count is only the fallback for a provider
		// that does not.
		caProvider = bootstrap.NewEngineCAProviderWithCounts(
			caEngine, bootstrap.ActiveCertCountByCAFromProvider(certificateProvider, bootstrap.NewDBActiveCertCountByCA(coreDB)))
	} else {
		caProvider = bootstrap.NewCAProviderFromEnv()
	}

	protocolProvider := bootstrap.NewProtocolProviderFromEnv()

	var discoveryProvider bootstrap.DiscoveryProvider
	if strings.ToLower(strings.TrimSpace(os.Getenv("APP_DISCOVERY_PROVIDER"))) == "scanner" {
		discoveryProvider = bootstrap.NewScannerDiscoveryProvider(nil, 50)
		log.Print("discovery provider: scanner (minimal in-memory mode: 443 only, nothing persisted; use db for full discovery)")
	} else {
		discoveryProvider = bootstrap.NewDiscoveryProviderFromEnv()
	}
	// W5-12: recurring agentless discovery — opt-in via
	// KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL; works with any provider.
	if sched := bootstrap.NewDiscoverySchedulerWithTargetsFromEnv(discoveryProvider, bootstrap.NewManagedTargetStoreFromEnv()); sched != nil {
		sched.Start(context.Background())
	}

	var notificationProvider bootstrap.NotificationProvider
	if strings.ToLower(strings.TrimSpace(os.Getenv("APP_NOTIFICATION_PROVIDER"))) == "delivery" {
		notificationProvider = bootstrap.NewDeliveryNotificationProvider(deliveryChannelsFromEnv(bootstrap.NewConfigStoreFromEnv()), 3)
		log.Print("notification provider: delivery engine")
	} else {
		notificationProvider = bootstrap.NewNotificationProviderFromEnv()
	}

	dashboardActionProvider := bootstrap.NewDashboardActionProviderFromEnv()

	// W20-20: one delivery plugin manager for the whole process (nil = off).
	pluginManager := newDeliveryPluginManager(coreDB, isPostgres)

	// --- Background schedulers ---
	// Renewal scheduler: scans daily for certs approaching expiry and triggers
	// auto-renewal or owner notifications.
	renewalScheduler := bootstrap.NewRenewalSchedulerFromEnv(certificateProvider, notificationProvider, auditProvider).
		// S-17: arm the sweep's execute path — targets that opted in
		// (auto_renew + ssh install profile + credential) renew for real via
		// the W5-13 engine; everything else stays notify-only.
		WithRenewalExecutor(bootstrap.NewRenewalExecutorFromEnv(certificateProvider).WithPluginDeliverer(pluginManager, auditProvider)).
		// RC1-A-01: a push also needs the principal that armed the target to
		// still exist and still hold certificate.renew.
		WithStampVerifier(auth.StampVerifier())
	renewalScheduler.Start()
	// W11-05: scheduled direct-CA inventory syncs.
	inventorySync := bootstrap.NewInventorySyncSchedulerFromEnv(certificateProvider)
	inventorySync.Start()
	defer inventorySync.Stop()
	defer renewalScheduler.Stop()
	log.Print("renewal scheduler: started")

	// Posture scheduler: captures a daily crypto-posture snapshot for trend charts.
	if snapshotStore, err := bootstrap.NewPostureSnapshotStoreFromEnv(); err != nil {
		log.Printf("posture scheduler: disabled (snapshot store unavailable: %v)", err)
	} else {
		postureScheduler := bootstrap.NewPostureSchedulerFromEnv(certificateProvider, snapshotStore)
		postureScheduler.Start()
		defer postureScheduler.Stop()
		log.Print("posture scheduler: started")
	}

	// W12-01: CT-log rogue-cert monitor (opt-in via KRYPTKEEPER_CT_DOMAINS).
	// Detection needs the core DB for finding persistence; notification is
	// best-effort over the first configured delivery channel and detection
	// never depends on it.
	if coreDB != nil {
		if ctStore, err := ctmonitor.NewStore(coreDB, isPostgres); err != nil {
			log.Printf("ct monitor: disabled (store: %v)", err)
		} else {
			ctInventory := ctmonitor.NewProviderInventory(func(ctx context.Context) (map[string]struct{}, error) {
				serials := map[string]struct{}{}
				err := bootstrap.ForEachCertificate(ctx, certificateProvider, bootstrap.CertificateListQuery{}, func(item bootstrap.CertificateItem) error {
					serials[item.SerialNumber] = struct{}{}
					return nil
				})
				if err != nil {
					return nil, err
				}
				return serials, nil
			})
			var ctNotifier ctmonitor.Notifier
			if target := strings.TrimSpace(os.Getenv("KRYPTKEEPER_CT_NOTIFY_TARGET")); target != "" {
				if chans := deliveryChannelsFromEnv(bootstrap.NewConfigStoreFromEnv()); len(chans) > 0 {
					ctNotifier = &ctmonitor.ChannelNotifier{Channel: chans[0], Target: target}
				}
			}
			if ctMonitor := ctmonitor.NewMonitorFromEnv(ctInventory, ctStore, ctNotifier); ctMonitor != nil {
				hours := 12
				if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_CT_SCAN_HOURS")); raw != "" {
					if n, err := strconv.Atoi(raw); err == nil && n > 0 {
						hours = n
					}
				}
				ctCtx, ctCancel := context.WithCancel(context.Background())
				go ctMonitor.Start(ctCtx, time.Duration(hours)*time.Hour)
				defer ctCancel()
				log.Printf("ct monitor: started (every %dh)", hours)
			}
		}
	}

	// W12-02: SLO evaluator — sweeps the expiry histogram and pages the
	// first delivery channel on ok->breach transitions. Always on; the
	// no-data guards keep an idle estate silent.
	{
		var sloChannel delivery.Channel
		sloTarget := strings.TrimSpace(os.Getenv("KRYPTKEEPER_SLO_NOTIFY_TARGET"))
		if sloTarget != "" {
			if chans := deliveryChannelsFromEnv(bootstrap.NewConfigStoreFromEnv()); len(chans) > 0 {
				sloChannel = chans[0]
			}
		}
		sloScheduler := bootstrap.NewSLOSchedulerFromEnv(certificateProvider, sloChannel, sloTarget)
		sloScheduler.Start()
		defer sloScheduler.Stop()
		log.Print("slo scheduler: started")
	}

	// W12-03: issuance-anomaly detection — scheduled scan with latched
	// paging; latest tick served at /api/v1/reports/anomalies.
	var anomalyScheduler *bootstrap.AnomalyScheduler
	{
		var anomalyChannel delivery.Channel
		anomalyTarget := strings.TrimSpace(os.Getenv("KRYPTKEEPER_ANOMALY_NOTIFY_TARGET"))
		if anomalyTarget != "" {
			if chans := deliveryChannelsFromEnv(bootstrap.NewConfigStoreFromEnv()); len(chans) > 0 {
				anomalyChannel = chans[0]
			}
		}
		anomalyScheduler = bootstrap.NewAnomalySchedulerFromEnv(certificateProvider, anomalyChannel, anomalyTarget)
		anomalyScheduler.Start()
		defer anomalyScheduler.Stop()
		log.Print("anomaly scheduler: started")
	}

	// W12-04: mesh/SaaS discovery sweep (dormant when unconfigured).
	if meshScheduler := bootstrap.NewMeshDiscoverySchedulerFromEnv(); meshScheduler != nil {
		meshScheduler.Start()
		defer meshScheduler.Stop()
		log.Print("mesh discovery scheduler: started")
	}

	// Evidence scheduler: emails recurring compliance evidence packs (v1.4).
	evidenceMailer := bootstrap.NewEvidenceMailerFromEnv()
	if evidenceStore := bootstrap.NewEvidenceScheduleStoreFromEnv(); evidenceStore != nil && evidenceMailer.Enabled() {
		evidenceScheduler := bootstrap.NewEvidenceSchedulerFromEnv(certificateProvider, caProvider, evidenceStore, evidenceMailer)
		evidenceScheduler.Start()
		defer evidenceScheduler.Stop()
		log.Print("evidence scheduler: started")
	} else {
		log.Print("evidence scheduler: disabled (configure SMTP_HOST/SMTP_FROM to enable)")
	}

	// Agent renewal driver: re-evaluates each registered agent's last-known
	// inventory against the renewal threshold and assigns AgentRenewalTask for
	// certs that have aged into it (W4-05, wired by S-35). The on-submitInventory
	// trigger only fires when an agent pushes, so a cert that crosses the
	// threshold between pushes was never tasked while this driver sat unwired.
	//
	// It builds its own AgentStore: handlers.go constructs one for the HTTP
	// handlers but keeps it local, and handlers.go is outside this ticket's
	// write_scope. Both resolve the same DSN, so a configured deployment shares
	// one database. Only in the no-database fallback would the two diverge, and
	// NewAgentStoreFromEnv already logs that unavailability — so the degradation
	// is visible rather than silent.
	stopAgentRenewalDriver := startAgentRenewalDriver(bootstrap.NewAgentStoreFromEnv())
	defer stopAgentRenewalDriver()

	// --- Network ---
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatalf("invalid PORT %q: %v", port, err)
	}
	bindAddr := os.Getenv("APP_BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(bindAddr, port)

	dataDir := os.Getenv("KRYPTKEEPER_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	// W19-14/UAT W19-05: decide TLS before resolving the public base URL --
	// the advertised scheme (http vs https) depends on it, and RFC 7030
	// mandates TLS for EST, so this hub must not default to cleartext
	// serving of its own protocol endpoints.
	// W19-21: the same certificateProvider.(ca.IssuedCertificateRecorder)
	// assertion the protocol servers use below (main.go's own established
	// seam) -- reused here so a self-issued listener certificate lands in
	// inventory with lineage too, not just ACME/EST/SCEP/CMP issuances.
	tlsRecorder, _ := certificateProvider.(ca.IssuedCertificateRecorder)
	tlsConfig, tlsWarning, err := resolveTLSMode(needsCrypto, caEngine, tlsRecorder, defaultCAID, dataDir, bindAddr)
	if err != nil {
		log.Fatalf("TLS configuration: %v", err)
	}
	if tlsWarning != "" {
		log.Print("warning: " + tlsWarning)
	}

	// W19-13: the hub's public URL must never be its bind address -- a wildcard
	// bind (APP_BIND_ADDR=0.0.0.0, observed in the pilot recipe) is not dialable
	// by any client, so ACME directory/order/challenge URLs built from it fail
	// with "dial tcp 0.0.0.0:PORT: connection refused" (UAT W19-04, 2026-09-10).
	publicBaseURL, baseURLWarning, err := resolvePublicBaseURL(bindAddr, port, tlsConfig != nil)
	if err != nil {
		log.Fatalf("invalid KRYPTKEEPER_BASE_URL: %v", err)
	}
	if baseURLWarning != "" {
		log.Print("warning: " + baseURLWarning)
	}

	pluginOpts := deliveryPluginOption(pluginManager)

	// --- Protocol handlers (only when crypto engine is active) ---
	if needsCrypto {
		baseURL := publicBaseURL
		protocolMux := http.NewServeMux()

		// CRL/OCSP pointers for every issuing path (W20-10, W20-12): the
		// issuing CA's configured crl_distribution_points/ocsp_service_url
		// when set, otherwise this hub's own endpoints, preferably on the
		// plain-HTTP revocation listener (see revocation_http.go).
		if engine, ok := caEngine.(*ca.Engine); ok {
			engine.SetRevocationPointers(func(caID string) (crlURLs, ocspURLs []string) {
				if item, ok, err := caProvider.GetCA(context.Background(), caID); err == nil && ok {
					crlURLs = item.CRLDistributionPoints
					if item.OCSPServiceURL != nil && strings.TrimSpace(*item.OCSPServiceURL) != "" {
						ocspURLs = []string{strings.TrimSpace(*item.OCSPServiceURL)}
					}
				}
				if base := revocationBaseURL(baseURL); base != "" {
					if len(crlURLs) == 0 {
						crlURLs = []string{base + "/crl/" + caID + ".crl"}
					}
					if len(ocspURLs) == 0 {
						ocspURLs = []string{base + "/ocsp"}
					}
				}
				return crlURLs, ocspURLs
			})
			if revocationBaseURL(baseURL) == "" {
				log.Print("warning: issued certificates carry no CRL/OCSP pointers unless their CA configures them: set KRYPTKEEPER_REVOCATION_BASE_URL or KRYPTKEEPER_BASE_URL")
			}
		}

		// Per-endpoint rate limiters (per client IP, sliding window).
		acmeRL := ratelimit.New(30, time.Minute)  // 30 req/min — covers order + authz + finalize
		ocspRL := ratelimit.New(200, time.Minute) // 200 req/min — clients poll frequently
		crlRL := ratelimit.New(30, time.Minute)
		estRL := ratelimit.New(30, time.Minute)
		scepRL := ratelimit.New(30, time.Minute)
		cmpRL := ratelimit.New(30, time.Minute)
		wstepRL := ratelimit.New(30, time.Minute)
		xcepRL := ratelimit.New(30, time.Minute)

		var acmeStore acme.Store
		if coreDB != nil {
			aStore := acme.NewSQLiteStore(coreDB, isPostgres)
			if err := aStore.EnsureSchema(); err != nil {
				log.Printf("warning: ACME schema migration failed (%v) — falling back to in-memory store", err)
				acmeStore = acme.NewMemStore()
			} else {
				acmeStore = aStore
				log.Print("ACME store: database")
			}
		} else {
			acmeStore = acme.NewMemStore()
			log.Print("ACME store: in-memory (no DB)")
		}
		acmeServer := acme.NewServerWithStore(baseURL, caEngine, defaultCAID, acmeStore, revStore)
		// W18-16/W18-18: issued certificates were never written to the
		// certificates table at issuance (only on-demand, by revocation).
		// certificateProvider is a bootstrap.CertificateProvider interface
		// value; only its ca-engine-backed concrete type implements the
		// recorder seam ca.IssuedCertificateRecorder needs, so this is one
		// type assertion shared by every protocol server below, not a hard
		// dependency -- none of acme/est/scep/cmp may import
		// internal/bootstrap.
		issuedRecorder, hasIssuedRecorder := certificateProvider.(ca.IssuedCertificateRecorder)
		if !hasIssuedRecorder {
			log.Print("certificate provider does not support issuance recording — ACME/EST/SCEP/CMP-issued certs will not appear in inventory until revoked")
		} else {
			acmeServer.WithIssuedRecorder(issuedRecorder)
		}
		protocolMux.Handle("/acme/", acmeRL.Middleware(acmeServer.Handler()))

		ocspResponder := ocsp.NewResponder(
			// CertStatusFunc: look up which CA issued the cert by matching issuer
			// SubjectKeyId, then query that CA's revocation store.
			func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
				if revStore == nil {
					metrics.OCSPRequestsUnknown.Inc()
					return false, time.Time{}, 0, nil
				}
				caID, err := ocspResolveCAID(caEngine, issuer)
				if err != nil {
					metrics.OCSPRequestsError.Inc()
					return false, time.Time{}, 0, err
				}
				revoked, at, reason, err := revStore.IsRevoked(serial, caID)
				if err != nil {
					metrics.OCSPRequestsError.Inc()
					return false, time.Time{}, 0, err
				}
				if revoked {
					metrics.OCSPRequestsRevoked.Inc()
				} else {
					metrics.OCSPRequestsGood.Inc()
				}
				return revoked, at, reason, nil
			},
			// IssuerLookupFunc: find the CA whose public key matches the RFC 6960
			// IssuerKeyHash (SHA-1 of the raw public key bytes).
			func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
				caObj, err := ocspResolveIssuerByKeyHash(caEngine, keyHash)
				if err != nil {
					return nil, nil, err
				}
				signer, err := keys.Signer(caObj.KeyID)
				if err != nil {
					return nil, nil, err
				}
				return caObj.Certificate, signer, nil
			},
			24*time.Hour, 10000,
		)
		// "/ocsp/" too: RFC 5019 GET puts the request in the path
		// (/ocsp/<base64>), which is what Windows CryptoAPI sends. With only
		// "/ocsp" registered those requests fell through to the UI.
		ocspHandler := ocspRL.Middleware(ocspResponder.Handler())
		protocolMux.Handle("/ocsp", ocspHandler)
		protocolMux.Handle("/ocsp/", ocspHandler)

		crlGen := crl.NewGenerator(
			func(caID string) ([]crl.RevokedCert, error) {
				if revStore == nil {
					return nil, nil
				}
				entries, err := revStore.ListRevoked(caID)
				if err != nil {
					return nil, err
				}
				result := make([]crl.RevokedCert, len(entries))
				for i, e := range entries {
					result[i] = crl.RevokedCert{
						SerialNumber: e.Serial,
						RevokedAt:    e.RevokedAt,
						ReasonCode:   e.ReasonCode,
					}
				}
				return result, nil
			},
			func(caID string) (*x509.Certificate, crypto.Signer, error) {
				caObj, err := caEngine.GetCA(caID)
				if err != nil {
					return nil, nil, err
				}
				signer, err := keys.Signer(caObj.KeyID)
				if err != nil {
					return nil, nil, err
				}
				return caObj.Certificate, signer, nil
			},
			24*time.Hour,
		)

		// W19-01/W19-29: ocspResponder and crlGen each cache per their own
		// keying (per-serial, per-CA respectively) and each had no
		// invalidation hook wired to any revoke path, so a real revocation
		// never showed up until a cache aged out on its own. Both
		// crl.Generator and *ocsp.Responder implement
		// ca.RevocationCacheInvalidator (InvalidateCache(serial)) — see
		// crl.Generator.InvalidateCache's doc comment for how it maps a bare
		// serial back to the CA whose cache to drop — so a single fan-out
		// invalidator, wired into the SAME two revoke call sites that used
		// to take only ocspResponder, makes one revoke invalidate both.
		revocationInvalidator := multiRevocationCacheInvalidator{ocspResponder, crlGen}
		acmeServer.WithOCSPCacheInvalidator(revocationInvalidator)
		if invalidatable, ok := certificateProvider.(interface {
			SetOCSPCacheInvalidator(ca.RevocationCacheInvalidator)
		}); ok {
			invalidatable.SetOCSPCacheInvalidator(revocationInvalidator)
		}

		crlHandler := crlRL.Middleware(crlGen.Handler())
		crlEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metrics.CRLRequestsTotal.Inc()
			crlHandler.ServeHTTP(w, r)
		})
		protocolMux.Handle("/crl/", crlEndpoint)
		startRevocationHTTP(crlEndpoint, ocspHandler)
		estServer := est.NewServer(caEngine, defaultCAID)
		if hasIssuedRecorder {
			estServer.WithIssuedRecorder(issuedRecorder)
		}
		configureESTAuth(estServer, revStore, auditProvider)
		protocolMux.Handle("/.well-known/est/", estRL.Middleware(estServer.Handler()))

		// W19-15: SCEP's PKIOperation envelope (CMS EnvelopedData, RFC 8894
		// §3.1) key-wraps the CSR to the issuing CA's RSA public key -- there
		// is no EC analogue, so the CA SCEP issues from must hold an RSA key.
		// KRYPTKEEPER_SCEP_CA_ID selects it explicitly; left unset, the
		// default CA is used only if it happens to be RSA. Never falls back
		// to silently creating one -- an operator who wants SCEP on an
		// ECDSA-default deployment must provision an RSA CA and say so.
		scepCAID := os.Getenv("KRYPTKEEPER_SCEP_CA_ID")
		if scepCAID == "" {
			scepCAID = defaultCAID
		}
		scepStore, scepOff := scepSetup(coreDB, isPostgres)
		var scepAPI bootstrap.ServerOption
		if scepOff != "" {
			log.Print("SCEP disabled: " + scepOff)
		} else if scepCAObj, scepCAErr := caEngine.GetCA(scepCAID); scepCAErr != nil {
			log.Printf("SCEP disabled — CA %s unavailable: %v", scepCAID, scepCAErr)
		} else if _, isRSA := scepCAObj.Certificate.PublicKey.(*rsa.PublicKey); !isRSA {
			log.Printf("SCEP disabled — CA %s key is not RSA (SCEP's PKCS#7 envelope requires an RSA recipient key); set KRYPTKEEPER_SCEP_CA_ID to an RSA-issuing CA", scepCAID)
		} else {
			scepServer := scep.NewServer(caEngine, scepCAID, scepStore)
			configureSCEPAudit(scepServer, auditProvider)
			// The decrypter is resolved fresh on every enrollment rather
			// than cached: keys.Signer's SoftwareStore implementation hands
			// back the concrete *rsa.PrivateKey, which implements
			// crypto.Decrypter directly, so this works today without any
			// keystore.Store interface change; a pkcs11-backed CA that
			// can't support decryption fails each request with a clear
			// error instead of a permanently-nil value chosen at boot.
			scepServer.WithDecrypter(func() (crypto.Decrypter, error) {
				caObj, err := caEngine.GetCA(scepCAID)
				if err != nil {
					return nil, err
				}
				signer, err := keys.Signer(caObj.KeyID)
				if err != nil {
					return nil, err
				}
				dec, ok := signer.(crypto.Decrypter)
				if !ok {
					return nil, fmt.Errorf("SCEP CA %s key backend does not support decryption (crypto.Decrypter)", scepCAID)
				}
				return dec, nil
			})
			if hasIssuedRecorder {
				scepServer.WithIssuedRecorder(issuedRecorder)
			}
			protocolMux.Handle("/scep", scepRL.Middleware(scepServer.Handler()))
			scepAPI = scepChallengeOption(auth, scepStore, scepCAID, auditProvider)
			log.Printf("SCEP endpoint: /scep (CA %s); one-time challenges: POST /api/v1/scep/challenges", scepCAID)
		}

		// CMP over HTTP (RFC 6712). W19-16: requires a shared secret — RFC
		// 4210 §5.1.3 message protection is now enforced, so an unconfigured
		// secret means no client could ever authenticate, matching SCEP's
		// disabled-until-configured pattern above.
		cmpSecret := os.Getenv("KRYPTKEEPER_CMP_SECRET")
		if cmpSecret == "" {
			log.Print("CMP disabled — set KRYPTKEEPER_CMP_SECRET to enable")
		} else {
			cmpReference := os.Getenv("KRYPTKEEPER_CMP_REFERENCE")
			cmpServer := cmp.NewServer(caEngine, defaultCAID, cmpSecret, cmpReference)
			if cmpReference == "" {
				log.Print("CMP: KRYPTKEEPER_CMP_REFERENCE is empty — the senderKID is not checked; set it so the key identifier is bound to the secret")
			}
			if sfx := strings.TrimSpace(os.Getenv("KRYPTKEEPER_CMP_ALLOWED_DNS_SUFFIXES")); sfx != "" {
				parts := strings.Split(sfx, ",")
				if err := (&ca.NamePolicy{AllowedDNSSuffixes: parts}).Validate(); err != nil {
					log.Fatalf("KRYPTKEEPER_CMP_ALLOWED_DNS_SUFFIXES: %v", err)
				}
				cmpServer.WithAllowedDNSSuffixes(parts)
			} else {
				log.Print("CMP: KRYPTKEEPER_CMP_ALLOWED_DNS_SUFFIXES is unset — a client holding the CMP secret can obtain a certificate for any name")
			}
			if hasIssuedRecorder {
				cmpServer.WithIssuedRecorder(issuedRecorder)
			}
			protocolMux.Handle("/cmp", cmpRL.Middleware(cmpServer.Handler()))
			log.Print("CMP endpoint: /cmp")
		}

		// MS-WSTEP + MS-XCEP (Windows autoenrollment), authenticated per
		// D-109: Kerberos for enrollment and policy, a hub-issued client
		// certificate for renewal. Without a keytab and SPN they are not
		// served at all (W20-08).
		if wstepAuth, err := wstep.KerberosFromEnv(); err != nil {
			log.Printf("WSTEP/XCEP disabled: %v", err)
		} else {
			wstepAudit := func(ctx context.Context, ev wstep.AuditEvent) {
				appendProtocolAudit(ctx, auditProvider, ev.Action, ev.Actor, ev.Outcome, ev.SourceIP, ev.Detail)
			}
			// Templates offered for autoenrollment: active, with an OID. One
			// list feeds XCEP (what clients are told), the WSTEP resolver and
			// the TokenType lookup (what is enforced), so they cannot
			// disagree (W18-08, W20-09).
			offeredTemplates := func() ([]bootstrap.TemplateItem, error) {
				result, err := templateProvider.ListTemplates(context.Background(), bootstrap.TemplateListQuery{Limit: 200})
				if err != nil {
					return nil, err
				}
				out := make([]bootstrap.TemplateItem, 0, len(result.Items))
				for _, t := range result.Items {
					if t.Active && t.OID != "" {
						out = append(out, t)
					}
				}
				return out, nil
			}
			// The renewal window is when clients start renewing; validity is
			// the template's when it sets one (W20-09), which is what WSTEP
			// then issues.
			var xcepRenewal uint64
			if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_XCEP_RENEWAL_PERIOD")); raw != "" {
				if d, err := time.ParseDuration(raw); err == nil && d > 0 {
					xcepRenewal = uint64(d / time.Second)
				} else {
					log.Printf("warning: KRYPTKEEPER_XCEP_RENEWAL_PERIOD=%q ignored: want a Go duration such as 1008h", raw)
				}
			}
			xcepTemplateFunc := func() ([]xcep.Template, error) {
				offered, err := offeredTemplates()
				if err != nil {
					return nil, err
				}
				out := make([]xcep.Template, 0, len(offered))
				for _, t := range offered {
					out = append(out, xcep.Template{
						Name:            t.Name,
						DisplayName:     t.DisplayName,
						OID:             t.OID,
						MinKeySize:      t.MinKeySize,
						AutoEnroll:      t.AutoEnroll,
						Revision:        t.Revision,
						Enrollee:        t.Enrollee(),
						RenewalSeconds:  xcepRenewal,
						ValiditySeconds: uint64(bootstrap.TemplatePolicy(t).MaxValidity / time.Second),
					})
				}
				return out, nil
			}
			findTemplate := func(match func(bootstrap.TemplateItem) bool) (bootstrap.TemplateItem, bool) {
				offered, err := offeredTemplates()
				if err != nil {
					log.Printf("wstep: template list error: %v", err)
					return bootstrap.TemplateItem{}, false
				}
				for _, t := range offered {
					if match(t) {
						return t, true
					}
				}
				return bootstrap.TemplateItem{}, false
			}
			wstepTemplateResolver := func(oid string) (wstep.TemplateRef, bool) {
				t, ok := findTemplate(func(t bootstrap.TemplateItem) bool { return t.OID == oid })
				if !ok {
					return wstep.TemplateRef{}, false
				}
				policy := bootstrap.TemplatePolicy(t)
				return wstep.TemplateRef{Name: t.Name, OID: t.OID, Enrollee: t.Enrollee(), MajorVersion: t.Revision, Policy: &policy}, true
			}
			// TokenType carries a template OID or name for non-Windows WSTEP
			// clients (our own connector sends the name).
			wstepTokenTypeLookup := func(tokenType string) (wstep.TemplateRef, bool) {
				t, ok := findTemplate(func(t bootstrap.TemplateItem) bool { return t.OID == tokenType || t.Name == tokenType })
				if !ok {
					return wstep.TemplateRef{}, false
				}
				policy := bootstrap.TemplatePolicy(t)
				return wstep.TemplateRef{Name: t.Name, OID: t.OID, Enrollee: t.Enrollee(), MajorVersion: t.Revision, Policy: &policy}, true
			}
			// MS-WSTEP (Windows WSTEP certificate enrollment).
			wstepServer := wstep.NewServer(caEngine, defaultCAID).
				WithAuthenticator(wstepAuth).
				WithRenewal(revStore).
				WithTemplateResolver(wstepTemplateResolver).
				WithTemplateLookup(wstepTokenTypeLookup).
				WithAuditFunc(wstepAudit)
			if hasIssuedRecorder {
				wstepServer.WithIssuedRecorder(issuedRecorder)
			}
			protocolMux.Handle("/wstep", wstepRL.Middleware(wstepServer.Handler()))
			renewalNote := "renewal over Kerberos (Windows) only; set KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true for TLS client-certificate renewal"
			if requestClientCertFromEnv() {
				renewalNote = "renewal over Kerberos, or by hub-issued TLS client certificate"
			}
			log.Printf("WSTEP endpoint: /wstep (Kerberos SPN %s; %s)", os.Getenv(wstep.EnvSPN), renewalNote)

			// MS-XCEP (Windows Certificate Enrollment Policy Protocol).
			// Bridge the bootstrap TemplateProvider to the XCEP TemplateListFunc.
			xcepPolicyID := os.Getenv("KRYPTKEEPER_XCEP_POLICY_ID")
			if xcepPolicyID == "" {
				xcepPolicyID = "kryptkeeper-default-policy"
			}
			xcepServer := xcep.NewServer(xcepTemplateFunc, xcepPolicyID).
				WithAuthenticator(wstepAuth).WithAuditFunc(wstepAudit)
			if issuer, err := caEngine.GetCA(defaultCAID); err == nil && issuer.Certificate != nil {
				xcepServer.WithIssuer(issuer.Certificate.Raw, os.Getenv("KRYPTKEEPER_WSTEP_URL"))
			} else {
				log.Printf("warning: XCEP has no issuing CA (%v); GetPolicies will fault", err)
			}
			protocolMux.Handle("/xcep", xcepRL.Middleware(xcepServer.Handler()))
			log.Printf("XCEP endpoint: /xcep (policy: %s)", xcepPolicyID)
		}

		protocolMux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			metrics.Default.WritePrometheus(w)
		})

		if err := bootstrap.RunWithProtocols(listenAddr, tlsConfig, auth, certSummaryProvider, auditProvider, caProvider, templateProvider, certificateProvider, protocolProvider, discoveryProvider, notificationProvider, dashboardActionProvider, protocolMux, keys, keyBackend, ceremonyOption(auth, auditProvider, coreDB, isPostgres, caEngine), anomalyOption(auth, anomalyScheduler), scepAPI, pluginOpts, bootstrap.WithSIEMRouter(siemRouter)); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := bootstrap.Run(listenAddr, tlsConfig, auth, certSummaryProvider, auditProvider, caProvider, templateProvider, certificateProvider, protocolProvider, discoveryProvider, notificationProvider, dashboardActionProvider, keys, keyBackend, ceremonyOption(auth, auditProvider, coreDB, isPostgres, caEngine), anomalyOption(auth, anomalyScheduler), pluginOpts, bootstrap.WithSIEMRouter(siemRouter)); err != nil {
			log.Fatal(err)
		}
	}
}

// configuredChannel wraps a delivery.Channel constructor, re-resolving every
// setting from the W8-03 config store (DB override, else env default)
// immediately before each Send instead of once at process startup (W8-13
// acceptance #1/#2). Send is only ever invoked from the renewal scheduler's
// poll tick (renewal_scheduler.go) or an authenticated admin-triggered
// test/retry-delivery request (handlers_notifications.go) -- never from an
// unauthenticated request -- so one config read per send stays within
// acceptance #3's bound; it is not a per-request hot path.
type configuredChannel struct {
	name  string
	build func(ctx context.Context) delivery.Channel
}

func (c *configuredChannel) Name() string { return c.name }

func (c *configuredChannel) Send(ctx context.Context, event delivery.Event) error {
	return c.build(ctx).Send(ctx, event)
}

// startAgentRenewalDriver starts the scheduled agent-renewal sweep and returns
// its stop func, so main() can `defer` it exactly like the other schedulers.
//
// A function rather than four inline lines because main() is not callable from
// a test: the same reason deliveryChannelsFromEnv exists. Taking the store as a
// parameter (rather than calling NewAgentStoreFromEnv inside) is what makes the
// wiring testable at all — bootstrap.AgentStore has only unexported methods, so
// no fake can be built outside that package, and a test here can at least prove
// this helper starts a driver against the store it was handed. The behavioural
// proof that Start() sweeps lives with the fake, in
// internal/bootstrap/renewal_agent_driver_test.go.
func startAgentRenewalDriver(store bootstrap.AgentStore) func() {
	driver := bootstrap.NewRenewalAgentDriverFromEnv(store)
	driver.Start()
	log.Print("agent renewal driver: started")
	return driver.Stop
}

// deliveryChannelsFromEnv builds the notification delivery channels wired
// into the delivery engine. store may be nil (config store unavailable --
// e.g. no encryption passphrase configured), in which case every setting
// falls back to its env var exactly as it did before W8-13.
func deliveryChannelsFromEnv(store bootstrap.ConfigStore) []delivery.Channel {
	return []delivery.Channel{
		&configuredChannel{name: "email", build: func(ctx context.Context) delivery.Channel {
			// W19-07: notifications.smtp_port/username/password have been
			// registered config keys since W8-13 (config_store.go), but
			// this builder never read them -- every delivery-mode SMTP send
			// went out on hardcoded port 587 with no auth, so a configured
			// non-587 host (e.g. a submission/test SMTP server on another
			// port) or an authenticated relay could never actually be
			// reached. Found live against a real Mailpit container (SMTP on
			// 1025) during the notifications UAT.
			return &delivery.SMTPChannel{
				Host:     resolveConfigString(ctx, store, "notifications.smtp_host", "SMTP_HOST"),
				Port:     resolveConfigInt(ctx, store, "notifications.smtp_port", "SMTP_PORT", 587),
				From:     resolveConfigString(ctx, store, "notifications.smtp_from", "SMTP_FROM"),
				Username: resolveConfigString(ctx, store, "notifications.smtp_username", "SMTP_USERNAME"),
				Password: resolveConfigSecret(ctx, store, "notifications.smtp_password", "SMTP_PASSWORD"),
			}
		}},
		&configuredChannel{name: "slack", build: func(ctx context.Context) delivery.Channel {
			return &delivery.SlackChannel{WebhookURL: resolveConfigSecret(ctx, store, "notifications.slack_webhook_url", "SLACK_WEBHOOK_URL")}
		}},
		&configuredChannel{name: "pagerduty", build: func(ctx context.Context) delivery.Channel {
			return &delivery.PagerDutyChannel{
				RoutingKey: resolveConfigSecret(ctx, store, "notifications.pagerduty_routing_key", "PAGERDUTY_ROUTING_KEY"),
				// W19-27: KRYPTKEEPER_PAGERDUTY_EVENTS_URL lets a UAT/test
				// fixture point delivery-mode PagerDuty at a local receiver
				// (tests/live/notifications/run.sh) instead of the real
				// Events API -- before this, PagerDutyChannel.Endpoint was
				// only settable in-process by a test constructing the struct
				// directly, so production wiring could never be pointed
				// anywhere but the real pagerduty.com (delivery.go's own doc
				// comment on Endpoint). Empty means "use the real endpoint";
				// PagerDutyChannel.Send already defaults it (pagerDutyEventsURL).
				Endpoint: strings.TrimSpace(os.Getenv("KRYPTKEEPER_PAGERDUTY_EVENTS_URL")),
			}
		}},
		&configuredChannel{name: "webhook", build: func(ctx context.Context) delivery.Channel {
			return &delivery.WebhookChannel{URL: resolveConfigSecret(ctx, store, "notifications.webhook_url", "WEBHOOK_URL")}
		}},
	}
}

// resolveConfigString returns store's non-secret DB override for key if one
// is set, else envVar's value -- the W8-03 precedence (DB override, env
// bootstrap default) for exactly the one key a caller needs, without paying
// for the full-registry walk EffectiveSettings does.
func resolveConfigString(ctx context.Context, store bootstrap.ConfigStore, key, envVar string) string {
	if store != nil {
		if entry, ok, err := store.Get(ctx, key); err == nil && ok && entry.HasValue {
			return entry.Value
		}
	}
	return strings.TrimSpace(os.Getenv(envVar))
}

// resolveConfigInt is resolveConfigString's numeric counterpart: DB override
// wins, then envVar, then fallback if neither is set or the value doesn't
// parse. Used for notifications.smtp_port, which config_store.go registers
// as non-secret (Secret: false).
func resolveConfigInt(ctx context.Context, store bootstrap.ConfigStore, key, envVar string, fallback int) int {
	raw := resolveConfigString(ctx, store, key, envVar)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// resolveConfigSecret returns store's decrypted DB override for a SECRET key
// if one is set, else envVar's value. Secrets are write-only over the HTTP
// API (W8-03), but ConfigStore.Resolve is exactly the internal-consumer path
// its own doc comment describes for this use -- the plaintext never crosses
// an HTTP response, only an outbound SMTP/Slack/PagerDuty/webhook call this
// process makes directly.
func resolveConfigSecret(ctx context.Context, store bootstrap.ConfigStore, key, envVar string) string {
	if store != nil {
		if plaintext, err := store.Resolve(ctx, key); err == nil {
			return string(plaintext)
		}
	}
	return strings.TrimSpace(os.Getenv(envVar))
}

// resolvePublicBaseURL determines the URL the hub advertises to protocol
// clients (currently only ACME, whose directory/order/challenge URLs are
// built from it -- EST/SCEP/CMP/WSTEP/XCEP use paths relative to the
// request, not a self-URL). KRYPTKEEPER_BASE_URL always wins when set: it is
// the only way to tell the hub what address is actually reachable from a
// client's network. Absent that, a wildcard/unspecified bind address is
// never dialable, so falling back to it (the pre-W19-13 bug, UAT W19-04)
// silently broke every ACME client behind APP_BIND_ADDR=0.0.0.0. Bare
// bindAddr is a safe base URL only when it's a concrete address the process
// is actually listening on.
func resolvePublicBaseURL(bindAddr, port string, tlsEnabled bool) (baseURL string, warning string, err error) {
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	if configured := strings.TrimRight(strings.TrimSpace(os.Getenv("KRYPTKEEPER_BASE_URL")), "/"); configured != "" {
		u, perr := url.Parse(configured)
		if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", "", fmt.Errorf("KRYPTKEEPER_BASE_URL %q must be an absolute http(s) URL", configured)
		}
		// W19-14: the advertised scheme and the listener's actual scheme
		// must agree -- otherwise ACME directory/order URLs would tell
		// clients to speak the wrong protocol to a socket that isn't
		// listening on it.
		if u.Scheme != scheme {
			return "", "", fmt.Errorf("KRYPTKEEPER_BASE_URL %q uses scheme %q but the hub is serving %s -- set KRYPTKEEPER_BASE_URL's scheme to match the TLS mode (KRYPTKEEPER_TLS_CERT_FILE/KEY_FILE, KRYPTKEEPER_TLS_SELF_ISSUE, or KRYPTKEEPER_TLS_DISABLE)", configured, u.Scheme, scheme)
		}
		return configured, "", nil
	}
	if bindAddr == "" || bindAddr == "0.0.0.0" || bindAddr == "::" {
		return scheme + "://127.0.0.1:" + port,
			"APP_BIND_ADDR=" + bindAddr + " is not a client-reachable address; advertising " + scheme + "://127.0.0.1:" + port +
				" as the hub's public URL. Clients connecting from another host need KRYPTKEEPER_BASE_URL set explicitly.",
			nil
	}
	return scheme + "://" + net.JoinHostPort(bindAddr, port), "", nil
}

// multiRevocationCacheInvalidator fans one InvalidateCache call out to every
// wrapped ca.RevocationCacheInvalidator (W19-29) -- the seam OCSP and CRL
// each already implement, but only one value can be wired into a
// WithOCSPCacheInvalidator/SetOCSPCacheInvalidator call site. This lets both
// caches be wired alongside each other at those existing call sites without
// changing internal/acme or internal/bootstrap's single-invalidator field.
type multiRevocationCacheInvalidator []ca.RevocationCacheInvalidator

func (m multiRevocationCacheInvalidator) InvalidateCache(serial *big.Int) {
	for _, inv := range m {
		inv.InvalidateCache(serial)
	}
}

// ocspResolveCAID finds the CA ID whose certificate is the provided issuer
// certificate. It never falls back to a default CA: a status read against the
// wrong CA's revocation list answers "good" for a certificate that CA never
// issued (SEMGREP-012). A CA-list read failure is returned as an error (the
// responder answers tryLater) and an issuer no CA matches is ocsp.ErrUnknownIssuer.
func ocspResolveCAID(engine ca.Service, issuer *x509.Certificate) (string, error) {
	if issuer == nil {
		return "", ocsp.ErrUnknownIssuer
	}
	cas, err := engine.ListCAs()
	if err != nil {
		return "", fmt.Errorf("list CAs: %w", err)
	}
	for _, c := range cas {
		if c.Certificate != nil && bytes.Equal(c.Certificate.Raw, issuer.Raw) {
			return c.ID, nil
		}
	}
	return "", ocsp.ErrUnknownIssuer
}

// ocspResolveIssuerByKeyHash finds the CA whose RFC 6960 IssuerKeyHash matches
// keyHash (hash of the raw public key bytes, §4.1.1; the hash is identified by
// its length: SHA-1/256/384/512). A key hash no CA matches is
// ocsp.ErrUnknownIssuer (answered "unauthorized", RFC 6960 §2.3) and a
// CA-list read failure is returned as-is (answered "tryLater"): neither falls
// back to a default CA, which signed "good" for certificates it never issued
// (SEMGREP-012/013).
func ocspResolveIssuerByKeyHash(engine ca.Service, keyHash []byte) (*ca.CA, error) {
	cas, err := engine.ListCAs()
	if err != nil {
		return nil, fmt.Errorf("list CAs: %w", err)
	}
	for _, c := range cas {
		if c.Certificate == nil {
			continue
		}
		if h := ocspPublicKeyHash(c.Certificate, len(keyHash)); h != nil && bytes.Equal(h, keyHash) {
			return c, nil
		}
	}
	return nil, ocsp.ErrUnknownIssuer
}

// ocspPublicKeyHash hashes the raw public key bytes from a certificate's
// SubjectPublicKeyInfo, matching RFC 6960 §4.1.1 IssuerKeyHash. size selects
// the hash by digest length (20 SHA-1, 32 SHA-256, 48 SHA-384, 64 SHA-512);
// any other size yields nil.
func ocspPublicKeyHash(cert *x509.Certificate, size int) []byte {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil
	}
	switch size {
	case sha1.Size:
		//nolint:gosec // SHA-1 mandated by RFC 6960
		h := sha1.Sum(spki.PublicKey.Bytes)
		return h[:]
	case sha256.Size:
		h := sha256.Sum256(spki.PublicKey.Bytes)
		return h[:]
	case sha512.Size384:
		h := sha512.Sum384(spki.PublicKey.Bytes)
		return h[:]
	case sha512.Size:
		h := sha512.Sum512(spki.PublicKey.Bytes)
		return h[:]
	}
	return nil
}

// removeCISeedAndExit implements `kryptkeeper --remove-ci-seed` (S-42). It runs
// against whichever core database the normal configuration points at, so an
// operator does not have to work out DSNs by hand.
func removeCISeedAndExit() {
	db, isPostgres, err := bootstrap.OpenCoreDB()
	if err != nil {
		log.Fatalf("--remove-ci-seed: core DB unavailable: %v", err)
	}
	defer func() { _ = db.Close() }()

	engine := "sqlite"
	if isPostgres {
		engine = "postgres"
	}
	n, err := kkdb.RemoveCISeedData(db, engine)
	if err != nil {
		log.Fatalf("--remove-ci-seed: %v", err)
	}
	if n == 0 {
		log.Print("--remove-ci-seed: no CI seed rows found; nothing to do")
	}
	os.Exit(0)
}

// buildCloudKMSStore wires the cloud KMS keystore (W9-02). With a core DB
// the id -> key-URI references persist in cloud_kms_keys and survive
// restarts; without one the store is memory-only, which orphans cloud keys
// on restart — warn loudly rather than silently degrade.
func buildCloudKMSStore(provider string, coreDB *sql.DB, isPostgres bool) (keystore.Store, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return nil, errors.New("KRYPTKEEPER_KMS_PROVIDER must be set to aws, gcp, or azure when KRYPTKEEPER_KEY_BACKEND=cloudkms")
	}
	if coreDB == nil {
		log.Print("warning: cloud KMS running WITHOUT a core DB — key references are memory-only and a restart will orphan cloud keys (G-34)")
	}
	return keystore.NewCloudKMSStoreWithDB(provider, coreDB, isPostgres)
}

// ceremonyOption wires the W9-06 M-of-N ceremony API when both the crypto
// engine and the core DB exist; otherwise it registers nothing.
func ceremonyOption(auth *bootstrap.Authenticator, auditProvider bootstrap.AuditProvider, coreDB *sql.DB, isPostgres bool, caEngine ca.CeremonyEngine) bootstrap.ServerOption {
	if coreDB == nil || caEngine == nil {
		return nil
	}
	mgr, err := ca.NewCeremonyManager(coreDB, isPostgres, caEngine)
	if err != nil {
		log.Printf("key ceremonies disabled: %v", err)
		return nil
	}
	log.Print("key ceremony API: /api/v1/ceremonies (M-of-N root-CA ceremonies)")
	return bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterCeremonyHandlers(mux, auth, mgr, auditProvider)
	})
}

// anomalyOption mounts the W12-03 anomaly report surface.
func anomalyOption(auth *bootstrap.Authenticator, scheduler *bootstrap.AnomalyScheduler) bootstrap.ServerOption {
	return bootstrap.WithExtraHandlers(func(mux *http.ServeMux) {
		bootstrap.RegisterAnomalyHandlers(mux, auth, scheduler)
	})
}
