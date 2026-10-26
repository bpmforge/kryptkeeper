// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/certmanager"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/metrics"
	"kryptkeeper/internal/privexec"
)

// W5-13: the hub-side renewal execution engine. W5-09 stored what to manage,
// W5-10 stored how to authenticate, W5-11 built the SSH install machinery,
// and W4-02 honestly removed the auto-renew branch that had no way to
// produce a CSR. This engine closes that loop for ssh-mode targets: generate
// a fresh key + CSR hub-side, renew through the production
// CertificateProvider, then run the installer's test→reload→verify→rollback
// sequence over SSH. Agent-mode targets are NOT handled here — they renew
// through the AgentRenewalTask queue (W4-05), which already works.

var (
	errRenewalTargetNotSSH   = errors.New("target install_mode is not ssh; agent-mode targets renew via the agent task queue")
	errRenewalNoCredential   = errors.New("target has no credential_ref; store an ssh_key credential and reference it from the target")
	errRenewalBadCredential  = errors.New("credential payload is invalid")
	errRenewalInstallProfile = errors.New("install profile requires server_type, cert_path, and key_path")
)

// sshCredentialPayload is the documented plaintext shape of an `ssh_key`
// outbound credential (W5-10 stores it encrypted and opaque). host_public_key
// is REQUIRED: the SSH executor refuses to dial unpinned (executor_ssh.go),
// and this is where the pinned key lives.
type sshCredentialPayload struct {
	PrivateKeyPEM string `json:"private_key_pem"`
	HostPublicKey string `json:"host_public_key"` // authorized_keys format
	User          string `json:"user"`
	Port          int    `json:"port,omitempty"` // 0 → 22
	// KeystorePassword/KeystoreFormat are only read for server_type tomcat
	// (W27-07). The credential is encrypted at rest and never returned by the
	// API; the password must never reach a log, error or audit detail.
	KeystorePassword string `json:"keystore_password,omitempty"`
	KeystoreFormat   string `json:"keystore_format,omitempty"` // pkcs12 (default) | pkcs12-legacy | jks

	// W34-14: how the SSH account is elevated on the target (D-209). Empty
	// sudo_mode means none, the pre-W34 behaviour. SudoPassword is stored
	// encrypted with the rest of the payload and must never reach a log,
	// error, audit detail or API response.
	SudoMode     string `json:"sudo_mode,omitempty"`     // none (default) | nopasswd | password | helper
	SudoPassword string `json:"sudo_password,omitempty"` // password mode only
	HelperSHA256 string `json:"helper_sha256,omitempty"` // helper mode only
}

var errSSHPrivilege = errors.New("invalid ssh_key privilege settings")

// validatePrivilege enforces the sudo_* combination: a password exactly when
// the mode is password, a helper hash exactly when it is helper. Messages name
// fields, never values.
func (p sshCredentialPayload) validatePrivilege() error {
	mode, err := privexec.ParseMode(p.SudoMode)
	if err != nil {
		return fmt.Errorf("%w: sudo_mode must be one of none, nopasswd, password, helper", errSSHPrivilege)
	}
	if (mode == privexec.ModePassword) != (p.SudoPassword != "") {
		return fmt.Errorf("%w: sudo_password is required for, and only allowed with, sudo_mode password", errSSHPrivilege)
	}
	if (mode == privexec.ModeHelper) != (p.HelperSHA256 != "") {
		return fmt.Errorf("%w: helper_sha256 is required for, and only allowed with, sudo_mode helper", errSSHPrivilege)
	}
	if mode == privexec.ModeHelper && !isHexSHA256(p.HelperSHA256) {
		return fmt.Errorf("%w: helper_sha256 must be 64 hex characters", errSSHPrivilege)
	}
	return nil
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// elevate wraps exec per the payload's sudo mode. The returned func zeroizes
// the password copy handed to privexec; call it when the executor is done.
func (p sshCredentialPayload) elevate(exec agentinstall.Executor) (agentinstall.Executor, func(), error) {
	if err := p.validatePrivilege(); err != nil {
		return nil, func() {}, err
	}
	mode, _ := privexec.ParseMode(p.SudoMode)
	if mode == privexec.ModeNone {
		return exec, func() {}, nil
	}
	pw := []byte(p.SudoPassword)
	wrapped, err := privexec.Wrap(exec, privexec.Config{Mode: mode, Password: pw, HelperSHA: p.HelperSHA256, ElevateExists: true})
	if err != nil {
		zeroize(pw)
		return nil, func() {}, err
	}
	return wrapped, func() { zeroize(pw) }, nil
}

// RenewalInstallProfile says where the renewed material lands on the target.
// It is explicit per call for now: ManagedTarget carries no install-profile
// columns yet — persisting one per target is S-17's remaining scope.
type RenewalInstallProfile struct {
	ServerType   string `json:"server_type"` // "nginx" | "apache"
	CertPath     string `json:"cert_path"`
	KeyPath      string `json:"key_path"`
	ReloadMethod string `json:"reload_method,omitempty"`
	// VerifyHostPort overrides the post-install TLS verification address;
	// empty → target host :443.
	VerifyHostPort string `json:"verify_host_port,omitempty"`
}

// RenewalExecuteResult reports both phases. Renewed can be true while the
// install failed — the successor cert exists either way, and hiding that
// behind a single error would be the exact invisible-partial-state failure
// S-50 was about.
type RenewalExecuteResult struct {
	PredecessorFingerprint string `json:"predecessor_fingerprint"`
	NewFingerprint         string `json:"new_fingerprint,omitempty"`
	Renewed                bool   `json:"renewed"`
	InstallOutcome         string `json:"install_outcome,omitempty"`
	InstallDetail          string `json:"install_detail,omitempty"`
	Verified               bool   `json:"verified"`
}

// sshDialFunc lets tests substitute an in-memory Executor for a real SSH
// connection (no live network in unit tests). The returned closer tears the
// connection down.
type sshDialFunc func(ctx context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error)

type RenewalExecutor struct {
	certs CertificateProvider
	creds OutboundCredentialStore
	// registry, when non-nil, routes renewals for certificates carrying a
	// renewal_connector_id THROUGH that upstream connector (W11-04) instead
	// of the internal RenewCertificate. The install path is identical.
	registry *connectors.Registry
	// registryFn, when set, takes precedence over registry and is called per
	// renewal so connectors created through the API after startup are seen
	// (a registry built once at boot would miss them and, failing closed,
	// refuse to renew certs pinned to them).
	registryFn func(ctx context.Context) (*connectors.Registry, error)
	dial       sshDialFunc
	// verifier overrides the installer's TLS-dial verify step; nil uses the
	// real one. Tests substitute one that reads the fake target's filesystem.
	verifier agentinstall.Verifier
	// tdsVerifier is the verify step for sqlserver targets. It is separate
	// from verifier because SQL Server starts
	// TLS inside TDS PRELOGIN, which the plain HubVerifier cannot read;
	// tests substitute a stub. rdpVerifier is the same for the RDP listener,
	// whose TLS starts after an X.224 negotiation.
	tdsVerifier agentinstall.Verifier
	rdpVerifier agentinstall.Verifier
	// pushClient overrides the push-mode HTTP client (nil = default);
	// tests point it at httptest fixtures.
	pushClient *http.Client
	// plugins runs install_mode "plugin" targets (W20-20); nil = plugins off.
	plugins     *DeliveryPluginManager
	pluginAudit AuditProvider
	// keyWipeSpy is test-only (nil in production): called with the SAME slice
	// after it is zeroized so a test can assert every byte is 0.
	keyWipeSpy func(wiped []byte)
	// blocker, when set, is told to mark a target Blocked after a rollback
	// that itself failed (W34-18, W34-10's Blocked state).
	blocker targetBlocker
}

// targetBlocker marks a target Blocked so scheduled runs stop pushing to it
// until an operator looks.
type targetBlocker interface {
	BlockTarget(ctx context.Context, targetID, reason string) error
}

// WithTargetBlocker arms the Blocked marking after a failed rollback.
func (e *RenewalExecutor) WithTargetBlocker(b targetBlocker) *RenewalExecutor {
	e.blocker = b
	return e
}

// reportPrivilegedInstall audits every elevated push (the mode, never the
// password) and, when the rollback itself failed, raises the alarm and blocks
// the target instead of leaving it to be retried.
func (e *RenewalExecutor) reportPrivilegedInstall(ctx context.Context, target ManagedTarget, mode string, res *RenewalExecuteResult) {
	if mode != "" && mode != string(privexec.ModeNone) && e.pluginAudit != nil {
		outcome := AuditOutcomeSuccess
		if !installSucceeded(res.InstallOutcome) {
			outcome = AuditOutcomeFailure
		}
		e.appendTargetAudit(ctx, "target.renewal.privileged", target.ID, outcome,
			fmt.Sprintf("mode=%s install=%s cert=%s", mode, res.InstallOutcome, res.NewFingerprint))
	}
	if res.InstallOutcome != agentinstall.OutcomeRollbackFailed {
		return
	}
	logging.Warnf("ALERT renewal.rollback_failed target=%s cert=%s: the host may hold a half-installed state", target.ID, res.NewFingerprint)
	e.appendTargetAudit(ctx, "target.renewal.rollback_failed", target.ID, AuditOutcomeFailure,
		"rollback after a failed install failed; target blocked until an operator checks the host")
	if e.blocker != nil {
		if err := e.blocker.BlockTarget(ctx, target.ID, "renewal rollback failed"); err != nil {
			logging.Warnf("renewal: block target %s: %v", target.ID, err)
		}
	}
}

func (e *RenewalExecutor) appendTargetAudit(ctx context.Context, action, targetID string, outcome AuditOutcome, detail string) {
	if e.pluginAudit == nil {
		return
	}
	if err := e.pluginAudit.AppendEntry(context.WithoutCancel(ctx), AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "system", ActorID: "renewal",
		ResourceType: "target", ResourceID: targetID, Outcome: outcome, ChangeSummary: detail,
	}); err != nil {
		logging.Warnf("audit append failed action=%s: %v", action, err)
	}
}

func NewRenewalExecutor(certs CertificateProvider, creds OutboundCredentialStore) *RenewalExecutor {
	return &RenewalExecutor{
		certs: certs,
		creds: creds,
		// The hub drives these dials, so they go through the egress policy
		// (RC1-A-04); tests substitute their own.
		verifier:    agentinstall.HubVerifier,
		tdsVerifier: agentinstall.NewTDSVerifier(),
		rdpVerifier: agentinstall.NewRDPVerifier(),
		dial: func(ctx context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
			exec, err := agentinstall.NewSSHExecutor(ctx, cfg)
			if err != nil {
				return nil, nil, err
			}
			return exec, exec.Close, nil
		},
	}
}

// WithConnectorRegistry arms the upstream renewal path (W11-04).
func (e *RenewalExecutor) WithConnectorRegistry(r *connectors.Registry) *RenewalExecutor {
	e.registry = r
	return e
}

// WithConnectorRegistryFunc arms the upstream renewal path with a registry
// resolved fresh on every renewal (see registryFn).
func (e *RenewalExecutor) WithConnectorRegistryFunc(fn func(ctx context.Context) (*connectors.Registry, error)) *RenewalExecutor {
	e.registryFn = fn
	return e
}

// connectorRegistry returns the registry for this renewal, or nil when none
// is configured. A resolution error is returned, not swallowed: callers that
// hold a connector-pinned cert must fail rather than renew from the hub CA.
func (e *RenewalExecutor) connectorRegistry(ctx context.Context) (*connectors.Registry, error) {
	if e.registryFn != nil {
		return e.registryFn(ctx)
	}
	return e.registry, nil
}

// pinnedRegistry resolves the connector registry only for certificates pinned
// to a connector, so unpinned renewals never pay for (or fail on) the build.
func (e *RenewalExecutor) pinnedRegistry(ctx context.Context, detail CertificateDetail) (*connectors.Registry, error) {
	if detail.RenewalConnectorID == "" {
		return nil, nil
	}
	return e.connectorRegistry(ctx)
}

// issuerChainProvider is implemented by certificate providers that can hand
// out a hub CA's chain (caCertificateProvider).
type issuerChainProvider interface {
	IssuerChainPEM(ctx context.Context, caID string) ([]byte, error)
}

// NewRenewalExecutorFromEnv builds the engine on the env-configured
// outbound-credential store — the wiring main.go's scheduler path uses
// (S-17). The store fails closed to nil without a passphrase; ExecuteRenewal
// then returns a clean configuration error instead of panicking.
func NewRenewalExecutorFromEnv(certs CertificateProvider) *RenewalExecutor {
	e := NewRenewalExecutor(certs, newOutboundCredentialStoreFromEnv()).WithEnvConnectorRegistry(certs)
	if ts := newManagedTargetStoreFromEnv(); ts != nil {
		e = e.WithTargetBlocker(targetStateBlocker{ts})
	}
	return e
}

// WithEnvConnectorRegistry arms the upstream (connector) renewal path from
// the env-configured connector store (FB-07). It is the one place that
// wires this, shared by the scheduler, manual-execute and rollout executors.
// The store opens lazily on first use (handler registration must not touch
// the DB) and the registry is rebuilt per renewal so connectors added via the
// API after boot are honoured. A missing store yields an empty registry, so
// pinned certs fail closed rather than using the hub CA.
func (e *RenewalExecutor) WithEnvConnectorRegistry(certs CertificateProvider) *RenewalExecutor {
	var once sync.Once
	var store ConnectorStore
	return e.WithConnectorRegistryFunc(func(ctx context.Context) (*connectors.Registry, error) {
		once.Do(func() { store = newConnectorStoreFromEnv() })
		return BuildConnectorRegistry(ctx, store, certs, e.creds)
	})
}

// ExecuteRenewal runs the full hub-side loop for one certificate on one
// ssh-mode target. The caller (handler) has already authorized access to
// both the certificate and the target.
func (e *RenewalExecutor) ExecuteRenewal(ctx context.Context, fingerprint string, target ManagedTarget, profile RenewalInstallProfile) (result RenewalExecuteResult, err error) {
	result = RenewalExecuteResult{PredecessorFingerprint: fingerprint}
	// W12-02: every renewal attempt feeds the renewal-success-rate SLO.
	// A refusal (bad profile, missing credential) counts as a failure on
	// purpose — a target that cannot renew is exactly what should erode
	// the SLO until an operator fixes it.
	defer func() {
		if err == nil && result.Renewed {
			metrics.CertRenewalSuccess.Inc()
			notifyRenewalVerified(ctx, result) // W32-26: auto-resolve ITSM tickets
		} else if err != nil {
			metrics.CertRenewalFailure.Inc()
		}
	}()

	switch target.InstallMode {
	case "f5", "citrix", "k8s", "iis", "sqlserver", "rdp", "exchange", "plugin":
		// W12-05: push-mode targets renew through the agentinstall
		// pushers. Same SLO accounting (the defer above), same result
		// contract.
		return e.executePushRenewal(ctx, fingerprint, target, profile)
	case "ssh", "keychain":
		// Both reach the host over SSH with a pinned host key. keychain
		// (W18-05) installs into a macOS keychain instead of files, so it
		// needs no server type or paths.
	default:
		return result, errRenewalTargetNotSSH
	}
	if mode, _ := effectiveKeyHandlingMode(target); mode == KeyModeClientCSR {
		return result, errRenewalKeyModeMismatch
	}
	if target.InstallMode == "ssh" && (profile.ServerType == "" || profile.CertPath == "" || (profile.KeyPath == "" && profile.ServerType != "haproxy")) {
		return result, errRenewalInstallProfile
	}
	if strings.TrimSpace(target.CredentialRef) == "" {
		return result, errRenewalNoCredential
	}
	if e.creds == nil {
		return result, errors.New("outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
	}

	detail, ok, err := e.certs.GetCertificate(ctx, fingerprint)
	if err != nil {
		return result, err
	}
	if !ok {
		return result, errCertificateNotFound
	}

	// Resolve the credential BEFORE renewing: an unreachable target must not
	// burn a serial and leave a successor nothing installs.
	payload, err := e.resolveSSHCredential(ctx, target.CredentialRef)
	if err != nil {
		return result, err
	}
	payload = payload.withJIT(jitSudoFrom(ctx))
	signer, hostKey, err := payload.parse()
	if err != nil {
		return result, err
	}

	// Resolved once: the registry build lists every connector row.
	reg, regErr := e.pinnedRegistry(ctx, detail)
	key, keyPEM, csrPEM, err := generateRenewalKeyAndCSR(detail.CertificateItem, renewalKeyAlgorithmFor(reg, detail))
	if err != nil {
		return result, fmt.Errorf("generate key/csr: %w", err)
	}
	e.appendKeyAudit(ctx, "key.generate_for_renewal", fingerprint, AuditOutcomeSuccess, "target="+target.ID+" mode=hub_generated")
	defer func() {
		e.wipeKey(keyPEM)
		e.appendKeyAudit(ctx, "key.zeroize", fingerprint, AuditOutcomeSuccess,
			"target="+target.ID+" installed="+strconv.FormatBool(result.Renewed && installSucceeded(result.InstallOutcome)))
	}()

	newFP, chainPEM, err := e.renewMaterial(ctx, fingerprint, detail, reg, regErr, key, csrPEM)
	if err != nil {
		return result, err
	}
	result.Renewed = true
	result.NewFingerprint = newFP

	// From here on, failures are reported IN the result: the successor cert
	// exists, and the operator needs to see that plus the install outcome,
	// not a single opaque error.
	if chainPEM == nil {
		download, err := e.certs.DownloadCertificate(ctx, result.NewFingerprint, "pem", true)
		if err != nil {
			result.InstallOutcome = "install_skipped"
			result.InstallDetail = fmt.Sprintf("renewed but could not fetch certificate bytes: %v", err)
			return result, nil
		}
		chainPEM = download.Body
	}

	leafFP, err := leafFingerprint(chainPEM)
	if err != nil {
		result.InstallOutcome = "install_skipped"
		result.InstallDetail = fmt.Sprintf("renewed but certificate bytes unparseable: %v", err)
		return result, nil
	}

	e.installSSHMaterial(ctx, target, profile, sshInstallInput{
		payload: payload, signer: signer, hostKey: hostKey,
		chainPEM: chainPEM, keyPEM: keyPEM, leafFP: leafFP, caID: detail.CAID,
	}, &result)
	return result, nil
}

// sshInstallInput is everything installSSHMaterial needs beyond the target and
// profile: the resolved credential and the already-issued material.
type sshInstallInput struct {
	payload  sshCredentialPayload
	signer   ssh.Signer
	hostKey  ssh.PublicKey
	chainPEM []byte
	keyPEM   []byte
	leafFP   string
	caID     string // keychain installs append this CA's issuer chain
}

// installSSHMaterial dials the target and installs in.chainPEM/in.keyPEM through
// the agentinstall installer (backup, config test, reload, verify, rollback),
// reporting the outcome IN result. Shared by ExecuteRenewal and InstallMaterial
// so a PQC wave delivery cannot drift from the renewal install path.
func (e *RenewalExecutor) installSSHMaterial(ctx context.Context, target ManagedTarget, profile RenewalInstallProfile, in sshInstallInput, result *RenewalExecuteResult) {
	payload, signer, hostKey, chainPEM, keyPEM, leafFP := in.payload, in.signer, in.hostKey, in.chainPEM, in.keyPEM, in.leafFP
	verifyHostPort := profile.VerifyHostPort
	if verifyHostPort == "" {
		verifyHostPort = net.JoinHostPort(target.Host, "443")
	}

	port := payload.Port
	if port == 0 {
		port = 22
	}
	// The operator-confirmed pin on the target wins over the credential's
	// embedded key (W24-09); a mismatch refuses the install.
	pinned := pinnedHostKeyFor(target, hostKey)
	executor, closeConn, err := e.dial(ctx, agentinstall.SSHTarget{
		Host:            target.Host,
		Port:            port,
		User:            payload.User,
		Signer:          signer,
		HostKeyCallback: agentinstall.PinnedHostKeyCallback(pinned),
		// Pin negotiation to the SAME algorithm as the pinned key. A real
		// sshd commonly serves rsa+ecdsa+ed25519 host keys at once; without
		// this, the client can negotiate a different key type than the one
		// the callback holds and a correctly-pinned host fails to connect
		// (found live against a real multi-hostkey sshd, W19-02).
		HostKeyAlgorithms: hostKeyAlgorithmsFor(pinned),
	})
	if err != nil {
		var mm *agentinstall.HostKeyMismatchError
		if errors.As(err, &mm) {
			recordHostKeyMismatch(ctx, e.pluginAudit, target.ID, mm)
		}
		result.InstallOutcome = "connect_failed"
		result.InstallDetail = boundInstallDetail(err.Error())
		return
	}
	defer func() { _ = closeConn() }()

	executor, endPrivilege, err := payload.elevate(executor)
	if err != nil {
		result.InstallOutcome = "connect_failed"
		result.InstallDetail = boundInstallDetail(err.Error(), payload.SudoPassword)
		return
	}
	defer endPrivilege()

	if target.InstallMode == "keychain" {
		// The keychain must trust the issuing root, and the renewed
		// certificate's download is the leaf alone: append the issuer chain
		// when the provider can supply it (hub-issued certificates).
		if ic, ok := e.certs.(issuerChainProvider); ok && in.caID != "" {
			if issuer, err := ic.IssuerChainPEM(ctx, in.caID); err == nil {
				chainPEM = append(append([]byte(nil), chainPEM...), issuer...)
			} else {
				logging.Warnf("renewal: issuer chain for CA %s unavailable, keychain trust will fail: %v", in.caID, err)
			}
		}
		// Verify-after-install only when the operator named a TLS endpoint:
		// a keychain identity is often a client or system identity that no
		// local server presents on :443.
		kc := agentinstall.NewKeychainInstaller(executor)
		if e.verifier != nil {
			kc = kc.WithVerifier(e.verifier)
		}
		kreq := agentinstall.KeychainInstallRequest{CertPEM: chainPEM, KeyPEM: keyPEM}
		if profile.VerifyHostPort != "" {
			kreq.VerifyHostPort, kreq.ExpectedFingerprint = profile.VerifyHostPort, leafFP
		}
		installRes, err := kc.Install(ctx, kreq)
		result.InstallOutcome = installRes.Outcome
		result.InstallDetail = boundInstallDetail(installRes.Detail)
		result.Verified = installRes.Verified
		if err != nil && result.InstallDetail == "" {
			result.InstallDetail = boundInstallDetail(err.Error())
		}
		return
	}

	installer := agentinstall.New(executor)
	if e.verifier != nil {
		installer = installer.WithVerifier(e.verifier)
	}
	// The installer's rollback restores only files that pre-existed, so a key
	// file this install newly created would survive a failed install. Remember
	// whether one was there so cleanup never removes a predecessor's key.
	keyPath := profile.KeyPath
	if profile.ServerType == "haproxy" || profile.ServerType == "tomcat" {
		keyPath = profile.CertPath // HAProxy uses one combined chain+key file; Tomcat one keystore
	}
	keyExisted := executor.Exists(keyPath)
	installRes, err := installer.Install(ctx, agentinstall.InstallRequest{
		ServerType:          profile.ServerType,
		CertPath:            profile.CertPath,
		KeyPath:             profile.KeyPath,
		CertPEM:             chainPEM,
		KeyPEM:              keyPEM,
		ReloadMethod:        profile.ReloadMethod,
		KeystorePassword:    payload.KeystorePassword,
		KeystoreFormat:      payload.KeystoreFormat,
		VerifyHostPort:      verifyHostPort,
		ExpectedFingerprint: leafFP,
	})
	result.InstallOutcome = installRes.Outcome
	result.InstallDetail = boundInstallDetail(installRes.Detail, payload.KeystorePassword, payload.SudoPassword)
	result.Verified = installRes.Verified
	if err != nil && result.InstallDetail == "" {
		result.InstallDetail = boundInstallDetail(err.Error(), payload.KeystorePassword, payload.SudoPassword)
	}
	if (err != nil || !installSucceeded(installRes.Outcome)) && !keyExisted {
		e.cleanupFailedInstallKey(ctx, executor, target, keyPath, result)
	}
	e.reportPrivilegedInstall(ctx, target, payload.SudoMode, result)
}

// InstallMaterial installs ALREADY-ISSUED chain and key on one ssh-mode target
// through the same install code as ExecuteRenewal (backup, config test, reload,
// verify the served leaf, rollback). It renews nothing and does not take
// ownership of keyPEM: the caller zeroizes it. A returned error means nothing
// was attempted on the host (refused profile, missing credential, unparseable
// material); an attempted install reports its outcome in the result.
func (e *RenewalExecutor) InstallMaterial(ctx context.Context, target ManagedTarget, profile RenewalInstallProfile, chainPEM, keyPEM []byte, caID string) (RenewalExecuteResult, error) {
	var result RenewalExecuteResult
	if target.InstallMode != "ssh" {
		return result, errRenewalTargetNotSSH
	}
	if mode, _ := effectiveKeyHandlingMode(target); mode == KeyModeClientCSR {
		return result, errRenewalKeyModeMismatch
	}
	// haproxy reads one combined chain+key file (CertPath), so it has no key path.
	if profile.ServerType == "" || profile.CertPath == "" || (profile.KeyPath == "" && profile.ServerType != "haproxy") {
		return result, errRenewalInstallProfile
	}
	if strings.TrimSpace(target.CredentialRef) == "" {
		return result, errRenewalNoCredential
	}
	if e.creds == nil {
		return result, errors.New("outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
	}
	leafFP, err := leafFingerprint(chainPEM)
	if err != nil {
		return result, fmt.Errorf("certificate bytes unparseable: %w", err)
	}
	payload, err := e.resolveSSHCredential(ctx, target.CredentialRef)
	if err != nil {
		return result, err
	}
	payload = payload.withJIT(jitSudoFrom(ctx))
	signer, hostKey, err := payload.parse()
	if err != nil {
		return result, err
	}
	result.NewFingerprint = leafFP
	e.installSSHMaterial(ctx, target, profile, sshInstallInput{
		payload: payload, signer: signer, hostKey: hostKey,
		chainPEM: chainPEM, keyPEM: keyPEM, leafFP: leafFP, caID: caID,
	}, &result)
	return result, nil
}

// PushMaterial installs ALREADY-ISSUED chain and key into a Kubernetes TLS
// Secret (D-315). It is InstallMaterial's counterpart for the k8s push mode
// and reuses pushMaterialToTarget, so a PQC wave delivery gets the same
// backup (prior Secret manifest), verify and restore as a renewal push. Only
// k8s is accepted: the other push modes either import a PFX the hub cannot
// build for an ML-DSA key (Windows) or are device APIs with no proven
// ML-DSA support (F5, Citrix). The caller zeroizes keyPEM. A returned error
// means nothing was attempted on the cluster.
func (e *RenewalExecutor) PushMaterial(ctx context.Context, target ManagedTarget, profile RenewalInstallProfile, chainPEM, keyPEM []byte) (RenewalExecuteResult, error) {
	var result RenewalExecuteResult
	if target.InstallMode != "k8s" {
		return result, fmt.Errorf("install_mode %q is not delivered by PushMaterial", target.InstallMode)
	}
	if mode, _ := effectiveKeyHandlingMode(target); mode == KeyModeClientCSR {
		return result, errRenewalKeyModeMismatch
	}
	if strings.TrimSpace(target.CredentialRef) == "" {
		return result, errRenewalNoCredential
	}
	if e.creds == nil {
		return result, errors.New("outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
	}
	leafFP, err := leafFingerprint(chainPEM)
	if err != nil {
		return result, fmt.Errorf("certificate bytes unparseable: %w", err)
	}
	result.NewFingerprint = leafFP
	res, pushErr := e.pushMaterialToTarget(ctx, target, profile, chainPEM, keyPEM, leafFP)
	result.InstallOutcome = res.Outcome
	result.InstallDetail = boundInstallDetail(res.Detail)
	result.Verified = res.Verified
	// The pusher reports verify_failed for a failed verify even when its
	// restore also failed; only RolledBack tells the two apart.
	if res.Outcome == agentinstall.OutcomeVerifyFailed && !res.RolledBack {
		result.InstallOutcome = agentinstall.OutcomeRollbackFailed
	}
	if pushErr != nil && result.InstallOutcome == "" {
		return result, pushErr // refused before the cluster was touched
	}
	if pushErr != nil && result.InstallDetail == "" {
		result.InstallDetail = boundInstallDetail(pushErr.Error())
	}
	return result, nil
}

// cleanupFailedInstallKey removes the key file a failed first install left on
// the target (W23-48). A removal failure is reported in the result, never
// returned: partial state is visible, not an opaque error (the S-50 rule).
func (e *RenewalExecutor) cleanupFailedInstallKey(ctx context.Context, executor agentinstall.Executor, target ManagedTarget, keyPath string, result *RenewalExecuteResult) {
	removed := true
	if _, rmErr := executor.Run(context.WithoutCancel(ctx), "rm", "-f", "--", keyPath); rmErr != nil {
		removed = false
		result.InstallDetail = boundInstallDetail(strings.TrimSpace(result.InstallDetail + "; key cleanup failed: " + rmErr.Error()))
	}
	logging.Warnf("ALERT renewal.install_failed_key_cleanup target=%s cert=%s path=%s removed=%t", target.ID, result.NewFingerprint, keyPath, removed)
	e.appendKeyAudit(ctx, "renewal.install_failed_key_cleanup", result.NewFingerprint, AuditOutcomeFailure,
		fmt.Sprintf("target=%s; removed=%t", target.ID, removed))
}

// wipeKey zeroizes the hub's transient key buffer and lets a test observe it.
func (e *RenewalExecutor) wipeKey(keyPEM []byte) {
	zeroize(keyPEM)
	if e.keyWipeSpy != nil {
		e.keyWipeSpy(keyPEM)
	}
}

// appendKeyAudit records hub-generated renewal key lifecycle events. Details
// must never carry key bytes, hashes of them, or their length.
func (e *RenewalExecutor) appendKeyAudit(ctx context.Context, action, certFP string, outcome AuditOutcome, detail string) {
	if e.pluginAudit == nil {
		return
	}
	if err := e.pluginAudit.AppendEntry(context.WithoutCancel(ctx), AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "system", ActorID: "renewal",
		ResourceType: "certificate", ResourceID: certFP, Outcome: outcome, ChangeSummary: detail,
	}); err != nil {
		logging.Warnf("audit append failed action=%s: %v", action, err)
	}
}

func installSucceeded(outcome string) bool {
	return outcome == agentinstall.OutcomeInstalled || outcome == agentinstall.OutcomeInstalledVerified
}

func (e *RenewalExecutor) resolveSSHCredential(ctx context.Context, ref string) (sshCredentialPayload, error) {
	meta, err := e.creds.Get(ctx, ref)
	if err != nil {
		return sshCredentialPayload{}, fmt.Errorf("credential %q: %w", ref, err)
	}
	if meta.CredentialType != CredentialTypeSSHKey {
		return sshCredentialPayload{}, fmt.Errorf("%w: credential %q has type %q, need %q", errRenewalBadCredential, ref, meta.CredentialType, CredentialTypeSSHKey)
	}
	plaintext, err := e.creds.Resolve(ctx, ref)
	if err != nil {
		return sshCredentialPayload{}, fmt.Errorf("credential %q: %w", ref, err)
	}
	defer zeroize(plaintext)
	var payload sshCredentialPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return sshCredentialPayload{}, fmt.Errorf("%w: not the documented JSON shape (private_key_pem/host_public_key/user/port)", errRenewalBadCredential)
	}
	return payload, nil
}

func (p sshCredentialPayload) parse() (ssh.Signer, ssh.PublicKey, error) {
	if p.PrivateKeyPEM == "" || p.HostPublicKey == "" || p.User == "" {
		return nil, nil, fmt.Errorf("%w: private_key_pem, host_public_key, and user are all required", errRenewalBadCredential)
	}
	signer, err := ssh.ParsePrivateKey([]byte(p.PrivateKeyPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: private key: %v", errRenewalBadCredential, err)
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.HostPublicKey))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: host_public_key must be authorized_keys format: %v", errRenewalBadCredential, err)
	}
	return signer, hostKey, nil
}

// hostKeyAlgorithmsFor returns the ssh.ClientConfig.HostKeyAlgorithms value
// that will actually negotiate the given pinned public key. This is NOT
// simply []string{pub.Type()}: an RSA ssh.PublicKey's Type() is "ssh-rsa",
// the legacy SHA-1 signature scheme, which golang.org/x/crypto/ssh's client
// refuses to negotiate at all (excluded from its own supportedHostKeyAlgos
// "due to security issues") -- passing it straight through would make an
// RSA-pinned host never connect. RSA hosts are negotiated instead via the
// SHA-2 algorithm names (rsa-sha2-512/256), which sign with the exact same
// key; every other key type's Type() already IS a valid negotiable name.
func hostKeyAlgorithmsFor(pub ssh.PublicKey) []string {
	if pub.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{pub.Type()}
}

// splitSubjectAltNames classifies each SAN string back into the x509 kind it
// came from: an IP-parseable string to IPAddresses, a string url.Parse
// accepts with a non-empty Scheme (spiffe://…, https://…) to URIs, a string
// containing "@" with no scheme to EmailAddresses, and everything else to
// DNSNames. ca.SubjectAltNameStrings now flattens every SAN kind into one
// []string on the stored record (W18-14), so this is the
// inverse: get each SAN kind wrong here and a renewed certificate silently
// changes identity (a SPIFFE URI or email SAN relabeled as a DNS name). A
// flat []string cannot distinguish a legal-but-unusual DNS name that merely
// looks like an IP/URI/email from the real thing; that ambiguity is a
// constraint of the record format, not something this function can resolve.
func splitSubjectAltNames(sans []string) (dns []string, ips []net.IP, uris []*url.URL, emails []string) {
	for _, san := range sans {
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if u, err := url.Parse(san); err == nil && u.Scheme != "" {
			uris = append(uris, u)
			continue
		}
		if strings.Contains(san, "@") {
			emails = append(emails, san)
			continue
		}
		dns = append(dns, san)
	}
	return dns, ips, uris, emails
}

// renewalKeyAlgorithm selects the key type generateRenewalKeyAndCSR
// produces. ECDSA P-256 is the default for every renewal path; RSA is only
// needed upstream of a SCEP connector, whose classic PKCS#7 key-transport
// envelope (both directions: CSR to the CA, CertRep back to the requester)
// has no EC analogue (see internal/connectors/scep_client.go).
type renewalKeyAlgorithm int

const (
	renewalKeyECDSAP256 renewalKeyAlgorithm = iota
	renewalKeyRSA2048
)

// generateRenewalKeyAndCSR produces a fresh key and a CSR carrying the
// predecessor's CN and SANs, each put back into the CSR field it belongs to
// (see splitSubjectAltNames). It also returns the key as a crypto.Signer —
// never serialized beyond keyPEM — so a SCEP renewal can hand the same
// in-process key object to the connector as IssueRequest.Signer/Decrypter
// (W19-28); every other path ignores it and uses keyPEM as before.
func generateRenewalKeyAndCSR(item CertificateItem, alg renewalKeyAlgorithm) (key crypto.Signer, keyPEM, csrPEM []byte, err error) {
	switch alg {
	case renewalKeyRSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	dns, ips, uris, emails := splitSubjectAltNames(item.SubjectAltNames)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: item.CommonName},
		DNSNames:       dns,
		IPAddresses:    ips,
		URIs:           uris,
		EmailAddresses: emails,
	}, key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return key, keyPEM, csrPEM, nil
}

// leafFingerprint returns the SHA-256 hex of the first CERTIFICATE block in
// a PEM bundle — the leaf, for verify-after-install.
func leafFingerprint(pemBundle []byte) (string, error) {
	rest := pemBundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return "", errors.New("no CERTIFICATE block in bundle")
		}
		if block.Type == "CERTIFICATE" {
			return agentinstall.FingerprintSHA256(block.Bytes), nil
		}
	}
}

// zeroize best-effort wipes key material the hub only ever holds transiently.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// renewalKeyAlgorithmFor picks the key algorithm generateRenewalKeyAndCSR
// should use, BEFORE the key exists — a SCEP-bound renewal must generate
// its key RSA from the start, since renewMaterial hands that same key
// object (not a re-derived one) to the connector as a Signer/Decrypter.
func renewalKeyAlgorithmFor(reg *connectors.Registry, detail CertificateDetail) renewalKeyAlgorithm {
	// A nil registry (unpinned, or unresolvable) is reported by renewMaterial,
	// which fails the renewal; here it only means "not SCEP-detectable".
	if detail.RenewalConnectorID != "" && reg != nil {
		if c, err := reg.Get(detail.RenewalConnectorID); err == nil && c.Type() == "scep" {
			return renewalKeyRSA2048
		}
	}
	return renewalKeyECDSAP256
}

// renewMaterial issues the successor via the upstream connector when the
// certificate carries one (W11-04), else through the internal provider.
// chainPEM is nil on the internal path — the caller downloads it (the
// pre-extraction behavior, unchanged). key is the crypto.Signer
// generateRenewalKeyAndCSR just produced for csrPEM: a SCEP connector needs
// it wired onto the request (Signer to sign the PKIOperation, Decrypter to
// open the CertRep, W19-28) because IssueRequest.CSRPEM alone cannot drive
// the real protocol; every other connector ignores it.
func (e *RenewalExecutor) renewMaterial(ctx context.Context, fingerprint string, detail CertificateDetail, registry *connectors.Registry, regErr error, key crypto.Signer, csrPEM []byte) (string, []byte, error) {
	if detail.RenewalConnectorID != "" {
		// Fail closed: a cert pinned to an upstream connector must never be
		// silently re-issued by the hub CA (wrong issuer, wrong trust chain).
		if regErr != nil {
			return "", nil, fmt.Errorf("upstream renewal via connector %s: connector registry unavailable: %w", detail.RenewalConnectorID, regErr)
		}
		if registry == nil {
			return "", nil, fmt.Errorf("upstream renewal via connector %s: no connector registry configured; refusing to renew from the hub CA", detail.RenewalConnectorID)
		}
		req := connectors.IssueRequest{
			CSRPEM: string(csrPEM),
			TeamID: detail.TeamID,
		}
		if c, err := registry.Get(detail.RenewalConnectorID); err == nil && c.Type() == "scep" {
			req.Signer = key
			if dec, ok := key.(crypto.Decrypter); ok {
				req.Decrypter = dec
			}
		}
		if c, err := registry.Get(detail.RenewalConnectorID); err == nil && c.Type() == "acme" && e.certs != nil {
			// RFC 9773: tell the CA which certificate this order replaces.
			if old, derr := e.certs.DownloadCertificate(ctx, fingerprint, "pem", false); derr == nil {
				ctx = WithACMEReplaces(ctx, string(old.Body))
			}
		}
		issued, err := registry.Issue(ctx, detail.RenewalConnectorID, req)
		if err != nil {
			return "", nil, fmt.Errorf("upstream renewal via connector %s: %w", detail.RenewalConnectorID, err)
		}
		return issued.FingerprintSHA256, []byte(issued.CertificatePEM), nil
	}
	renewed, err := e.certs.RenewCertificate(ctx, fingerprint, CertificateRenewRequest{CSRPEM: string(csrPEM)})
	if err != nil {
		return "", nil, err
	}
	return renewed.CertificateItem.FingerprintSHA256, nil, nil
}

// pushCredentialPayload is the documented plaintext JSON shape of an
// api_token credential backing a push-mode target (W12-05). Device
// endpoints and secrets live ONLY here — never inline on the target.
type pushCredentialPayload struct {
	BaseURL          string `json:"base_url"`
	Username         string `json:"username,omitempty"`           // f5, citrix
	Password         string `json:"password,omitempty"`           // f5, citrix
	BearerToken      string `json:"bearer_token,omitempty"`       // k8s
	ClientSSLProfile string `json:"client_ssl_profile,omitempty"` // f5
	CertKeyName      string `json:"certkey_name,omitempty"`       // citrix
	Namespace        string `json:"namespace,omitempty"`          // k8s
	SecretName       string `json:"secret_name,omitempty"`        // k8s
	// CACert is the PEM-encoded cluster CA bundle a k8s push target
	// trusts instead of the system root store (W19-17). Falls back to
	// KRYPTKEEPER_K8S_CA_CERT / _FILE when empty — see resolveK8sCACert.
	CACert string `json:"ca_cert,omitempty"` // k8s
	// iis: the HTTP.sys binding and the machine store to import into. The
	// installer needs these per target, and the credential blob is the one
	// per-target place a push already carries.
	IPPort    string `json:"ipport,omitempty"`     // e.g. 0.0.0.0:443
	AppID     string `json:"app_id,omitempty"`     // netsh appid GUID
	StoreName string `json:"store_name,omitempty"` // default MY
	// sqlserver (W35-02): instance name (default MSSQLSERVER) and its TCP
	// port (default 1433), used for the TDS verify dial. A named instance on
	// a dynamic port needs the port stated here or via verify_host_port.
	SQLInstance string   `json:"sql_instance,omitempty"`
	SQLPort     flexPort `json:"sql_port,omitempty"`
	// exchange: services to enable the certificate for (default IIS,SMTP) and
	// the SMTP ports probed with STARTTLS afterwards (default 25 and 587).
	Services  []string `json:"services,omitempty"`
	SMTPPorts []int    `json:"smtp_ports,omitempty"`
}

// flexPort reads a port given as a JSON number or as a string: the wizard's
// credential form submits every field as text, API callers send numbers.
type flexPort int

func (p *flexPort) UnmarshalJSON(b []byte) error {
	t := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if t == "" || t == "null" {
		*p = 0
		return nil
	}
	n, err := strconv.Atoi(t)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("sql_port must be a TCP port number")
	}
	*p = flexPort(n)
	return nil
}

// isWinRMPushMode reports the install modes that drive a Windows host over
// WinRM with a windows_password credential: their base_url is a WinRM
// endpoint (validated by the WinRM client), not an https device API.
func isWinRMPushMode(installMode string) bool {
	switch installMode {
	case "iis", "sqlserver", "rdp", "exchange":
		return true
	}
	return false
}

// resolveK8sCACert returns the credential-carried CA bundle if present,
// else the env fallback (KRYPTKEEPER_K8S_CA_CERT / _FILE) shared with the
// certmanager discovery connector — reused rather than duplicated so the
// two can't drift. Empty/nil means "no bundle configured": NewK8sPusher
// then falls back to the system root store, unchanged from before W19-17.
func resolveK8sCACert(credentialCACert string) ([]byte, error) {
	if credentialCACert != "" {
		return []byte(credentialCACert), nil
	}
	return certmanager.CACertPEMFromEnv()
}

// requireHTTPSPushURL rejects a push base_url that is not an absolute https
// URL without embedded credentials. The egressAllowLoopback test seam also
// admits plain http, matching the client policy.
func requireHTTPSPushURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("must be an absolute https URL")
	}
	if u.User != nil {
		return errors.New("must not embed credentials")
	}
	if u.Scheme != "https" && !(egressAllowLoopback && u.Scheme == "http") {
		return errors.New("must use https")
	}
	return nil
}

// devicePushClient is the explicit test client, else the guarded default.
func (e *RenewalExecutor) devicePushClient() *http.Client {
	if e.pushClient != nil {
		return e.pushClient
	}
	return pushDeviceHTTPClient(nil)
}

func (e *RenewalExecutor) resolvePushCredential(ctx context.Context, ref, installMode string) (pushCredentialPayload, error) {
	meta, err := e.creds.Get(ctx, ref)
	if err != nil {
		return pushCredentialPayload{}, fmt.Errorf("credential %q: %w", ref, err)
	}
	// The credential type is install-mode specific: IIS authenticates the
	// WinRM channel with a windows_password (username+password); the HTTP
	// device pushers (f5/citrix/k8s) use an api_token. Before this, the
	// windows_password type the whole W18 wave added was rejected here, so
	// no IIS target could ever be pushed to — the credential existed but the
	// consumer refused it.
	wantType := CredentialTypeAPIToken
	if isWinRMPushMode(installMode) {
		wantType = CredentialTypeWindowsPassword
	}
	if meta.CredentialType != wantType {
		return pushCredentialPayload{}, fmt.Errorf("%w: credential %q has type %q, %s targets need %q", errRenewalBadCredential, ref, meta.CredentialType, installMode, wantType)
	}
	plaintext, err := e.creds.Resolve(ctx, ref)
	if err != nil {
		return pushCredentialPayload{}, fmt.Errorf("credential %q: %w", ref, err)
	}
	defer zeroize(plaintext)
	var payload pushCredentialPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return pushCredentialPayload{}, fmt.Errorf("%w: not the documented push JSON shape (base_url + per-type fields)", errRenewalBadCredential)
	}
	if payload.BaseURL == "" {
		return pushCredentialPayload{}, fmt.Errorf("%w: base_url is required", errRenewalBadCredential)
	}
	// Refuse a bad service list now: the push runs after the renewal, and a
	// typo here must not burn a serial.
	if installMode == "exchange" {
		if _, err := agentinstall.NormalizeExchangeServices(payload.Services); err != nil {
			return pushCredentialPayload{}, fmt.Errorf("%w: %v", errRenewalBadCredential, err)
		}
	}
	// The F5/Citrix/Kubernetes push sends device credentials and the renewed
	// private key to base_url, so plain http would put them on the wire in
	// clear. (IIS is a WinRM endpoint with its own transport message
	// encryption and is validated by its own client.) The egress client
	// enforces the same rule at dial time; this fails early with a clear error.
	if !isWinRMPushMode(installMode) {
		if err := requireHTTPSPushURL(payload.BaseURL); err != nil {
			return pushCredentialPayload{}, fmt.Errorf("%w: base_url: %v", errRenewalBadCredential, err)
		}
	}
	return payload, nil
}

// executePushRenewal is the push-mode path: renew, then push through the
// matching agentinstall pusher. Push failures after renewal are reported
// IN the result (the S-50 rule) — the successor exists either way.
func (e *RenewalExecutor) executePushRenewal(ctx context.Context, fingerprint string, target ManagedTarget, profile RenewalInstallProfile) (result RenewalExecuteResult, err error) {
	result = RenewalExecuteResult{PredecessorFingerprint: fingerprint}
	if mode, _ := effectiveKeyHandlingMode(target); mode == KeyModeClientCSR {
		return result, errRenewalKeyModeMismatch
	}
	if strings.TrimSpace(target.CredentialRef) == "" {
		return result, errRenewalNoCredential
	}
	if e.creds == nil {
		return result, errors.New("outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
	}
	// Resolve BEFORE renewing: a misconfigured device must not burn a
	// serial and leave a successor nothing installs.
	if target.InstallMode == "plugin" {
		if _, perr := e.preparePlugin(ctx, target); perr != nil {
			return result, perr
		}
	} else if _, cerr := e.resolvePushCredential(ctx, target.CredentialRef, target.InstallMode); cerr != nil {
		return result, cerr
	}

	detail, ok, err := e.certs.GetCertificate(ctx, fingerprint)
	if err != nil {
		return result, err
	}
	if !ok {
		return result, errCertificateNotFound
	}
	// Resolved once: the registry build lists every connector row.
	reg, regErr := e.pinnedRegistry(ctx, detail)
	key, keyPEM, csrPEM, err := generateRenewalKeyAndCSR(detail.CertificateItem, renewalKeyAlgorithmFor(reg, detail))
	if err != nil {
		return result, fmt.Errorf("generate key/csr: %w", err)
	}
	e.appendKeyAudit(ctx, "key.generate_for_renewal", fingerprint, AuditOutcomeSuccess, "target="+target.ID+" mode=hub_generated")
	defer func() {
		e.wipeKey(keyPEM)
		e.appendKeyAudit(ctx, "key.zeroize", fingerprint, AuditOutcomeSuccess,
			"target="+target.ID+" installed="+strconv.FormatBool(result.Renewed && installSucceeded(result.InstallOutcome)))
	}()

	newFP, chainPEM, err := e.renewMaterial(ctx, fingerprint, detail, reg, regErr, key, csrPEM)
	if err != nil {
		return result, err
	}
	result.Renewed = true
	result.NewFingerprint = newFP

	if chainPEM == nil {
		download, derr := e.certs.DownloadCertificate(ctx, newFP, "pem", true)
		if derr != nil {
			result.InstallOutcome = "install_skipped"
			result.InstallDetail = fmt.Sprintf("renewed but could not fetch certificate bytes: %v", derr)
			return result, nil
		}
		chainPEM = download.Body
	}
	leafFP, err := leafFingerprint(chainPEM)
	if err != nil {
		result.InstallOutcome = "install_skipped"
		result.InstallDetail = fmt.Sprintf("renewed but certificate bytes unparseable: %v", err)
		return result, nil
	}
	installRes, pushErr := e.pushMaterialToTarget(ctx, target, profile, chainPEM, keyPEM, leafFP)
	result.InstallOutcome = installRes.Outcome
	result.InstallDetail = boundInstallDetail(installRes.Detail)
	result.Verified = installRes.Verified
	if pushErr != nil && result.InstallDetail == "" {
		result.InstallDetail = boundInstallDetail(pushErr.Error())
	}
	return result, nil
}

// pushMaterialToTarget installs ALREADY-RENEWED material on one target.
//
// W17-07 split this out of executePushRenewal, which renews on every
// call. A coordinated rollout must push ONE certificate to every node in
// the cluster — calling the renewing path per node would issue a
// different certificate to each, destroying the shared identity that
// makes the cluster a cluster. Renew once, push many.
func (e *RenewalExecutor) pushMaterialToTarget(ctx context.Context, target ManagedTarget, profile RenewalInstallProfile, chainPEM, keyPEM []byte, leafFP string) (agentinstall.InstallResult, error) {
	if target.InstallMode == "plugin" {
		return e.pushViaPlugin(ctx, target, profile, chainPEM, keyPEM, leafFP)
	}
	payload, err := e.resolvePushCredential(ctx, target.CredentialRef, target.InstallMode)
	if err != nil {
		return agentinstall.InstallResult{}, err
	}
	verifyHostPort := profile.VerifyHostPort
	if verifyHostPort == "" {
		verifyHostPort = net.JoinHostPort(target.Host, defaultVerifyPort(target.InstallMode, payload))
	}
	req := agentinstall.PushRequest{
		Name:                pushObjectName(target.Name),
		CertPEM:             chainPEM,
		KeyPEM:              keyPEM,
		VerifyHostPort:      verifyHostPort,
		ExpectedFingerprint: leafFP,
	}

	var installRes agentinstall.InstallResult
	var pushErr error
	switch target.InstallMode {
	case "f5":
		p := agentinstall.NewF5Pusher(agentinstall.F5Config{
			BaseURL: payload.BaseURL, Username: payload.Username, Password: payload.Password,
			ClientSSLProfile: payload.ClientSSLProfile,
		}, e.devicePushClient())
		if e.verifier != nil {
			p = p.WithVerifier(e.verifier)
		}
		installRes, pushErr = p.Push(ctx, req)
	case "citrix":
		p := agentinstall.NewCitrixPusher(agentinstall.CitrixConfig{
			BaseURL: payload.BaseURL, Username: payload.Username, Password: payload.Password,
			CertKeyName: payload.CertKeyName,
		}, e.devicePushClient())
		if e.verifier != nil {
			p = p.WithVerifier(e.verifier)
		}
		installRes, pushErr = p.Push(ctx, req)
	case "iis":
		// The IIS installer drives the host entirely through an Executor,
		// so a Linux hub can install to a remote Windows box over WinRM.
		// (It used to be unreachable off Windows: the file was named
		// iis_windows.go, and that suffix is a build constraint in its own
		// right — see agentinstall/iis.go.)
		// W18-06: a WinRM listener is commonly fronted by a certificate
		// this product issued, which the system roots do not know about.
		// A bad bundle fails the install rather than quietly downgrading
		// to system roots — misconfigured trust must not look like a
		// healthy install that happens to verify differently.
		winExec, werr := e.winRMExecutor(payload)
		if werr != nil {
			return agentinstall.InstallResult{}, werr
		}
		inst := agentinstall.NewIISInstaller(winExec)
		if e.verifier != nil {
			inst = inst.WithVerifier(e.verifier)
		}
		installRes, pushErr = inst.Install(ctx, agentinstall.IISInstallRequest{
			IPPort:              payload.IPPort,
			AppID:               payload.AppID,
			StoreName:           payload.StoreName,
			CertPEM:             chainPEM,
			KeyPEM:              keyPEM,
			VerifyHostPort:      verifyHostPort,
			ExpectedFingerprint: leafFP,
		})
	case "sqlserver":
		// W35-02. A plain TLS dial never reaches SQL Server's certificate,
		// so verification uses the TDS-aware verifier, not e.verifier.
		winExec, werr := e.winRMExecutor(payload)
		if werr != nil {
			return agentinstall.InstallResult{}, werr
		}
		inst := agentinstall.NewSQLServerInstaller(winExec)
		if e.tdsVerifier != nil {
			inst = inst.WithVerifier(e.tdsVerifier)
		}
		installRes, pushErr = inst.Install(ctx, agentinstall.SQLServerInstallRequest{
			Instance:            payload.SQLInstance,
			CertPEM:             chainPEM,
			KeyPEM:              keyPEM,
			VerifyHostPort:      verifyHostPort,
			ExpectedFingerprint: leafFP,
		})
	case "rdp":
		// W35-04. The verifier negotiates X.224 before TLS, so it is not
		// e.verifier either.
		winExec, werr := e.winRMExecutor(payload)
		if werr != nil {
			return agentinstall.InstallResult{}, werr
		}
		inst := agentinstall.NewRDPInstaller(winExec)
		if e.rdpVerifier != nil {
			inst = inst.WithVerifier(e.rdpVerifier)
		}
		installRes, pushErr = inst.Install(ctx, agentinstall.RDPInstallRequest{
			CertPEM:             chainPEM,
			KeyPEM:              keyPEM,
			VerifyHostPort:      verifyHostPort,
			ExpectedFingerprint: leafFP,
		})
	case "exchange":
		// W35-03: HTTPS (OWA) and SMTP STARTTLS are both verified.
		winExec, werr := e.winRMExecutor(payload)
		if werr != nil {
			return agentinstall.InstallResult{}, werr
		}
		inst := agentinstall.NewExchangeInstaller(winExec)
		if e.verifier != nil {
			inst = inst.WithVerifiers(e.verifier, e.verifier)
		}
		installRes, pushErr = inst.Install(ctx, agentinstall.ExchangeInstallRequest{
			Services:            payload.Services,
			CertPEM:             chainPEM,
			KeyPEM:              keyPEM,
			VerifyHostPort:      verifyHostPort,
			SMTPVerifyHostPorts: smtpVerifyHostPorts(target.Host, payload.SMTPPorts),
			ExpectedFingerprint: leafFP,
		})
	case "k8s":
		// W19-17: a real API server (self-signed cluster CA, e.g. kind)
		// could only be reached through a kubectl proxy before this --
		// K8sConfig had no CA-trust mechanism of its own, unlike
		// discovery's certmanager.Connector. No skip-verify option is
		// added: a target with a self-signed CA that provides no bundle
		// simply fails TLS verification, like any other misconfigured
		// target.
		caPEM, caErr := resolveK8sCACert(payload.CACert)
		if caErr != nil {
			return agentinstall.InstallResult{}, caErr
		}
		p, err := agentinstall.NewK8sPusher(agentinstall.K8sConfig{
			BaseURL: payload.BaseURL, BearerToken: payload.BearerToken,
			Namespace: payload.Namespace, SecretName: payload.SecretName,
			CACertPEM: caPEM,
		}, e.pushClient)
		if err != nil {
			return agentinstall.InstallResult{}, err
		}
		if e.verifier != nil {
			p = p.WithVerifier(e.verifier)
		}
		installRes, pushErr = p.Push(ctx, req)
	}
	return installRes, pushErr
}

// winRMExecutor builds the WinRM-backed Executor for a Windows push target.
// W18-06: a WinRM listener is commonly fronted by a certificate this product
// issued, which the system roots do not know about. A bad trust bundle fails
// the install rather than quietly downgrading to system roots -- misconfigured
// trust must not look like a healthy install that happens to verify
// differently.
func (e *RenewalExecutor) winRMExecutor(payload pushCredentialPayload) (*agentinstall.WinRMExecutor, error) {
	winrmRoots, err := agentdiscovery.WinRMRootCAsFromEnv()
	if err != nil {
		return nil, err
	}
	shell := agentdiscovery.NewWSManShell(agentdiscovery.WinRMConfig{
		EndpointURL: payload.BaseURL,
		Username:    payload.Username,
		Password:    payload.Password,
		RootCAs:     winrmRoots,
	}, e.pushClient)
	return agentinstall.NewWinRMExecutor(shell), nil
}

// defaultVerifyPort is the port the verify-after-install dial uses when the
// target states none: the service's own listener, not 443.
func defaultVerifyPort(installMode string, payload pushCredentialPayload) string {
	switch installMode {
	case "sqlserver":
		if payload.SQLPort > 0 {
			return strconv.Itoa(int(payload.SQLPort))
		}
		return "1433"
	case "rdp":
		return "3389"
	}
	return "443"
}

// smtpVerifyHostPorts lists host:port probes for the SMTP STARTTLS check:
// the configured ports, else the MTA port and the client submission port.
func smtpVerifyHostPorts(host string, ports []int) []string {
	if len(ports) == 0 {
		ports = []int{25, 587}
	}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		if p >= 1 && p <= 65535 {
			out = append(out, net.JoinHostPort(host, strconv.Itoa(p)))
		}
	}
	return out
}

// pushObjectName sanitizes a target name into a device-safe object name.
func pushObjectName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			out = append(out, r)
		case r == ' ', r == '_', r == '.':
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "kryptkeeper"
	}
	return string(out)
}

// renewedPushMaterial is one renewal's output, ready to install on any
// number of targets.
type renewedPushMaterial struct {
	NewFingerprint  string
	LeafFingerprint string
	ChainPEM        []byte
	KeyPEM          []byte
}

// renewPushMaterial performs EXACTLY ONE renewal and returns the material
// to install. W17-07 needs this because a coordinated rollout must push
// the SAME certificate to every node in a cluster; renewing per node
// would give each node a different identity.
//
// The caller owns the returned KeyPEM and MUST zeroize it.
func (e *RenewalExecutor) renewPushMaterial(ctx context.Context, fingerprint string) (renewedPushMaterial, error) {
	var out renewedPushMaterial
	detail, ok, err := e.certs.GetCertificate(ctx, fingerprint)
	if err != nil {
		return out, err
	}
	if !ok {
		return out, errCertificateNotFound
	}
	// Resolved once: the registry build lists every connector row.
	reg, regErr := e.pinnedRegistry(ctx, detail)
	key, keyPEM, csrPEM, err := generateRenewalKeyAndCSR(detail.CertificateItem, renewalKeyAlgorithmFor(reg, detail))
	if err != nil {
		return out, fmt.Errorf("generate key/csr: %w", err)
	}
	newFP, chainPEM, err := e.renewMaterial(ctx, fingerprint, detail, reg, regErr, key, csrPEM)
	if err != nil {
		zeroize(keyPEM)
		return out, err
	}
	if chainPEM == nil {
		download, derr := e.certs.DownloadCertificate(ctx, newFP, "pem", true)
		if derr != nil {
			zeroize(keyPEM)
			return out, fmt.Errorf("renewed but could not fetch certificate bytes: %w", derr)
		}
		chainPEM = download.Body
	}
	leafFP, err := leafFingerprint(chainPEM)
	if err != nil {
		zeroize(keyPEM)
		return out, fmt.Errorf("renewed but certificate bytes unparseable: %w", err)
	}
	return renewedPushMaterial{NewFingerprint: newFP, LeafFingerprint: leafFP, ChainPEM: chainPEM, KeyPEM: keyPEM}, nil
}

// maxInstallDetailBytes bounds install_detail: a Tomcat configtest failure
// dumps a ~4 KB stack trace into a field that is stored in the audit trail
// and returned on every renewal response.
const maxInstallDetailBytes = 1024

const installDetailTruncMarker = "...[truncated]"

// boundInstallDetail redacts the named secrets FIRST and truncates after, so a
// cut can never expose a secret's prefix, and never lands inside a
// "[redacted]" token (which would leave a dangling fragment that reads as if
// a different value had been masked).
func boundInstallDetail(detail string, secrets ...string) string {
	detail = redact(detail, secrets...)
	if len(detail) <= maxInstallDetailBytes {
		return detail
	}
	cut := maxInstallDetailBytes - len(installDetailTruncMarker)
	for cut > 0 && !utf8.RuneStart(detail[cut]) {
		cut--
	}
	const tok = "[redacted]"
	if i := strings.LastIndex(detail[:cut], "["); i >= 0 && strings.HasPrefix(detail[i:], tok) && i+len(tok) > cut {
		cut = i
	}
	return detail[:cut] + installDetailTruncMarker
}
