// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/logging"
)

// errWaveDeliveryUnsupported marks a Deliver refusal that is a capability gap,
// not a failure: the member is reported delivery_unsupported (manual install),
// the wave is not regressed, and the host was never touched.
var errWaveDeliveryUnsupported = errors.New("delivery unsupported")

// waveMaterialInstaller is the renewal install path (RenewalExecutor) as the
// wave deliverer sees it.
type waveMaterialInstaller interface {
	InstallMaterial(ctx context.Context, target ManagedTarget, profile RenewalInstallProfile, chainPEM, keyPEM []byte, caID string) (RenewalExecuteResult, error)
	// PushMaterial is the k8s TLS Secret path (D-315).
	PushMaterial(ctx context.Context, target ManagedTarget, profile RenewalInstallProfile, chainPEM, keyPEM []byte) (RenewalExecuteResult, error)
}

// keystoreWaveDeliverer is the production waveDeliverer (W31F-06, replaces
// unsupportedWaveDeliverer when the keystore can export software keys). It
// exports the PQC successor's private key as PKCS#8, installs chain + key
// through the renewal install path (which backs up the previous files, config
// tests, reloads, verifies the served leaf and rolls back on any failure) and
// reports what happened.
//
// Verification is the renewal verifier: a TLS dial from the hub that compares
// the SHA-256 of the served leaf with the successor's. It was checked against a
// live OpenSSL 3.5 nginx serving an ML-DSA-65 leaf (tests/live/pqc-wave); a
// server stack Go cannot handshake with fails the verify and is rolled back, so
// an unverifiable delivery is never reported as delivered.
//
// D-315 adds ssh haproxy (combined PEM) and k8s (kubernetes.io/tls Secret,
// tls.crt/tls.key PEM). Both keep the same export gate, zeroization, audit row
// and restore-on-failure; unsupported targets are told why in Supports.
type keystoreWaveDeliverer struct {
	exporter  keystore.PrivateKeyPKCS8Exporter
	certs     CertificateProvider
	installer waveMaterialInstaller
	audit     AuditProvider
	// wipeSpy is test-only: called with the DER and PEM buffers after they have
	// been zeroized so a test can assert every byte is 0.
	wipeSpy func(der, keyPEM []byte)
}

// Supports decides, from the target alone, whether a wave can deliver to it.
// Every refusal names why, so the operator knows what the manual install is.
func (d *keystoreWaveDeliverer) Supports(t ManagedTarget) (bool, string) {
	if mode, _ := effectiveKeyHandlingMode(t); mode == KeyModeClientCSR {
		return false, "target key_handling_mode is client_csr: the hub does not push keys to it; manual install"
	}
	switch t.InstallMode {
	case "ssh":
		return supportsSSHWaveTarget(t)
	case "k8s":
		if t.CredentialRef == "" {
			return false, "target has no cluster credential; manual install"
		}
		return true, ""
	case "iis", "sqlserver", "rdp", "exchange":
		// D-315. These installers import a PFX built hub-side, and Go (go-pkcs12
		// in go.mod) cannot encode an ML-DSA key into PKCS#12. Separately,
		// Microsoft documents ML-DSA TLS certificate templates for AD CS
		// (https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ml-dsa-overview)
		// but publishes no statement that Schannel serves ML-DSA certificates;
		// Windows TLS PQC work documented so far is ML-KEM key exchange only.
		return false, fmt.Sprintf("install_mode %q: the Windows installer imports a PFX the hub cannot build for an ML-DSA key, and Microsoft does not document Schannel serving ML-DSA certificates; manual install", t.InstallMode)
	case "f5", "citrix":
		return false, fmt.Sprintf("install_mode %q: ML-DSA key import is not proven on this device API; manual install", t.InstallMode)
	case "plugin":
		return false, "install_mode plugin: delivery plugins are not granted the receive_private_key capability for PQC waves; manual install"
	default:
		return false, fmt.Sprintf("install_mode %q cannot receive hub-held PQC key material; manual install", t.InstallMode)
	}
}

// supportsSSHWaveTarget covers the ssh server types whose installer writes
// PEM: nginx and apache (separate chain and key files) and haproxy (one
// combined PEM that OpenSSL 3.5 loads, checked by `haproxy -c` before reload).
func supportsSSHWaveTarget(t ManagedTarget) (bool, string) {
	if t.CredentialRef == "" {
		return false, "target has no ssh credential; manual install"
	}
	switch t.InstallServerType {
	case "nginx", "apache":
		if t.InstallCertPath == "" || t.InstallKeyPath == "" {
			return false, "target install profile must name cert and key paths; manual install"
		}
	case "haproxy":
		if t.InstallCertPath == "" {
			return false, "haproxy target must name the combined PEM path; manual install"
		}
		if t.InstallReloadMethod == "binary" {
			return false, "haproxy binary reload is not supported by the installer; use systemctl; manual install"
		}
	case "tomcat":
		// D-315. The installer only writes a PKCS#12/JKS keystore, which Go cannot
		// build around an ML-DSA key, and it does not edit server.xml, so a PEM
		// certificateFile/certificateKeyFile connector (which Tomcat supports) is
		// not something the hub can switch on. Not proven with a JDK 24 Tomcat.
		return false, "tomcat: the installer writes a PKCS#12/JKS keystore the hub cannot build for an ML-DSA key and does not reconfigure the connector for PEM files; manual install"
	default:
		return false, "target install profile must name an nginx, apache or haproxy server type; manual install"
	}
	return true, ""
}

func (d *keystoreWaveDeliverer) Deliver(ctx context.Context, t ManagedTarget, oldFP, newFP, keyID string) (waveDelivery, error) {
	dl, err := d.certs.DownloadCertificate(ctx, newFP, "pem", true)
	if err != nil {
		return waveDelivery{}, fmt.Errorf("fetch successor certificate: %w", err)
	}
	der, err := d.exporter.ExportPrivateKeyPKCS8(keyID)
	if err != nil {
		d.auditExport(ctx, newFP, AuditOutcomeFailure, "target="+t.ID+" key_id="+keyID+" reason=export refused")
		if errors.Is(err, keystore.ErrPrivateKeyNotExportable) {
			return waveDelivery{}, fmt.Errorf("%w: the successor key cannot be exported (%v); manual install", errWaveDeliveryUnsupported, err)
		}
		return waveDelivery{}, fmt.Errorf("export successor key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer func() {
		zeroize(keyPEM)
		if d.wipeSpy != nil {
			d.wipeSpy(der, keyPEM)
		}
	}()
	zeroize(der)
	d.auditExport(ctx, newFP, AuditOutcomeSuccess, "target="+t.ID+" key_id="+keyID)

	var res RenewalExecuteResult
	if t.InstallMode == "k8s" {
		res, err = d.installer.PushMaterial(ctx, t, profileFromTarget(t), dl.Body, keyPEM)
	} else {
		res, err = d.installer.InstallMaterial(ctx, t, profileFromTarget(t), dl.Body, keyPEM, "")
	}
	if err != nil {
		return waveDelivery{}, err
	}
	out := waveDelivery{Detail: res.InstallDetail}
	switch res.InstallOutcome {
	case agentinstall.OutcomeInstalledVerified:
		out.Outcome, out.Verified = waveDeliveryOK, res.Verified
	case agentinstall.OutcomeVerifyFailed, agentinstall.OutcomeConfigTestFailed, agentinstall.OutcomeReloadFailed, agentinstall.OutcomeWriteFailed:
		out.Outcome = waveDeliveryRolledBack
	case "connect_failed":
		return waveDelivery{}, fmt.Errorf("connect to target: %s", res.InstallDetail)
	default:
		// rollback_failed, or "installed" without verification: the host state
		// is not known to be either version.
		out.Outcome = waveDeliveryFailed
	}
	if out.Detail == "" {
		out.Detail = res.InstallOutcome
	} else {
		out.Detail = res.InstallOutcome + ": " + out.Detail
	}
	return out, nil
}

// auditExport records a private-key export for delivery; the entry carries the
// target and key name only, never key bytes, hashes or lengths.
func (d *keystoreWaveDeliverer) auditExport(ctx context.Context, newFP string, outcome AuditOutcome, detail string) {
	if d.audit == nil {
		return
	}
	if err := d.audit.AppendEntry(context.WithoutCancel(ctx), AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "key.export_for_delivery", ActorType: "system", ActorID: "pqc-wave",
		ResourceType: "certificate", ResourceID: newFP, Outcome: outcome, ChangeSummary: detail,
	}); err != nil {
		logging.Warnf("audit append failed action=key.export_for_delivery: %v", err)
	}
}

// newWaveDeliverer picks the production deliverer: the keystore one when the
// keystore can export software keys, otherwise every bound target is reported
// delivery_unsupported.
func newWaveDeliverer(keys keystore.Store, certs CertificateProvider, creds OutboundCredentialStore, targets ManagedTargetStore, audit AuditProvider) waveDeliverer {
	exp, ok := keys.(keystore.PrivateKeyPKCS8Exporter)
	if !ok || creds == nil {
		return unsupportedWaveDeliverer{}
	}
	ex := NewRenewalExecutor(certs, creds).WithPluginDeliverer(nil, audit)
	if targets != nil {
		ex = ex.WithTargetBlocker(targetStateBlocker{targets})
	}
	return &keystoreWaveDeliverer{exporter: exp, certs: certs, installer: ex, audit: audit}
}
