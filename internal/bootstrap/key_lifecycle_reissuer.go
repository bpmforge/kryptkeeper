// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrReissueDeferred marks a certificate the compromise flow could not
// re-issue because the hub has no managed target to push a replacement to. The
// hub never holds subject private keys, so without a target the only path is
// the subject's own re-enrolment: the certificate is reported as deferred, not
// failed.
var ErrReissueDeferred = errors.New("no managed target for certificate; re-issue deferred")

// RenewalCertReissuer is the production CertReissuer (W23-39): it renews a
// certificate on its managed target through the renewal executor, which
// generates the new key hub-side, renews through the CA (now re-keyed) and
// installs the result over the target's channel.
type RenewalCertReissuer struct {
	certs   CertificateProvider
	targets ManagedTargetStore
	exec    renewalRunner
}

// NewRenewalCertReissuer wires the reissuer. exec is normally a
// *RenewalExecutor; the narrower renewalRunner seam lets tests substitute one.
func NewRenewalCertReissuer(certs CertificateProvider, targets ManagedTargetStore, exec renewalRunner) *RenewalCertReissuer {
	return &RenewalCertReissuer{certs: certs, targets: targets, exec: exec}
}

// ReissueCertificate satisfies CertReissuer. It returns an error wrapping
// ErrReissueDeferred when no target can receive the replacement, and any other
// error when a target was found but the renewal or install did not complete.
// It does not require auto_renew: the compromise flow is dual-controlled, so
// two administrators already approved this push.
func (r *RenewalCertReissuer) ReissueCertificate(ctx context.Context, fingerprint string) error {
	detail, ok, err := r.certs.GetCertificate(ctx, fingerprint)
	if err != nil {
		return err
	}
	if !ok {
		return errCertificateNotFound
	}
	targets, err := r.targets.List(ctx)
	if err != nil {
		return fmt.Errorf("list managed targets: %w", err)
	}
	target, found := matchReissueTarget(ctx, targets, detail)
	if !found {
		return fmt.Errorf("%w: %s", ErrReissueDeferred, fingerprint)
	}

	result, err := r.exec.ExecuteRenewal(ctx, fingerprint, target, profileFromTarget(target))
	if err != nil {
		if errors.Is(err, errRenewalTargetNotSSH) {
			// An agent-mode target renews through the agent task queue, not a
			// hub push: nothing for the hub to do here.
			return fmt.Errorf("%w: %s (target %q is not hub-pushable)", ErrReissueDeferred, fingerprint, target.Name)
		}
		return fmt.Errorf("renewal on target %q: %w", target.Name, err)
	}
	if !result.Renewed {
		return fmt.Errorf("renewal on target %q did not produce a successor", target.Name)
	}
	if result.InstallOutcome != "installed_verified" && result.InstallOutcome != "installed" {
		return fmt.Errorf("renewed but install failed: successor %s exists; target %q outcome=%s %s",
			result.NewFingerprint, target.Name, result.InstallOutcome, result.InstallDetail)
	}
	return nil
}

// matchReissueTarget picks the first target that can receive cert: it holds a
// credential, its tenant may see the certificate's CA, and its host is one the
// certificate was seen on (discovery endpoints) or names (CN/SANs, the same
// heuristic the renewal sweep uses).
func matchReissueTarget(ctx context.Context, targets []ManagedTarget, cert CertificateDetail) (ManagedTarget, bool) {
	for _, t := range targets {
		if strings.TrimSpace(t.CredentialRef) == "" || strings.TrimSpace(t.Host) == "" {
			continue
		}
		if !targetMayReceiveCert(ctx, t, cert.CertificateItem) {
			continue
		}
		if targetHostsCert(t.Host, cert) {
			return t, true
		}
	}
	return ManagedTarget{}, false
}

func targetHostsCert(host string, cert CertificateDetail) bool {
	for _, ep := range cert.Endpoints {
		if strings.EqualFold(host, ep.Hostname) || (ep.IPAddress != "" && host == ep.IPAddress) {
			return true
		}
	}
	if strings.EqualFold(host, cert.CommonName) {
		return true
	}
	for _, san := range cert.SubjectAltNames {
		if strings.EqualFold(host, san) {
			return true
		}
	}
	return false
}
