// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// k8sVerifyRetryAttempts/k8sVerifyRetryDelay bound the retry-until-match
// loop below. A kubelet propagates an updated Secret into a Pod's mounted
// volume on its own sync cadence -- observed live (W19-03, kind v1.37):
// the API server accepts the write immediately, but a workload dialed
// right after can still be serving the pre-push leaf for tens of seconds.
// Unlike installer.go's nginx/apache reload race (verifyRetryAttempts, a
// sub-2s in-process handover), this is a kubelet-to-kubelet propagation
// delay with no reload signal to wait on.
//
// W19-17: the original 40*1.5s=60s budget still timed out live on kind
// (verify_failed, served fingerprint never caught up) even after the two
// unrelated defects that were masking this window's real size were fixed
// -- server.go's global 15s WriteTimeout truncating the HTTP response
// (handlers_renewal_execute.go now extends the per-connection deadline)
// and discovery_scanner_provider.go passing a request-scoped context into
// a goroutine net/http cancels when the handler returns (unrelated to
// this retry loop, but found investigating the same UAT run). kubelet's
// two documented knobs stack against a Secret volume update: the
// sync-frequency resync period (default 1m) and the secret manager's TTL
// cache (default 1m) can combine to ~2 minutes worst case, comfortably
// past the old 60s. 90 attempts * 1.5s = 135s covers that with margin.
const (
	k8sVerifyRetryAttempts = 90
	k8sVerifyRetryDelay    = 1500 * time.Millisecond
)

// W5-04: agentless push of a renewed certificate into a Kubernetes
// cluster as a kubernetes.io/tls Secret, via the core REST API with a
// bearer token — deliberately no client-go (no new dependency; the
// Secrets API is plain REST and the injectable http.Client carries the
// cluster-CA trust). Istio ingress-gateway serving certs ARE such
// secrets (the Gateway's credentialName, hot-reloaded by istiod's SDS),
// so pointing this at that secret in the gateway namespace covers the
// mesh-edge path. Workload mTLS identities are minted by istiod itself
// and cannot be pushed from outside the mesh — out of scope here.

// K8sConfig locates and authenticates the cluster.
type K8sConfig struct {
	// BaseURL is the API server, e.g. https://k8s.example.com:6443
	// (no trailing slash).
	BaseURL string
	// BearerToken authenticates every request.
	BearerToken string
	Namespace   string
	// SecretName is the kubernetes.io/tls Secret to create or replace
	// (for Istio gateways: the Gateway's credentialName).
	SecretName string
	// CACertPEM, when set, replaces the system root store so a push
	// target's own cluster CA (self-signed, e.g. kind) verifies without a
	// kubectl proxy in front of it -- W19-03 found no way to reach a real
	// API server otherwise. No skip-verify escape hatch exists anywhere in
	// this pusher: an API server whose CA isn't provided here just fails
	// TLS verification, the same as any other misconfigured push target.
	CACertPEM []byte
}

// K8sPusher drives the push; http.Client injectable as with F5/Citrix.
type K8sPusher struct {
	cfg    K8sConfig
	client *http.Client
	verify Verifier
	// retryAttempts/retryDelay are fields (not the k8sVerify* consts
	// directly) so tests can shrink the ~60s worst case to milliseconds —
	// see TestK8sVerifyMismatch* below, which exercise a PERMANENT
	// mismatch and would otherwise pay the full retry window.
	retryAttempts int
	retryDelay    time.Duration
}

// NewK8sPusher builds the pusher. A non-nil client wins outright (tests'
// httptest client, which already trusts the fixture's certificate);
// cfg.CACertPEM only shapes the client this constructs itself for the
// nil case, which is what production takes. A CA bundle that fails to
// parse is refused HERE, at construction, rather than surfacing as a
// confusing TLS error on the first real push.
func NewK8sPusher(cfg K8sConfig, client *http.Client) (*K8sPusher, error) {
	if client == nil {
		if len(cfg.CACertPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
				return nil, fmt.Errorf("k8s push: CA bundle contains no usable PEM certificate")
			}
			client = guardedPushClient(pool)
		} else {
			client = guardedPushClient(nil)
		}
	}
	return &K8sPusher{
		cfg: cfg, client: client, verify: defaultVerifier,
		retryAttempts: k8sVerifyRetryAttempts, retryDelay: k8sVerifyRetryDelay,
	}, nil
}

func (p *K8sPusher) WithVerifier(v Verifier) *K8sPusher { p.verify = v; return p }

func (p *K8sPusher) secretsPath() string {
	return "/api/v1/namespaces/" + p.cfg.Namespace + "/secrets"
}

func (p *K8sPusher) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.BearerToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // error surfaces via the status code
	return resp.StatusCode, out, nil
}

// mergeResourceVersion copies metadata.resourceVersion from `current` (a
// freshly-GETed object) into a copy of `prior` (a captured-earlier
// manifest), so a rollback PUT targets the object's actual current version
// instead of replaying a now-stale one and drawing a 409 Conflict.
func mergeResourceVersion(prior, current []byte) ([]byte, error) {
	var priorObj, currentObj map[string]any
	if err := json.Unmarshal(prior, &priorObj); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(current, &currentObj); err != nil {
		return nil, err
	}
	currentMeta, _ := currentObj["metadata"].(map[string]any)
	rv, ok := currentMeta["resourceVersion"]
	if !ok {
		return prior, nil // nothing to merge; caller's PUT will surface any real error
	}
	priorMeta, _ := priorObj["metadata"].(map[string]any)
	if priorMeta == nil {
		priorMeta = map[string]any{}
		priorObj["metadata"] = priorMeta
	}
	priorMeta["resourceVersion"] = rv
	return json.Marshal(priorObj)
}

func (p *K8sPusher) tlsSecretManifest(req PushRequest) []byte {
	manifest, _ := json.Marshal(map[string]any{ // fixed-shape map: cannot fail
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]string{"name": p.cfg.SecretName, "namespace": p.cfg.Namespace},
		"type":       "kubernetes.io/tls",
		"data": map[string]string{
			"tls.crt": base64.StdEncoding.EncodeToString(req.CertPEM),
			"tls.key": base64.StdEncoding.EncodeToString(req.KeyPEM),
		},
	})
	return manifest
}

// Push creates or replaces the TLS secret, verifies what the endpoint
// serves, and restores the pre-push cluster state on a mismatch.
func (p *K8sPusher) Push(ctx context.Context, req PushRequest) (InstallResult, error) {
	// Both names are spliced into the API path; Kubernetes itself only
	// allows DNS-1123 names, so anything else (a "/" or "..") is refused here
	// rather than letting the request address a different API resource.
	if !k8sNamespacePattern.MatchString(p.cfg.Namespace) || len(p.cfg.Namespace) > 63 {
		return InstallResult{}, fmt.Errorf("k8s push: namespace %q is not a valid DNS-1123 label", p.cfg.Namespace)
	}
	if !k8sSecretNamePattern.MatchString(p.cfg.SecretName) || len(p.cfg.SecretName) > 253 {
		return InstallResult{}, fmt.Errorf("k8s push: secret name %q is not a valid DNS-1123 subdomain", p.cfg.SecretName)
	}
	if len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return InstallResult{}, fmt.Errorf("k8s push: cert and key are required")
	}
	namedPath := p.secretsPath() + "/" + p.cfg.SecretName

	// Capture the prior manifest (rollback material) and learn whether
	// this is a first install.
	status, prior, err := p.do(ctx, http.MethodGet, namedPath, nil)
	if err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, err
	}
	var existed bool
	switch status {
	case http.StatusOK:
		existed = true
	case http.StatusNotFound:
		existed = false
	default:
		detail := fmt.Sprintf("k8s GET %s: HTTP %d: %s", namedPath, status, truncateBody(prior))
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: detail}, fmt.Errorf("%s", detail)
	}

	manifest := p.tlsSecretManifest(req)
	if existed {
		// PUT with no resourceVersion = unconditional replace, the
		// desired semantic for a renewal.
		status, out, err := p.do(ctx, http.MethodPut, namedPath, manifest)
		if err != nil || status >= 300 {
			detail := fmt.Sprintf("k8s PUT %s: HTTP %d %s %v", namedPath, status, truncateBody(out), err)
			return InstallResult{Outcome: OutcomeWriteFailed, Detail: detail}, fmt.Errorf("%s", detail)
		}
	} else {
		status, out, err := p.do(ctx, http.MethodPost, p.secretsPath(), manifest)
		if err != nil || status >= 300 {
			detail := fmt.Sprintf("k8s POST %s: HTTP %d %s %v", p.secretsPath(), status, truncateBody(out), err)
			return InstallResult{Outcome: OutcomeWriteFailed, Detail: detail}, fmt.Errorf("%s", detail)
		}
	}

	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, verr := p.verifyUntilMatchOrExhausted(ctx, req.VerifyHostPort, req.ExpectedFingerprint)
		if verr != nil || normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			// Restore the pre-push state: replace with the captured
			// manifest, or delete a secret that did not exist before.
			// RolledBack must reflect the RESTORE's actual outcome — a
			// failed restore leaves the cluster on the unverified cert,
			// and a false RolledBack would tell the operator otherwise.
			// do() surfaces a bad status via the return code, not an
			// error, so a failed restore must be detected on BOTH the
			// transport error AND status>=300.
			var rbStatus int
			var rberr error
			if existed {
				// The Secret's resourceVersion in `prior` is now stale --
				// the write above that just failed verification also
				// advanced it (Kubernetes' optimistic concurrency), so
				// replaying `prior` verbatim gets a 409 Conflict every
				// time, not just on a race. Re-GET the CURRENT object
				// immediately before restoring and carry ITS
				// resourceVersion into the restore payload.
				restorePayload := prior
				if _, current, gerr := p.do(ctx, http.MethodGet, namedPath, nil); gerr == nil {
					if merged, merr := mergeResourceVersion(prior, current); merr == nil {
						restorePayload = merged
					}
				}
				rbStatus, _, rberr = p.do(ctx, http.MethodPut, namedPath, restorePayload)
			} else {
				rbStatus, _, rberr = p.do(ctx, http.MethodDelete, namedPath, nil)
			}
			if rberr == nil && rbStatus >= 300 {
				rberr = fmt.Errorf("restore returned HTTP %d", rbStatus)
			}
			detail := "served fingerprint does not match renewed cert"
			if verr != nil {
				detail = verr.Error()
			}
			if rberr != nil {
				return InstallResult{Installed: true, Reloaded: true, RolledBack: false, ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
						Detail: detail + "; ROLLBACK FAILED (secret may still serve the unverified cert): " + rberr.Error()},
					fmt.Errorf("k8s push: verify failed AND rollback failed: %v", rberr)
			}
			return InstallResult{Installed: true, Reloaded: true, RolledBack: true, ServedFingerprint: served, Outcome: OutcomeVerifyFailed, Detail: detail},
				fmt.Errorf("k8s push: verify failed, secret %s/%s restored to pre-push state", p.cfg.Namespace, p.cfg.SecretName)
		}
		return InstallResult{Installed: true, Reloaded: true, Verified: true, ServedFingerprint: served, Outcome: OutcomeInstalledVerified}, nil
	}
	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}

// verifyUntilMatchOrExhausted calls verify up to k8sVerifyRetryAttempts
// times, stopping as soon as the served fingerprint matches expected. A
// dial error or a stale (mismatched) fingerprint both just mean "the
// kubelet hasn't propagated the Secret to the volume yet" during this
// window, so both retry the same way; only the FINAL attempt's result is
// returned, preserving Push's existing dial-error-vs-mismatch branching.
func (p *K8sPusher) verifyUntilMatchOrExhausted(ctx context.Context, hostPort, expected string) (served string, err error) {
	for attempt := 1; attempt <= p.retryAttempts; attempt++ {
		served, err = p.verify(ctx, hostPort)
		if err == nil && normalizeFingerprint(served) == normalizeFingerprint(expected) {
			return served, nil
		}
		if attempt < p.retryAttempts {
			select {
			case <-ctx.Done():
				return served, err
			case <-time.After(p.retryDelay):
			}
		}
	}
	return served, err
}

var (
	k8sNamespacePattern  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	k8sSecretNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)
