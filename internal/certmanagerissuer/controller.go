// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certmanagerissuer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// unreachableAlertThreshold is the number of consecutive hub failures that
// fires the certmanager.issuer.unreachable alert (once per outage).
const unreachableAlertThreshold = 5

// hubCallTimeout bounds a single hub issuance call.
const hubCallTimeout = 30 * time.Second

// certManagerAlertHook raises operator alerts. The default logs; tests swap it.
var certManagerAlertHook = func(code, detail string) {
	logging.Infof("ALERT %s: %s", code, detail)
}

// certManagerAuditHook records issuer-side audit events. The default logs;
// the hub records its own certificate.issue failure row for the same call.
var certManagerAuditHook = func(action, resource, detail string) {
	logging.Infof("AUDIT %s %s %s", action, resource, detail)
}

// Controller reconciles CertificateRequests via list+watch and issues
// certificates through the Kryptkeeper Hub.
type Controller struct {
	K8sClient      *K8sClient
	Issuer         IssuerConfig
	Namespaces     []string // empty = all namespaces
	ResyncInterval time.Duration

	now        func() time.Time // injectable clock; nil = time.Now
	retryBase  time.Duration    // initial re-list delay after a watch failure
	retryTick  time.Duration    // how often due backoff retries are scanned
	backoff    *backoff
	failMu     sync.Mutex
	hubFailing int // consecutive hub failures (guarded by failMu)
}

// NewController returns a Controller with sensible defaults.
func NewController(k8s *K8sClient, issuer IssuerConfig, namespaces []string) *Controller {
	return &Controller{
		K8sClient:      k8s,
		Issuer:         issuer,
		Namespaces:     namespaces,
		ResyncInterval: 5 * time.Minute,
		retryBase:      time.Second,
		retryTick:      time.Second,
		backoff:        newBackoff(),
	}
}

func (c *Controller) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func crKey(cr *CertificateRequest) string {
	return cr.Metadata.Namespace + "/" + cr.Metadata.Name
}

// Run starts one list+watch loop per namespace, a periodic resync and the
// backoff retry scanner. Blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	logging.Infof("certmanager-issuer: starting; hub=%s ca=%s template=%s",
		c.Issuer.HubURL, c.Issuer.CAID, c.Issuer.TemplateID)

	namespaces := c.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{""}
	}

	var wg sync.WaitGroup
	for _, ns := range namespaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runNamespace(ctx, ns)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.maintain(ctx)
	}()
	wg.Wait()
	return ctx.Err()
}

// maintain runs the safety-net resync and the backoff retry scanner.
func (c *Controller) maintain(ctx context.Context) {
	resync := time.NewTicker(c.ResyncInterval)
	defer resync.Stop()
	retry := time.NewTicker(c.retryTick)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-resync.C:
			if err := c.reconcileAll(ctx); err != nil {
				logging.Infof("certmanager-issuer: resync error: %v", err)
			}
		case <-retry.C:
			c.retryDue(ctx)
		}
	}
}

// runNamespace lists, then watches from the list's resourceVersion. A watch
// that ends cleanly is resumed from the last seen version; any failure or an
// expired version triggers a capped-exponential wait and a fresh list.
func (c *Controller) runNamespace(ctx context.Context, ns string) {
	delay := c.retryBase
	for ctx.Err() == nil {
		rv, err := c.listAndReconcile(ctx, ns)
		if err == nil {
			for ctx.Err() == nil {
				err = c.K8sClient.WatchCertificateRequests(ctx, ns, rv, func(ev WatchEvent) error {
					return c.handleEvent(ctx, ev, &rv)
				})
				if err != nil {
					break
				}
				delay = c.retryBase
			}
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrWatchExpired) {
			logging.Infof("certmanager-issuer: watch expired (ns=%q); re-listing", ns)
		} else {
			logging.Infof("certmanager-issuer: watch/list (ns=%q): %v", ns, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay *= 2; delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}

// listAndReconcile lists CertificateRequests, reconciles pending ones and
// returns the list resourceVersion to watch from.
func (c *Controller) listAndReconcile(ctx context.Context, ns string) (string, error) {
	list, err := c.K8sClient.ListCertificateRequests(ctx, ns)
	if err != nil {
		return "", err
	}
	for i := range list.Items {
		if cr := &list.Items[i]; cr.needsIssuance() {
			c.process(ctx, cr)
		}
	}
	return list.Metadata.ResourceVersion, nil
}

// handleEvent applies one watch event, advancing *rv.
func (c *Controller) handleEvent(ctx context.Context, ev WatchEvent, rv *string) error {
	switch ev.Type {
	case "ADDED", "MODIFIED", "BOOKMARK":
	default:
		return nil
	}
	var cr CertificateRequest
	if err := json.Unmarshal(ev.Object, &cr); err != nil {
		return fmt.Errorf("decode %s object: %w", ev.Type, err)
	}
	if v := cr.Metadata.ResourceVersion; v != "" {
		*rv = v
	}
	if ev.Type != "BOOKMARK" && cr.needsIssuance() {
		c.process(ctx, &cr)
	}
	return nil
}

// reconcileAll lists all pending CertificateRequests in the configured
// namespaces and processes those targeting our issuer. It is the periodic
// resync pass.
func (c *Controller) reconcileAll(ctx context.Context) error {
	namespaces := c.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{""}
	}
	for _, ns := range namespaces {
		if _, err := c.listAndReconcile(ctx, ns); err != nil {
			logging.Infof("certmanager-issuer: list CertificateRequests (ns=%q): %v", ns, err)
		}
	}
	return nil
}

// retryDue re-processes requests whose backoff has elapsed. The watch will not
// re-deliver them, so this is what actually performs the scheduled retry.
func (c *Controller) retryDue(ctx context.Context) {
	for _, e := range c.backoff.due(c.clock()) {
		key := e.namespace + "/" + e.name
		cr, err := c.K8sClient.GetCertificateRequest(ctx, e.namespace, e.name)
		if err != nil {
			if strings.Contains(err.Error(), "status 404") {
				c.backoff.forget(key)
			} else {
				logging.Infof("certmanager-issuer: refetch %s: %v", key, err)
			}
			continue
		}
		if !cr.needsIssuance() {
			c.backoff.forget(key)
			continue
		}
		c.process(ctx, cr)
	}
}

// process runs reconcile unless the request is in backoff or already in flight.
func (c *Controller) process(ctx context.Context, cr *CertificateRequest) {
	key := crKey(cr)
	if !c.backoff.begin(key, cr.Metadata.Namespace, cr.Metadata.Name, c.clock()) {
		return
	}
	defer c.backoff.end(key)
	if err := c.reconcile(ctx, cr); err != nil {
		logging.Infof("certmanager-issuer: reconcile %s: %v", key, err)
	}
}

// reconcile processes a single CertificateRequest.
func (c *Controller) reconcile(ctx context.Context, cr *CertificateRequest) error {
	key := crKey(cr)
	logging.Infof("certmanager-issuer: issuing for %s (issuer %s/%s)",
		key, cr.Spec.IssuerRef.Kind, cr.Spec.IssuerRef.Name)

	csrPEM, err := csrToPEM(cr.Spec.Request)
	if err != nil {
		return c.deny(ctx, cr, "invalid_csr", err.Error())
	}

	certPEM, err := issueCertificate(ctx, c.Issuer, csrPEM)
	var he *HubError
	if err != nil && !errors.As(err, &he) {
		he = &HubError{Unreachable: true, Message: err.Error()}
	}
	switch {
	case he == nil:
		c.hubReachable()
		c.backoff.reset(key)
		// The hub is the approval authority: approve on success. A request
		// already approved by another approver keeps its condition (cert-manager
		// forbids modifying it).
		if !cr.isApproved() {
			cr.Status.Conditions = append(cr.Status.Conditions, Condition{
				Type: "Approved", Status: "True", LastTransitionTime: c.clock().UTC(),
				Reason: ReasonApproved, Message: "approved by the Kryptkeeper hub issuance policy",
			})
		}
		return c.K8sClient.PatchCRStatus(ctx, cr, certPEM, nil)
	case he.Unreachable:
		return c.unreachable(ctx, cr, he)
	case he.PendingApproval():
		c.hubReachable()
		c.backoff.reset(key)
		return c.patchReady(ctx, cr, ReasonPendingApproval, "approval required: "+he.Message)
	default:
		c.hubReachable()
		return c.deny(ctx, cr, he.Code, he.Message)
	}
}

// csrToPEM turns CertificateRequest.spec.request (base64 of the CSR) into PEM.
// cert-manager stores PEM bytes there, so the decoded value is normally
// already PEM and is passed through; a bare DER CSR is wrapped as a fallback.
func csrToPEM(request string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(request)
	if err != nil {
		return "", fmt.Errorf("base64 decode CSR: %v", err)
	}
	if block, _ := pem.Decode(raw); block != nil {
		return string(pem.EncodeToMemory(block)), nil
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})), nil
}

// deny records a terminal denial: Denied=True and Ready=False (reason Denied,
// which stops reprocessing), both carrying the hub's code and message.
func (c *Controller) deny(ctx context.Context, cr *CertificateRequest, code, message string) error {
	key := crKey(cr)
	c.backoff.reset(key)
	msg := message
	if code != "" {
		msg = code + ": " + message
	}
	logging.Warnf("certmanager-issuer: denied %s: %s", key, msg)
	certManagerAuditHook("certmanager.request.deny", key, msg)
	now := c.clock().UTC()
	ready := Condition{Type: "Ready", Status: "False", LastTransitionTime: now, Reason: ReasonDenied, Message: msg}
	if cr.isApproved() {
		// cert-manager's webhook rejects Denied on an approved request;
		// Ready=False/Denied is the terminal marker instead.
		return c.K8sClient.PatchCRConditions(ctx, cr, ready)
	}
	return c.K8sClient.PatchCRConditions(ctx, cr,
		Condition{Type: "Denied", Status: "True", LastTransitionTime: now, Reason: ReasonDenied, Message: msg},
		ready,
	)
}

// unreachable records a retriable hub outage: Ready=False/Pending, a backoff
// retry, and the consecutive-failure alert.
func (c *Controller) unreachable(ctx context.Context, cr *CertificateRequest, he *HubError) error {
	key := crKey(cr)
	delay := c.backoff.fail(key, cr.Metadata.Namespace, cr.Metadata.Name, c.clock())
	logging.Infof("certmanager-issuer: hub unreachable for %s: %v; retry in %s", key, he, delay)

	c.failMu.Lock()
	c.hubFailing++
	fire := c.hubFailing == unreachableAlertThreshold
	c.failMu.Unlock()
	if fire {
		certManagerAlertHook("certmanager.issuer.unreachable", c.Issuer.HubURL)
	}
	return c.patchReady(ctx, cr, ReasonPending, "hub unreachable: "+he.Message)
}

func (c *Controller) hubReachable() {
	c.failMu.Lock()
	c.hubFailing = 0
	c.failMu.Unlock()
}

func (c *Controller) patchReady(ctx context.Context, cr *CertificateRequest, reason, message string) error {
	return c.K8sClient.PatchCRConditions(ctx, cr, Condition{
		Type: "Ready", Status: "False", LastTransitionTime: c.clock().UTC(),
		Reason: reason, Message: message,
	})
}

// issueCertificate calls the Kryptkeeper Hub to issue a certificate for the
// CSR. Failures are always *HubError (see its doc for classification).
func issueCertificate(ctx context.Context, cfg IssuerConfig, csrPEM string) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"ca_id":       cfg.CAID,
		"template_id": cfg.TemplateID,
		"csr_pem":     csrPEM,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, hubCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(cfg.HubURL, "/")+"/api/v1/certificates",
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIToken)

	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &HubError{Unreachable: true, Message: err.Error()}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, &HubError{Status: resp.StatusCode, Unreachable: true, Message: "read response: " + err.Error()}
	}
	certPEM, fingerprint, err := parseHubResponse(resp.StatusCode, respBody)
	if err != nil || certPEM != nil {
		return certPEM, err
	}
	// The hub's issue response carries the inventory item, not the PEM.
	return downloadCertificate(ctx, hc, cfg, fingerprint)
}

// downloadCertificate fetches the issued certificate (leaf plus intermediates)
// as PEM. A failure after a successful issue is retriable: the hub answers the
// repeated request with the existing certificate (200, W26-32) rather than
// signing again.
func downloadCertificate(ctx context.Context, hc *http.Client, cfg IssuerConfig, fingerprint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(cfg.HubURL, "/")+"/api/v1/certificates/"+url.PathEscape(fingerprint)+"/download?format=pem&include_chain=true", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &HubError{Unreachable: true, Message: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, &HubError{Status: resp.StatusCode, Unreachable: true, Message: "read certificate download: " + err.Error()}
	}
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		return nil, &HubError{Status: resp.StatusCode, Unreachable: true,
			Message: "certificate download failed: " + strings.TrimSpace(string(body))}
	}
	return body, nil
}

// parseHubResponse classifies a hub response (split out for table testing).
// A success returns the certificate PEM when the body carries one, otherwise
// the issued certificate's fingerprint for the caller to download.
func parseHubResponse(status int, respBody []byte) ([]byte, string, error) {
	switch status {
	case http.StatusCreated, http.StatusOK:
		var result struct {
			Data struct {
				CertificatePEM string `json:"certificate_pem"`
				Fingerprint    string `json:"fingerprint_sha256"`
			} `json:"data"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, "", &HubError{Status: status, Unreachable: true, Message: "decode response: " + err.Error()}
		}
		if result.Data.CertificatePEM != "" {
			return []byte(result.Data.CertificatePEM), "", nil
		}
		if result.Data.Fingerprint == "" {
			return nil, "", &HubError{Status: status, Unreachable: true, Message: "response has neither certificate_pem nor fingerprint_sha256"}
		}
		return nil, result.Data.Fingerprint, nil

	case http.StatusAccepted:
		var r struct {
			ApprovalID string `json:"approval_id"`
			Data       struct {
				ApprovalID string `json:"approval_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(respBody, &r); err != nil {
			logging.Infof("certmanager-issuer: decode 202 body: %v", err)
		}
		id := r.ApprovalID
		if id == "" {
			id = r.Data.ApprovalID
		}
		return nil, "", &HubError{Status: status, Code: "pending_approval", Message: "approval_id=" + id}

	case http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusUnprocessableEntity:
		he := &HubError{Status: status}
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Detail  string `json:"detail"` // RFC 7807 form
		}
		if json.Unmarshal(respBody, &e) == nil {
			he.Code = e.Error
			he.Message = e.Message
			if he.Message == "" {
				he.Message = e.Detail
			}
		}
		if he.Code == "" && he.Message == "" {
			he.Message = strings.TrimSpace(string(respBody))
		}
		return nil, "", he

	default:
		// 5xx, 429 and unexpected statuses (e.g. 401 from a bad token) are
		// retriable: an operator fix should recover without manual action.
		return nil, "", &HubError{Status: status, Unreachable: true, Message: strings.TrimSpace(string(respBody))}
	}
}
