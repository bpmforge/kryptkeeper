// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command cloudflare is a delivery plugin that uploads the renewed
// certificate to a Cloudflare zone as a custom certificate and makes it the
// one served for a hostname. Cloudflare serves it at the edge, so the hub
// verifies by dialing the public name (the default TLS verification); this
// plugin's own read-back checks status, expiry and host coverage.
//
// Swap: PUT /zones/{zone}/custom_certificates/prioritize with the new
// certificate one priority above the one currently served. Cloudflare's
// documentation says "the higher priority will break ties across overlapping
// legacy_custom certificates" and that legacy_custom certificates take
// precedence over sni_custom; certificates are uploaded without a type, which
// the API treats as legacy_custom, so a larger number wins here. It does not
// document precedence beyond that, which is why the hub's TLS verify of the
// public name, not this ordering, is the proof of what is served.
//
// The previous certificate is kept as the rollback target and never edited
// (no PATCH). Superseded certificates are NOT deleted: that is left to the
// operator, and each zone has a custom-certificate quota (Business and
// Enterprise: 5 modern packs and 1 legacy pack by default, one pack per
// uploaded certificate), so remove old ones or renewals will start failing
// with a quota error.
//
// API: https://developers.cloudflare.com/api/resources/custom_certificates/
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(cf{}) }

func main() {}

type cf struct{}

// sleep is injectable so activation polling is instant in tests.
var sleep = time.Sleep

const (
	pollEvery = 5 * time.Second
	maxPolls  = 24
	maxMsg    = 160
)

var (
	zonePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hostPattern = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	bundleModes = map[string]bool{"ubiquitous": true, "optimal": true, "force": true}
	// Statuses a certificate will not leave on its own.
	deadStatus = map[string]bool{"failed": true, "expired": true, "deleted": true, "pending_deletion": true}
)

// handle is the RollbackHandle.
type handle struct {
	Zone          string  `json:"zone"`
	Prior         string  `json:"prior"`
	New           string  `json:"new"`
	PriorPriority float64 `json:"prior_priority"`
}

type target struct{ zone, hostname, bundle string }

func locate(inv abi.Invocation) (target, error) {
	t := target{zone: inv.Target["zone_id"], hostname: strings.ToLower(inv.Target["hostname"]), bundle: inv.Target["bundle_method"]}
	if t.bundle == "" {
		t.bundle = "ubiquitous"
	}
	switch {
	case !zonePattern.MatchString(t.zone):
		return t, errors.New("target setting zone_id must be a 32 character hex zone id")
	case !hostPattern.MatchString(t.hostname) || strings.HasPrefix(t.hostname, "*."):
		return t, errors.New("target setting hostname must be a host name")
	case !bundleModes[t.bundle]:
		return t, errors.New("target setting bundle_method must be ubiquitous, optimal or force")
	}
	return t, nil
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// envelope is the common Cloudflare reply.
type envelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// call performs one API request. Errors carry method, path, status and the
// first error message cut short; never the body, which can echo the request.
func call(h *delivery.Host, inv abi.Invocation, method, path string, body any) (json.RawMessage, error) {
	headers := map[string]string{"Authorization": "Bearer " + inv.Credential["api_token"]}
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return nil, err
		}
		headers["Content-Type"] = "application/json"
	}
	short := strings.SplitN(path, "?", 2)[0]
	resp, err := h.HTTP(abi.HTTPRequest{Method: method, URL: strings.TrimRight(inv.Credential["api_base"], "/") + path, Headers: headers, Body: raw})
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, short, err)
	}
	var env envelope
	parsed := json.Unmarshal(resp.Body, &env) == nil
	if resp.Status/100 == 2 && parsed && env.Success {
		return env.Result, nil
	}
	msg := ""
	if parsed && len(env.Errors) > 0 {
		msg = env.Errors[0].Message
		if len(msg) > maxMsg {
			msg = msg[:maxMsg]
		}
		msg = ": " + msg
	}
	return nil, fmt.Errorf("%s %s: HTTP %d%s", method, short, resp.Status, msg)
}

type certInfo struct {
	ID        string   `json:"id"`
	Hosts     []string `json:"hosts"`
	Status    string   `json:"status"`
	Priority  float64  `json:"priority"`
	ExpiresOn string   `json:"expires_on"`
}

// covers reports whether a certificate host pattern serves name: equal, or
// "*.x" for a name with exactly one more label.
func covers(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	if pattern == name {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") || strings.HasPrefix(name, "*.") {
		return false
	}
	rest, ok := strings.CutSuffix(name, pattern[1:])
	return ok && rest != "" && !strings.Contains(rest, ".")
}

func coversAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if covers(p, name) {
			return true
		}
	}
	return false
}

func (cf) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	t, err := locate(req.Invocation)
	if err != nil {
		return err
	}
	_, err = call(h, req.Invocation, "GET", "/zones/"+t.zone+"/custom_certificates?per_page=1", nil)
	return err
}

// served finds the certificate currently served for hostname: among active
// certificates covering it, the highest priority.
func served(h *delivery.Host, inv abi.Invocation, t target) (certInfo, bool, error) {
	res, err := call(h, inv, "GET", "/zones/"+t.zone+"/custom_certificates?per_page=50", nil)
	if err != nil {
		return certInfo{}, false, err
	}
	var all []certInfo
	if json.Unmarshal(res, &all) != nil {
		return certInfo{}, false, errors.New("certificate list unreadable")
	}
	var best certInfo
	found := false
	for _, c := range all {
		if c.Status == "active" && coversAny(c.Hosts, t.hostname) && (!found || c.Priority > best.Priority) {
			best, found = c, true
		}
	}
	return best, found, nil
}

func getCert(h *delivery.Host, inv abi.Invocation, zone, id string) (certInfo, error) {
	res, err := call(h, inv, "GET", "/zones/"+zone+"/custom_certificates/"+id, nil)
	if err != nil {
		return certInfo{}, err
	}
	var c certInfo
	if json.Unmarshal(res, &c) != nil {
		return certInfo{}, errors.New("certificate unreadable")
	}
	return c, nil
}

func deleteCert(h *delivery.Host, inv abi.Invocation, zone, id string) error {
	_, err := call(h, inv, "DELETE", "/zones/"+zone+"/custom_certificates/"+id, nil)
	return err
}

type prio struct {
	ID       string  `json:"id"`
	Priority float64 `json:"priority"`
}

func prioritize(h *delivery.Host, inv abi.Invocation, zone string, items ...prio) error {
	_, err := call(h, inv, "PUT", "/zones/"+zone+"/custom_certificates/prioritize", map[string]any{"certificates": items})
	return err
}

// waitActive polls the uploaded certificate until it is active.
func waitActive(h *delivery.Host, inv abi.Invocation, zone, id string) error {
	status := ""
	for i := 0; i < maxPolls; i++ {
		if i > 0 {
			sleep(pollEvery)
		}
		c, err := getCert(h, inv, zone, id)
		if err != nil {
			return err
		}
		status = c.Status
		if status == "active" {
			return nil
		}
		if deadStatus[status] {
			break
		}
	}
	return fmt.Errorf("uploaded certificate did not become active (status %q)", status)
}

func leaf(certPEM string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		return nil, errors.New("certificate is not PEM")
	}
	return x509.ParseCertificate(b.Bytes)
}

// checkReadback compares what Cloudflare reports with the leaf pushed.
func checkReadback(c certInfo, l *x509.Certificate) error {
	if c.Status != "active" {
		return fmt.Errorf("certificate status is %q, not active", c.Status)
	}
	exp, err := time.Parse(time.RFC3339, c.ExpiresOn)
	if err != nil || !exp.Truncate(time.Second).Equal(l.NotAfter.Truncate(time.Second)) {
		return errors.New("expiry reported by Cloudflare does not match the pushed certificate")
	}
	for _, san := range l.DNSNames {
		if !coversAny(c.Hosts, san) {
			return errors.New("Cloudflare does not report every certificate name as covered")
		}
	}
	return nil
}

// restore puts the previous certificate back in front and removes the new one.
// The delete is best effort: the prioritize call is what changes what is served.
func restore(h *delivery.Host, inv abi.Invocation, hd handle) (string, error) {
	if hd.Prior == "" {
		return "no previous certificate; new one removed", deleteCert(h, inv, hd.Zone, hd.New)
	}
	if err := prioritize(h, inv, hd.Zone, prio{hd.Prior, hd.PriorPriority + 1}, prio{hd.New, hd.PriorPriority}); err != nil {
		return "", err
	}
	_ = deleteCert(h, inv, hd.Zone, hd.New)
	return "", nil
}

// scrub withholds a detail string that repeats the API token or a line of
// the private key: Cloudflare error messages can echo request fragments.
func scrub(detail, token, keyPEM string) string {
	secrets := append(strings.Split(keyPEM, "\n"), token)
	for _, s := range secrets {
		if s = strings.TrimSpace(s); len(s) >= 8 && !strings.HasPrefix(s, "-----") && strings.Contains(detail, s) {
			return "Cloudflare error message withheld: it repeats request content"
		}
	}
	return detail
}

func (cf) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	fail := func(outcome, detail string) (abi.PushResult, error) {
		return abi.PushResult{Outcome: outcome, Detail: scrub(detail, req.Invocation.Credential["api_token"], req.KeyPEM)}, nil
	}
	inv := req.Invocation
	t, err := locate(inv)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	l, err := leaf(req.CertPEM)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	prior, havePrior, err := served(h, inv, t)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}

	res, err := call(h, inv, "POST", "/zones/"+t.zone+"/custom_certificates",
		map[string]string{"certificate": req.CertPEM, "private_key": req.KeyPEM, "bundle_method": t.bundle})
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	var up certInfo
	if json.Unmarshal(res, &up) != nil || !idPattern.MatchString(up.ID) {
		return fail(abi.OutcomeWriteFailed, "upload response carried no certificate id")
	}
	hd := handle{Zone: t.zone, New: up.ID, PriorPriority: prior.Priority}
	if havePrior {
		hd.Prior = prior.ID
	}

	if err := waitActive(h, inv, t.zone, up.ID); err != nil {
		detail := err.Error()
		if derr := deleteCert(h, inv, t.zone, up.ID); derr != nil {
			detail += "; CLEANUP FAILED: " + derr.Error()
		}
		return fail(abi.OutcomeWriteFailed, detail)
	}

	// Swap: nothing is reordered when this fails, so the previous
	// certificate is still the one served.
	items := []prio{{up.ID, hd.PriorPriority + 1}}
	if havePrior {
		items = append(items, prio{prior.ID, hd.PriorPriority})
	}
	if err := prioritize(h, inv, t.zone, items...); err != nil {
		detail := err.Error()
		if derr := deleteCert(h, inv, t.zone, up.ID); derr != nil {
			detail += "; CLEANUP FAILED: " + derr.Error()
		}
		return fail(abi.OutcomeBindingFailed, detail)
	}

	got, err := getCert(h, inv, t.zone, up.ID)
	if err == nil {
		err = checkReadback(got, l)
	}
	if err != nil {
		detail := err.Error()
		if _, rerr := restore(h, inv, hd); rerr != nil {
			detail += "; RESTORE FAILED: " + rerr.Error()
		}
		return fail(abi.OutcomeBindingFailed, detail)
	}
	raw, _ := json.Marshal(hd)
	return abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, RollbackHandle: string(raw)}, nil
}

func (cf) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	var hd handle
	if json.Unmarshal([]byte(req.Handle), &hd) != nil || !zonePattern.MatchString(hd.Zone) || !idPattern.MatchString(hd.New) ||
		(hd.Prior != "" && !idPattern.MatchString(hd.Prior)) {
		return abi.RollbackResult{Detail: "rollback handle is not a Cloudflare certificate handle"}, nil
	}
	detail, err := restore(h, req.Invocation, hd)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	return abi.RollbackResult{RolledBack: true, Detail: detail}, nil
}
