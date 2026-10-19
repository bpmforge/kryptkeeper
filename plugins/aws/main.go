// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command aws is a delivery plugin that imports the renewed certificate into
// AWS Certificate Manager and points an Application Load Balancer listener
// (mode acm_alb) or a CloudFront distribution (mode acm_cloudfront) at it.
// Both serve the certificate on the public name, so the hub verifies with the
// default TLS dial. Secrets Manager delivery is the separate
// aws-secretsmanager plugin because its verification is read-back.
//
// import_mode "new" imports a fresh ACM certificate each renewal and is fully
// reversible. import_mode "reimport" (the default once certificate_arn is
// set) replaces the material inside the same ARN: the ARN, and so the
// binding, never changes, but ACM cannot give the old private key back, so
// rollback can only restore the previous binding, never the old material.
//
// CloudFront only accepts ACM certificates from us-east-1, so that mode sends
// every ACM call to us-east-1 whatever the credential region is.
//
// Superseded ACM certificates are not deleted; remove them out of band.
//
// API shapes (verified against the AWS API references): ACM JSON 1.1
// (X-Amz-Target CertificateManager.ImportCertificate / GetCertificate,
// base64 PEM blobs), Elastic Load Balancing v2 query API version 2015-12-01
// (DescribeListeners, ModifyListener with Certificates.member.1), CloudFront
// REST 2020-05-31 (GET and PUT /distribution/{Id}/config, If-Match).
//
// Minimum IAM: acm:ImportCertificate, acm:GetCertificate,
// elasticloadbalancing:DescribeListeners, elasticloadbalancing:ModifyListener,
// cloudfront:GetDistributionConfig, cloudfront:UpdateDistribution.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(awsPlugin{}) }

func main() {}

type awsPlugin struct{}

const (
	modeALB        = "acm_alb"
	modeCloudFront = "acm_cloudfront"
	modeReimport   = "reimport"
	modeNew        = "new"

	// cloudFrontRegion is where CloudFront reads its ACM certificates.
	cloudFrontRegion = "us-east-1"

	materialNote = "in-place import: previous certificate material not restorable"
)

// regions mirrors the hosts in manifest.json; a manifest cannot hold wildcards.
var regions = map[string]bool{
	"us-east-1": true, "us-east-2": true, "us-west-1": true, "us-west-2": true, "eu-west-1": true,
	"eu-west-2": true, "eu-central-1": true, "ap-southeast-1": true, "ap-southeast-2": true, "ap-northeast-1": true,
}

var (
	acmARNPattern      = regexp.MustCompile(`^arn:aws:acm:([a-z0-9-]+):[0-9]{12}:certificate/[A-Za-z0-9-]+$`)
	listenerARNPattern = regexp.MustCompile(`^arn:aws:elasticloadbalancing:([a-z0-9-]+):[0-9]{12}:listener/(app|net)/[A-Za-z0-9/_-]+$`)
	distIDPattern      = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)
)

type config struct {
	creds       creds
	region      string // credential region: ELB endpoint and, for ALB, ACM
	acmRegion   string
	mode        string
	importMode  string
	certARN     string
	listenerARN string
	distID      string
}

func parse(inv abi.Invocation) (config, error) {
	cr, t := inv.Credential, inv.Target
	c := config{
		creds:  creds{AccessKeyID: cr["access_key_id"], SecretAccessKey: cr["secret_access_key"], SessionToken: cr["session_token"]},
		region: cr["region"], mode: t["mode"], certARN: t["certificate_arn"],
		listenerARN: t["listener_arn"], distID: t["distribution_id"], importMode: t["import_mode"],
	}
	if c.creds.AccessKeyID == "" || c.creds.SecretAccessKey == "" {
		return c, errors.New("credential access_key_id and secret_access_key are required")
	}
	if !regions[c.region] {
		return c, fmt.Errorf("credential region %q is not one this plugin's manifest grants; fork the manifest to add it", c.region)
	}
	if c.importMode == "" {
		c.importMode = modeNew
		if c.certARN != "" {
			c.importMode = modeReimport
		}
	}
	if c.importMode != modeNew && c.importMode != modeReimport {
		return c, errors.New("target import_mode must be reimport or new")
	}
	c.acmRegion = c.region
	switch c.mode {
	case modeALB:
		if !listenerARNPattern.MatchString(c.listenerARN) {
			return c, errors.New("target listener_arn is required for mode acm_alb")
		}
		if m := listenerARNPattern.FindStringSubmatch(c.listenerARN); m[1] != c.region {
			return c, errors.New("listener_arn is not in the credential region")
		}
	case modeCloudFront:
		if !distIDPattern.MatchString(c.distID) {
			return c, errors.New("target distribution_id is required for mode acm_cloudfront")
		}
		c.acmRegion = cloudFrontRegion
	default:
		return c, errors.New("target mode must be acm_alb or acm_cloudfront")
	}
	if c.importMode == modeReimport && c.certARN == "" {
		return c, errors.New("import_mode reimport needs target certificate_arn")
	}
	if c.certARN != "" {
		m := acmARNPattern.FindStringSubmatch(c.certARN)
		if m == nil {
			return c, errors.New("target certificate_arn is not an ACM certificate ARN")
		}
		if m[1] != c.acmRegion {
			return c, fmt.Errorf("certificate_arn must be in %s for mode %s", c.acmRegion, c.mode)
		}
	}
	return c, nil
}

// handle is the RollbackHandle.
type handle struct {
	PriorARN   string `json:"prior_arn"`
	ARN        string `json:"arn"`
	ImportMode string `json:"import_mode"`
}

func parseHandle(s string, c config) (handle, error) {
	var hd handle
	if json.Unmarshal([]byte(s), &hd) != nil {
		return hd, errors.New("rollback handle is not an AWS handle")
	}
	for _, a := range []string{hd.PriorARN, hd.ARN} {
		if m := acmARNPattern.FindStringSubmatch(a); m == nil || m[1] != c.acmRegion {
			return hd, errors.New("rollback handle is not an AWS handle")
		}
	}
	return hd, nil
}

// splitCert returns the leaf and the rest of the chain as PEM, plus the
// leaf's SHA-256 fingerprint.
func splitCert(certPEM string) (leaf, chain, fp string, err error) {
	rest := []byte(certPEM)
	var out []string
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if len(out) == 0 {
			sum := sha256.Sum256(b.Bytes)
			fp = hex.EncodeToString(sum[:])
		}
		out = append(out, string(pem.EncodeToMemory(b)))
	}
	if len(out) == 0 {
		return "", "", "", errors.New("certificate is not PEM")
	}
	return out[0], strings.Join(out[1:], ""), fp, nil
}

// binding is the service-specific half of a delivery.
type binding interface {
	current() (string, error) // ARN the service serves now
	bind(arn string) error
}

func (c config) binding(a *aws) binding {
	if c.mode == modeALB {
		return albBinding{a: a, region: c.region, listener: c.listenerARN}
	}
	return cfBinding{a: a, id: c.distID}
}

func (awsPlugin) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	c, err := parse(req.Invocation)
	if err != nil {
		return err
	}
	a := &aws{h: h, c: c.creds}
	if _, err := c.binding(a).current(); err != nil {
		return err
	}
	if c.importMode == modeReimport {
		_, err = a.certFingerprint(c.acmRegion, c.certARN)
	}
	return err
}

func (awsPlugin) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	fail := func(outcome, detail string) (abi.PushResult, error) {
		return abi.PushResult{Outcome: outcome, Detail: detail}, nil
	}
	c, err := parse(req.Invocation)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	leaf, chain, fp, err := splitCert(req.CertPEM)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	a := &aws{h: h, c: c.creds}
	b := c.binding(a)

	prior, err := b.current()
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	importARN := ""
	if c.importMode == modeReimport {
		importARN = c.certARN
	}
	arn, err := a.importCert(c.acmRegion, importARN, leaf, chain, req.KeyPEM)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	if m := acmARNPattern.FindStringSubmatch(arn); m == nil || m[1] != c.acmRegion || (importARN != "" && arn != importARN) {
		return fail(abi.OutcomeWriteFailed, "ACM returned an unexpected certificate ARN")
	}
	hd := handle{PriorARN: prior, ARN: arn, ImportMode: c.importMode}

	err = b.bind(arn)
	if err == nil {
		err = checkBound(a, b, c.acmRegion, arn, fp)
	}
	if err != nil {
		detail := err.Error()
		if prior != arn {
			if rerr := b.bind(prior); rerr != nil {
				detail += "; RESTORE FAILED: " + rerr.Error()
			}
		}
		if c.importMode == modeReimport {
			detail += "; " + materialNote
		}
		return fail(abi.OutcomeBindingFailed, detail)
	}
	raw, _ := json.Marshal(hd)
	return abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, RollbackHandle: string(raw)}, nil
}

// checkBound reads the binding back and fingerprints the certificate behind it.
func checkBound(a *aws, b binding, acmRegion, arn, fp string) error {
	got, err := b.current()
	if err != nil {
		return err
	}
	if got != arn {
		return errors.New("service is not bound to the imported certificate")
	}
	have, err := a.certFingerprint(acmRegion, arn)
	if err != nil {
		return err
	}
	if have != fp {
		return errors.New("ACM certificate read back does not match the pushed certificate")
	}
	return nil
}

func (awsPlugin) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	c, err := parse(req.Invocation)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	hd, err := parseHandle(req.Handle, c)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	if hd.PriorARN == hd.ARN {
		return abi.RollbackResult{Detail: materialNote}, nil
	}
	if err := c.binding(&aws{h: h, c: c.creds}).bind(hd.PriorARN); err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	detail := ""
	if hd.ImportMode == modeReimport {
		detail = materialNote
	}
	return abi.RollbackResult{RolledBack: true, Detail: detail}, nil
}
