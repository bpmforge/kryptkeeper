// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock AWS ACM (JSON 1.1), Elastic Load Balancing v2 (query protocol, XML)
// and CloudFront (REST, XML) for the aws plugin (W27-29). Requests are routed
// by Host header, whose service and region must match the SigV4 credential
// scope, so a CloudFront delivery that sent ACM to the credential region
// instead of us-east-1 fails here. Both services serve the certificate on the
// public name, so the plugin is graded with the normal TLS verification:
// Served is the fingerprint of the ACM certificate the listener or
// distribution is bound to. The plugin runs import_mode "new", the fully
// reversible mode; the in-place "reimport" limit is covered by its own tests.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

const (
	awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	awsSession   = "FwoGZXIvYXdzEXAMPLESESSIONTOKEN"
	awsListener  = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:listener/app/shop/50dc6c495c0c9188/f2f7dc8efc522ab2"
	awsDist      = "E2EXAMPLE1234"
)

var awsARNElement = regexp.MustCompile(`<ACMCertificateArn>([^<]*)</ACMCertificateArn>`)

type awsACMDevice struct {
	ts      *httptest.Server
	mode    string
	mu      sync.Mutex
	certs   map[string]string // ACM ARN -> leaf PEM
	bound   string
	fresh   string // ARN of the most recent import
	next    int
	etag    int
	fail    failSet
	initial Cert
	arnReg  string // region of ACM ARNs
}

func newAWSACMDevice(t *testing.T, mode string) *awsACMDevice {
	d := &awsACMDevice{mode: mode, initial: NewCert(t, "aws-initial-"+mode), arnReg: "eu-west-1"}
	if mode == "acm_cloudfront" {
		d.arnReg = "us-east-1"
	}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	d.Reset()
	return d
}

func (d *awsACMDevice) initialARN() string {
	return "arn:aws:acm:" + d.arnReg + ":123456789012:certificate/00000000-0000-0000-0000-000000000001"
}

func (d *awsACMDevice) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.certs = map[string]string{d.initialARN(): string(d.initial.CertPEM)}
	d.bound, d.fresh, d.etag, d.fail = d.initialARN(), "", 1, failSet{}
}

func (d *awsACMDevice) FailNext(step string) { d.mu.Lock(); d.fail[step] = true; d.mu.Unlock() }

func (d *awsACMDevice) Served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Fingerprint(d.certs[d.bound])
}

func (d *awsACMDevice) Env() delivery.Env {
	target := map[string]string{"mode": d.mode, "import_mode": "new"}
	if d.mode == "acm_alb" {
		target["listener_arn"] = awsListener
	} else {
		target["distribution_id"] = awsDist
	}
	return anyHostEnv(d.ts, map[string]string{"access_key_id": "AKIAEXAMPLE", "secret_access_key": awsSecretKey, "session_token": awsSession, "region": "eu-west-1"},
		[]string{"secret_access_key", "session_token"}, target)
}

// authorized checks the SigV4 credential scope against the Host header.
func awsAuthorized(r *http.Request, wantRegion, wantService string) bool {
	a := r.Header.Get("Authorization")
	return strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") &&
		strings.Contains(a, "/"+wantRegion+"/"+wantService+"/aws4_request,") &&
		strings.Contains(a, "Signature=") && r.Header.Get("X-Amz-Date") != "" && r.Header.Get("X-Amz-Security-Token") == awsSession
}

func awsJSONErr(w http.ResponseWriter, status int, typ string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ})
}

func (d *awsACMDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	parts := strings.Split(r.Host, ".")
	service, region := parts[0], ""
	if service == "cloudfront" {
		region = "us-east-1"
	} else {
		region = parts[1]
	}
	if !awsAuthorized(r, region, service) {
		http.Error(w, "bad signature scope", http.StatusForbidden)
		return
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(r.Body)
	switch service {
	case "acm":
		d.acm(w, r, region, body.Bytes())
	case "elasticloadbalancing":
		d.elb(w, body.Bytes())
	case "cloudfront":
		d.cloudfront(w, r, body.Bytes())
	default:
		http.NotFound(w, r)
	}
}

func (d *awsACMDevice) acm(w http.ResponseWriter, r *http.Request, region string, body []byte) {
	if region != d.arnReg {
		awsJSONErr(w, http.StatusBadRequest, "ValidationException") // wrong-region ACM call
		return
	}
	switch r.Header.Get("X-Amz-Target") {
	case "CertificateManager.ImportCertificate":
		if d.fail.take("upload") {
			awsJSONErr(w, http.StatusBadRequest, "LimitExceededException")
			return
		}
		var b struct {
			Certificate, PrivateKey []byte
			CertificateArn          string
		}
		if json.Unmarshal(body, &b) != nil || len(b.PrivateKey) == 0 || Fingerprint(string(b.Certificate)) == "" {
			awsJSONErr(w, http.StatusBadRequest, "ValidationException")
			return
		}
		arn := b.CertificateArn
		if arn == "" {
			d.next++
			arn = fmt.Sprintf("arn:aws:acm:%s:123456789012:certificate/new-%d", region, d.next)
		}
		d.certs[arn], d.fresh = string(b.Certificate), arn
		_ = json.NewEncoder(w).Encode(map[string]string{"CertificateArn": arn})
	case "CertificateManager.GetCertificate":
		var b struct{ CertificateArn string }
		_ = json.Unmarshal(body, &b)
		c, ok := d.certs[b.CertificateArn]
		if !ok {
			awsJSONErr(w, http.StatusBadRequest, "ResourceNotFoundException")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"Certificate": c})
	default:
		awsJSONErr(w, http.StatusBadRequest, "UnknownOperationException")
	}
}

// swap is the binding change: "bind" when it targets the freshly imported
// certificate, "rollback" when it restores another.
func (d *awsACMDevice) swap(arn string) bool {
	step := "rollback"
	if arn == d.fresh {
		step = "bind"
	}
	if d.fail.take(step) {
		return false
	}
	d.bound = arn
	return true
}

func (d *awsACMDevice) elb(w http.ResponseWriter, body []byte) {
	form, _ := url.ParseQuery(string(body))
	if form.Get("Version") != "2015-12-01" || form.Get("ListenerArn")+form.Get("ListenerArns.member.1") != awsListener {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ListenerNotFound</Code></Error></ErrorResponse>`))
		return
	}
	switch form.Get("Action") {
	case "DescribeListeners":
		fmt.Fprintf(w, `<DescribeListenersResponse><DescribeListenersResult><Listeners><member><Certificates><member><CertificateArn>%s</CertificateArn></member></Certificates></member></Listeners></DescribeListenersResult></DescribeListenersResponse>`, d.bound)
	case "ModifyListener":
		arn := form.Get("Certificates.member.1.CertificateArn")
		if _, ok := d.certs[arn]; !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>CertificateNotFound</Code></Error></ErrorResponse>`))
			return
		}
		if !d.swap(arn) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InternalFailure</Code></Error></ErrorResponse>`))
			return
		}
		_, _ = w.Write([]byte(`<ModifyListenerResponse/>`))
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (d *awsACMDevice) cloudfront(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.URL.Path != "/2020-05-31/distribution/"+awsDist+"/config" {
		http.NotFound(w, r)
		return
	}
	etag := fmt.Sprintf("E%d", d.etag)
	switch r.Method {
	case "GET":
		w.Header().Set("ETag", etag)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><DistributionConfig xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><CallerReference>cr</CallerReference><ViewerCertificate><ACMCertificateArn>%s</ACMCertificateArn><SSLSupportMethod>sni-only</SSLSupportMethod></ViewerCertificate></DistributionConfig>`, d.bound)
	case "PUT":
		if r.Header.Get("If-Match") != etag {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		m := awsARNElement.FindSubmatch(body)
		if m == nil || r.Header.Get("Content-Type") != "application/xml" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := d.certs[string(m[1])]; !ok || !d.swap(string(m[1])) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		d.etag++
		_, _ = w.Write([]byte(`<Distribution/>`))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestAWSPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "plugins/aws"))
	if p.Manifest().Verification == abi.VerificationReadback {
		t.Fatal("aws plugin serves on the public name and must use TLS verification")
	}
	for _, mode := range []string{"acm_alb", "acm_cloudfront"} {
		t.Run(mode, func(t *testing.T) { Suite(t, p, newAWSACMDevice(t, mode)) })
	}
}
