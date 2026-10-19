// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

const (
	secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	sessTok   = "FwoGZXIvYXdzEXAMPLESESSIONTOKEN"
	keyMarker = "TOP-SECRET-KEY-BYTES"
	listener  = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:listener/app/shop/50dc6c495c0c9188/f2f7dc8efc522ab2"
	oldARN    = "arn:aws:acm:eu-west-1:123456789012:certificate/00000000-0000-0000-0000-000000000001"
	oldCFARN  = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-0000000000cf"
	distID    = "E2EXAMPLE1234"
)

func newCert(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func fpOf(certPEM string) string { _, _, fp, _ := splitCert(certPEM); return fp }

const cfDoc = `<?xml version="1.0" encoding="UTF-8"?>
<DistributionConfig xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><CallerReference>cr-1</CallerReference><Comment>keep &amp; me</Comment><Aliases><Quantity>1</Quantity><Items><CNAME>shop.example.com</CNAME></Items></Aliases><Enabled>true</Enabled><ViewerCertificate><ACMCertificateArn>%s</ACMCertificateArn><SSLSupportMethod>sni-only</SSLSupportMethod><MinimumProtocolVersion>TLSv1.2_2021</MinimumProtocolVersion></ViewerCertificate></DistributionConfig>`

// fakeAWS answers ACM, ELBv2 and CloudFront by request host.
type fakeAWS struct {
	t          *testing.T
	certs      map[string]string // ACM ARN -> leaf PEM
	next       int
	albBound   string
	cfBound    string
	etag       int
	failImport bool
	failModify func(arn string) bool
	failPut    int // status to answer a CloudFront PUT with (0 = succeed)
	wrongCert  string
	acmHosts   []string
	importArns []string
	modifies   []string
	puts       [][]byte
	putIfMatch []string
	scopes     []string
	logs       []string
}

func newFake(t *testing.T) *fakeAWS {
	return &fakeAWS{t: t, certs: map[string]string{}, albBound: oldARN, cfBound: oldCFARN, etag: 1}
}

func (f *fakeAWS) host() *delivery.Host { return delivery.NewHost(f.call) }

func (f *fakeAWS) call(op string, in []byte) ([]byte, error) {
	if op != abi.HostHTTP {
		f.logs = append(f.logs, string(in))
		return json.Marshal(abi.HostReply{})
	}
	var req abi.HTTPRequest
	if err := json.Unmarshal(in, &req); err != nil {
		f.t.Fatal(err)
	}
	status, hdr, body := f.serve(req)
	resp, _ := json.Marshal(abi.HTTPResponse{Status: status, Headers: hdr, Body: body})
	return json.Marshal(abi.HostReply{Result: resp})
}

func js(v any) []byte { b, _ := json.Marshal(v); return b }

func (f *fakeAWS) serve(req abi.HTTPRequest) (int, map[string]string, []byte) {
	u, _ := url.Parse(req.URL)
	parts := strings.Split(u.Host, ".")
	if len(parts) != 4 && len(parts) != 3 || !strings.HasSuffix(u.Host, ".amazonaws.com") {
		f.t.Fatalf("unexpected host %s", u.Host)
	}
	service, region := parts[0], ""
	if service == "cloudfront" {
		region = "us-east-1"
	} else {
		region = parts[1]
	}
	auth := req.Headers["Authorization"]
	scope := "/" + region + "/" + service + "/aws4_request"
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") || !strings.Contains(auth, scope+",") || req.Headers["X-Amz-Date"] == "" ||
		req.Headers["X-Amz-Security-Token"] != sessTok {
		f.t.Errorf("bad signature header for %s: %q", u.Host, auth)
	}
	f.scopes = append(f.scopes, region+"/"+service)
	switch service {
	case "acm":
		f.acmHosts = append(f.acmHosts, u.Host)
		return f.acm(req)
	case "elasticloadbalancing":
		return f.elb(req)
	default:
		return f.cloudfront(req, u)
	}
}

func awsErr(status int, typ string) (int, map[string]string, []byte) {
	return status, nil, js(map[string]string{"__type": "com.amazon#" + typ, "message": "leaky " + keyMarker})
}

func (f *fakeAWS) acm(req abi.HTTPRequest) (int, map[string]string, []byte) {
	switch req.Headers["X-Amz-Target"] {
	case "CertificateManager.ImportCertificate":
		var b struct {
			Certificate, PrivateKey, CertificateChain []byte
			CertificateArn                            string
		}
		if json.Unmarshal(req.Body, &b) != nil || len(b.Certificate) == 0 || !bytes.Contains(b.PrivateKey, []byte("PRIVATE KEY")) {
			f.t.Errorf("bad ImportCertificate body")
		}
		f.importArns = append(f.importArns, b.CertificateArn)
		if f.failImport {
			return awsErr(400, "LimitExceededException")
		}
		arn := b.CertificateArn
		if arn == "" {
			f.next++
			arn = fmt.Sprintf("arn:aws:acm:%s:123456789012:certificate/new-%d", strings.Split(strings.TrimPrefix(req.URL, "https://acm."), ".")[0], f.next)
		}
		f.certs[arn] = string(b.Certificate)
		return 200, nil, js(map[string]string{"CertificateArn": arn})
	case "CertificateManager.GetCertificate":
		var b struct{ CertificateArn string }
		_ = json.Unmarshal(req.Body, &b)
		c, ok := f.certs[b.CertificateArn]
		if !ok {
			return awsErr(400, "ResourceNotFoundException")
		}
		if f.wrongCert != "" {
			c = f.wrongCert
		}
		return 200, nil, js(map[string]string{"Certificate": c})
	}
	f.t.Fatalf("unexpected ACM target %q", req.Headers["X-Amz-Target"])
	return 0, nil, nil
}

func (f *fakeAWS) elb(req abi.HTTPRequest) (int, map[string]string, []byte) {
	form, _ := url.ParseQuery(string(req.Body))
	if form.Get("Version") != "2015-12-01" || req.Headers["Content-Type"] == "" {
		f.t.Errorf("bad ELB request %v", form)
	}
	switch form.Get("Action") {
	case "DescribeListeners":
		if form.Get("ListenerArns.member.1") != listener {
			f.t.Errorf("listener %q", form.Get("ListenerArns.member.1"))
		}
		return 200, nil, []byte(`<DescribeListenersResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"><DescribeListenersResult><Listeners><member><Protocol>HTTPS</Protocol><Certificates><member><CertificateArn>` +
			f.albBound + `</CertificateArn></member></Certificates></member></Listeners></DescribeListenersResult></DescribeListenersResponse>`)
	case "ModifyListener":
		arn := form.Get("Certificates.member.1.CertificateArn")
		f.modifies = append(f.modifies, arn)
		if f.failModify != nil && f.failModify(arn) {
			return 500, nil, []byte(`<ErrorResponse><Error><Code>InternalFailure</Code><Message>` + keyMarker + `</Message></Error></ErrorResponse>`)
		}
		f.albBound = arn
		return 200, nil, []byte(`<ModifyListenerResponse/>`)
	}
	f.t.Fatalf("unexpected ELB action %q", form.Get("Action"))
	return 0, nil, nil
}

func (f *fakeAWS) cfXML() []byte { return []byte(fmt.Sprintf(cfDoc, f.cfBound)) }

func (f *fakeAWS) cloudfront(req abi.HTTPRequest, u *url.URL) (int, map[string]string, []byte) {
	if u.Path != "/2020-05-31/distribution/"+distID+"/config" {
		f.t.Fatalf("unexpected CloudFront path %s", u.Path)
	}
	etag := fmt.Sprintf("E%d", f.etag)
	switch req.Method {
	case "GET":
		return 200, map[string]string{"Etag": etag}, f.cfXML()
	case "PUT":
		f.puts = append(f.puts, req.Body)
		f.putIfMatch = append(f.putIfMatch, req.Headers["If-Match"])
		if req.Headers["Content-Type"] != "application/xml" {
			f.t.Errorf("PUT content-type %q", req.Headers["Content-Type"])
		}
		if f.failPut != 0 {
			return f.failPut, nil, []byte(`<ErrorResponse/>`)
		}
		if req.Headers["If-Match"] != etag {
			return 412, nil, []byte(`<ErrorResponse><Error><Code>PreconditionFailed</Code></Error></ErrorResponse>`)
		}
		m := arnElement.FindSubmatch(req.Body)
		f.cfBound = string(m[1])
		f.etag++
		return 200, nil, []byte(`<Distribution/>`)
	}
	f.t.Fatalf("unexpected CloudFront method %s", req.Method)
	return 0, nil, nil
}

func inv(mode, importMode, certARN, region string) abi.Invocation {
	t := map[string]string{"mode": mode, "import_mode": importMode, "certificate_arn": certARN}
	if mode == modeALB {
		t["listener_arn"] = listener
	} else {
		t["distribution_id"] = distID
	}
	return abi.Invocation{
		Credential: map[string]string{"access_key_id": "AKIAEXAMPLE", "secret_access_key": secretKey, "session_token": sessTok, "region": region},
		Target:     t,
	}
}

func push(f *fakeAWS, in abi.Invocation, certPEM string) (abi.PushResult, error) {
	return (awsPlugin{}).Push(f.host(), abi.PushRequest{Invocation: in, Name: "shop", CertPEM: certPEM,
		KeyPEM: "-----BEGIN PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString([]byte(keyMarker)) + "\n-----END PRIVATE KEY-----\n"})
}

func albNew() abi.Invocation { return inv(modeALB, "new", "", "eu-west-1") }

func seedOld(f *fakeAWS) string {
	old := newCert(f.t, "old")
	f.certs[oldARN], f.certs[oldCFARN] = old, old
	return old
}

func TestValidate(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	for _, in := range []abi.Invocation{albNew(), inv(modeALB, "reimport", oldARN, "eu-west-1"), inv(modeCloudFront, "reimport", oldCFARN, "eu-west-1")} {
		if err := (awsPlugin{}).Validate(f.host(), abi.ValidateRequest{Invocation: in}); err != nil {
			t.Fatalf("validate %v: %v", in.Target, err)
		}
	}
}

func TestALBNewImportBindsAndReadsBack(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	cert := newCert(t, "new") + newCert(t, "intermediate")
	res, err := push(f, albNew(), cert)
	if err != nil || !res.Installed || res.Outcome != abi.OutcomeInstalled {
		t.Fatalf("%+v %v", res, err)
	}
	if f.albBound == oldARN || fpOf(f.certs[f.albBound]) != fpOf(cert) {
		t.Fatalf("listener bound to %s", f.albBound)
	}
	if f.importArns[0] != "" {
		t.Error("new import must not pass CertificateArn")
	}
	var hd handle
	_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
	if hd.PriorARN != oldARN || hd.ARN != f.albBound {
		t.Errorf("handle %+v", hd)
	}
}

func TestACMReimportKeepsARN(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	in := inv(modeALB, "", oldARN, "eu-west-1") // import_mode defaults to reimport
	var arns []string
	for i := 0; i < 2; i++ {
		res, err := push(f, in, newCert(t, fmt.Sprint("n", i)))
		if err != nil || !res.Installed {
			t.Fatalf("push %d: %+v %v", i, res, err)
		}
		var hd handle
		_ = json.Unmarshal([]byte(res.RollbackHandle), &hd)
		arns = append(arns, hd.ARN)
	}
	if f.importArns[0] != oldARN || f.importArns[1] != oldARN || arns[0] != oldARN || arns[1] != oldARN || len(f.certs) != 2 {
		t.Fatalf("import arns %v handles %v certs %d", f.importArns, arns, len(f.certs))
	}
}

func TestALBBindFailureRestoresPriorBinding(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	f.failModify = func(arn string) bool { return arn != oldARN }
	res, _ := push(f, albNew(), newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || res.Installed || f.albBound != oldARN {
		t.Fatalf("%+v bound %s", res, f.albBound)
	}
	if strings.Contains(res.Detail, keyMarker) || strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Errorf("detail %q", res.Detail)
	}
	if last := f.modifies[len(f.modifies)-1]; last != oldARN {
		t.Errorf("last ModifyListener %s, want restore to prior", last)
	}
}

func TestALBRestoreFailureIsReported(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	f.failModify = func(string) bool { return true }
	res, _ := push(f, albNew(), newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "RESTORE FAILED") {
		t.Fatalf("%+v", res)
	}
}

func TestALBReimportBindFailureReportsMaterialNotRestorable(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	f.failModify = func(string) bool { return true }
	res, _ := push(f, inv(modeALB, "reimport", oldARN, "eu-west-1"), newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "in-place import: previous certificate material not restorable") {
		t.Fatalf("%+v", res)
	}
}

func TestReadbackMismatchRestoresBinding(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	f.wrongCert = newCert(t, "other")
	res, _ := push(f, albNew(), newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || f.albBound != oldARN || !strings.Contains(res.Detail, "does not match") {
		t.Fatalf("%+v bound %s", res, f.albBound)
	}
}

func TestImportFailureIsWriteFailed(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	f.failImport = true
	res, _ := push(f, albNew(), newCert(t, "new"))
	if res.Outcome != abi.OutcomeWriteFailed || f.albBound != oldARN || len(f.modifies) != 0 {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(res.Detail, "LimitExceededException") || strings.Contains(res.Detail, keyMarker) {
		t.Errorf("detail %q", res.Detail)
	}
}

func TestALBRollbackRestoresPrior(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	res, _ := push(f, albNew(), newCert(t, "new"))
	rb, _ := (awsPlugin{}).Rollback(f.host(), abi.RollbackRequest{Invocation: albNew(), Handle: res.RollbackHandle})
	if !rb.RolledBack || f.albBound != oldARN {
		t.Fatalf("%+v bound %s", rb, f.albBound)
	}
}

func TestRollbackReimportIsNotRolledBack(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	in := inv(modeALB, "reimport", oldARN, "eu-west-1")
	res, _ := push(f, in, newCert(t, "new"))
	before := len(f.modifies)
	rb, _ := (awsPlugin{}).Rollback(f.host(), abi.RollbackRequest{Invocation: in, Handle: res.RollbackHandle})
	if rb.RolledBack || !strings.Contains(rb.Detail, "not restorable") || len(f.modifies) != before {
		t.Fatalf("%+v", rb)
	}
}

func TestRollbackRejectsBadHandle(t *testing.T) {
	f := newFake(t)
	rb, _ := (awsPlugin{}).Rollback(f.host(), abi.RollbackRequest{Invocation: albNew(), Handle: `{"prior_arn":"x","arn":"y"}`})
	if rb.RolledBack || rb.Detail == "" {
		t.Fatalf("%+v", rb)
	}
}

func TestCloudFrontUsesUsEast1ACM(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	res, _ := push(f, inv(modeCloudFront, "new", "", "eu-west-1"), newCert(t, "new"))
	if !res.Installed {
		t.Fatalf("%+v", res)
	}
	if len(f.acmHosts) == 0 {
		t.Fatal("no ACM requests")
	}
	for _, h := range f.acmHosts {
		if h != "acm.us-east-1.amazonaws.com" {
			t.Errorf("ACM request to %s", h)
		}
	}
	for _, s := range f.scopes {
		if !strings.HasPrefix(s, "us-east-1/") {
			t.Errorf("signing scope %s", s)
		}
	}
	if !strings.Contains(f.cfBound, ":acm:us-east-1:") || f.cfBound == oldCFARN {
		t.Errorf("distribution bound to %s", f.cfBound)
	}
}

func TestCloudFrontRejectsNonUsEast1CertificateARN(t *testing.T) {
	_, err := parse(inv(modeCloudFront, "reimport", oldARN, "eu-west-1"))
	if err == nil || !strings.Contains(err.Error(), "us-east-1") {
		t.Fatalf("err %v", err)
	}
}

func TestCloudFrontPutUsesIfMatchAndPreservesXML(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	orig := f.cfXML()
	res, _ := push(f, inv(modeCloudFront, "new", "", "eu-west-1"), newCert(t, "new"))
	if !res.Installed || len(f.puts) != 1 {
		t.Fatalf("%+v puts %d", res, len(f.puts))
	}
	if f.putIfMatch[0] != "E1" {
		t.Errorf("If-Match %q", f.putIfMatch[0])
	}
	want := bytes.Replace(orig, []byte(oldCFARN), []byte(f.cfBound), 1)
	if !bytes.Equal(f.puts[0], want) {
		t.Fatalf("PUT body differs outside the ARN element:\n%s\nwant\n%s", f.puts[0], want)
	}
	if !bytes.Contains(f.puts[0], []byte("keep &amp; me")) {
		t.Error("escaped text was altered")
	}
}

func TestCloudFrontPreconditionFailedRestores(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	f.failPut = 412
	res, _ := push(f, inv(modeCloudFront, "new", "", "eu-west-1"), newCert(t, "new"))
	if res.Outcome != abi.OutcomeBindingFailed || !strings.Contains(res.Detail, "distribution changed during update") || f.cfBound != oldCFARN {
		t.Fatalf("%+v bound %s", res, f.cfBound)
	}
}

func TestCloudFrontRollbackRestoresPrior(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	in := inv(modeCloudFront, "new", "", "eu-west-1")
	res, _ := push(f, in, newCert(t, "new"))
	rb, _ := (awsPlugin{}).Rollback(f.host(), abi.RollbackRequest{Invocation: in, Handle: res.RollbackHandle})
	if !rb.RolledBack || f.cfBound != oldCFARN {
		t.Fatalf("%+v bound %s", rb, f.cfBound)
	}
}

func TestParseRejects(t *testing.T) {
	for name, mut := range map[string]func(*abi.Invocation){
		"unknown region":       func(i *abi.Invocation) { i.Credential["region"] = "mars-north-1" },
		"missing key":          func(i *abi.Invocation) { delete(i.Credential, "access_key_id") },
		"bad mode":             func(i *abi.Invocation) { i.Target["mode"] = "secrets_manager" },
		"bad listener":         func(i *abi.Invocation) { i.Target["listener_arn"] = "nope" },
		"bad import mode":      func(i *abi.Invocation) { i.Target["import_mode"] = "sideways" },
		"reimport without arn": func(i *abi.Invocation) { i.Target["import_mode"] = "reimport" },
		"bad cert arn":         func(i *abi.Invocation) { i.Target["certificate_arn"] = "arn:aws:s3:::x" },
	} {
		in := albNew()
		mut(&in)
		if _, err := parse(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parse(inv(modeCloudFront, "new", "", "eu-west-1")); err != nil {
		t.Errorf("valid cloudfront target: %v", err)
	}
}

func TestSecretsNeverInOutput(t *testing.T) {
	f := newFake(t)
	seedOld(f)
	var out []string
	f.failModify = func(arn string) bool { return arn != oldARN }
	res, _ := push(f, albNew(), newCert(t, "new"))
	out = append(out, res.Detail, res.RollbackHandle)
	f.failModify, f.failImport = nil, true
	res, _ = push(f, albNew(), newCert(t, "new2"))
	out = append(out, res.Detail)
	f.failPut, f.failImport = 500, false
	res, _ = push(f, inv(modeCloudFront, "new", "", "eu-west-1"), newCert(t, "new3"))
	out = append(out, res.Detail)
	err := (awsPlugin{}).Validate(f.host(), abi.ValidateRequest{Invocation: inv(modeALB, "reimport", "arn:aws:acm:eu-west-1:123456789012:certificate/missing", "eu-west-1")})
	if err == nil {
		t.Fatal("expected validate failure")
	}
	out = append(out, err.Error())
	for _, s := range out {
		if strings.Contains(s, secretKey) || strings.Contains(s, sessTok) || strings.Contains(s, keyMarker) || strings.Contains(s, "BEGIN") {
			t.Errorf("secret material in %q", s)
		}
	}
	for _, l := range f.logs {
		if strings.Contains(l, secretKey) || strings.Contains(l, keyMarker) {
			t.Errorf("secret in log")
		}
	}
}

func TestManifestHostsCoverRegions(t *testing.T) {
	raw, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := abi.ParseManifest(bytes.ReplaceAll(raw, []byte(strings.Repeat("0", 64)), []byte(strings.Repeat("a", 64))))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, h := range m.Capabilities.Network.Hosts {
		have[h] = true
	}
	want := regexp.MustCompile(`^(acm|elasticloadbalancing)\.([a-z0-9-]+)\.amazonaws\.com$`)
	for r := range regions {
		for _, s := range []string{"acm", "elasticloadbalancing"} {
			if h := s + "." + r + ".amazonaws.com"; !have[h] {
				t.Errorf("manifest lacks %s", h)
			}
		}
	}
	for h := range have {
		if m := want.FindStringSubmatch(h); h != "cloudfront.amazonaws.com" && (m == nil || !regions[m[2]]) {
			t.Errorf("manifest host %s not in regions list", h)
		}
	}
	if !have["acm.us-east-1.amazonaws.com"] || !have["cloudfront.amazonaws.com"] {
		t.Error("cloudfront path needs acm.us-east-1 and cloudfront hosts")
	}
}
