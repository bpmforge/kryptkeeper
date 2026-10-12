// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep_test

// Live acceptance for W19-10: user-context MS-XCEP/MS-WSTEP enrollment
// against a running hub, authenticated by real Kerberos from a real KDC
// (Active Directory). Machine-context GPO autoenrollment was proven from a
// Windows client in W18-08 (docs/ops/WSTEP_AUTOENROLLMENT.md); this drives
// the same endpoints as a domain user, the way Windows does on a user pulse,
// and checks what the hub hands back, not what it says it did.
//
// Skipped unless KK_LIVE_WSTEP=1, with:
//
//	KK_WSTEP_BASE       hub base URL by its Kerberos name, e.g. https://hub.example.lab:8443
//	KK_WSTEP_CA_FILE    PEM the hub's TLS certificate chains to
//	KK_WSTEP_REALM      Kerberos realm, e.g. EXAMPLE.LAB
//	KK_WSTEP_KDC        KDC host:port
//	KK_WSTEP_USER       a domain user (sAMAccountName), not a machine account
//	KK_WSTEP_PASSWORD   that user's password (read here, never logged)
//
// Optional:
//
//	KK_WSTEP_CONNECT_ADDR  host:port to dial instead of resolving the base
//	                       URL's host (like curl --resolve); TLS and the
//	                       Kerberos SPN still use the URL's host name
//	KK_WSTEP_TEMPLATE_OID  enroll under this template (sent as TokenType)
//	KK_WSTEP_API_TOKEN     hub API token: check the inventory row and revoke
//	                       the test certificate at the end

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

const (
	getPoliciesAction = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
	wstepAction       = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
	x509v3TokenType   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"

	// MS-XCEP 3.1.4.1.3.x: what a user (not machine) template must carry.
	subjectCNFromDir   = 0x40000000
	generalMachineType = 0x00000040
)

type liveEnv struct {
	base, realm, kdc, user, password, templateOID, apiToken, connectAddr string
	tlsConfig                                                            *tls.Config
}

func loadEnv(t *testing.T) liveEnv {
	t.Helper()
	if os.Getenv("KK_LIVE_WSTEP") != "1" {
		t.Skip("set KK_LIVE_WSTEP=1 and the KK_WSTEP_* vars to run against a real hub and KDC; see tests/live/wstep/README.md")
	}
	e := liveEnv{
		base:        strings.TrimRight(os.Getenv("KK_WSTEP_BASE"), "/"),
		realm:       os.Getenv("KK_WSTEP_REALM"),
		kdc:         os.Getenv("KK_WSTEP_KDC"),
		user:        os.Getenv("KK_WSTEP_USER"),
		password:    os.Getenv("KK_WSTEP_PASSWORD"),
		templateOID: os.Getenv("KK_WSTEP_TEMPLATE_OID"),
		apiToken:    os.Getenv("KK_WSTEP_API_TOKEN"),
		connectAddr: os.Getenv("KK_WSTEP_CONNECT_ADDR"),
	}
	for name, v := range map[string]string{"KK_WSTEP_BASE": e.base, "KK_WSTEP_REALM": e.realm, "KK_WSTEP_KDC": e.kdc, "KK_WSTEP_USER": e.user, "KK_WSTEP_PASSWORD": e.password} {
		if v == "" {
			t.Fatalf("%s is required", name)
		}
	}
	if strings.HasSuffix(e.user, "$") {
		t.Fatal("KK_WSTEP_USER must be a user, not a machine account: this test proves user context")
	}
	pemBytes, err := os.ReadFile(os.Getenv("KK_WSTEP_CA_FILE"))
	if err != nil {
		t.Fatalf("KK_WSTEP_CA_FILE: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("KK_WSTEP_CA_FILE holds no PEM certificate")
	}
	e.tlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return e
}

func (e liveEnv) httpClient() *http.Client {
	tr := &http.Transport{TLSClientConfig: e.tlsConfig}
	if e.connectAddr != "" {
		var d net.Dialer
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, e.connectAddr)
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

// kerberosClient logs the user in at the KDC and returns an HTTP client that
// answers the hub's Negotiate challenge with a service ticket for HTTP/<host>.
func (e liveEnv) kerberosClient(t *testing.T) *spnego.Client {
	t.Helper()
	u, err := url.Parse(e.base)
	if err != nil {
		t.Fatalf("KK_WSTEP_BASE: %v", err)
	}
	cfg, err := config.NewFromString(fmt.Sprintf(`[libdefaults]
  default_realm = %[1]s
  dns_lookup_kdc = false
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
  %[1]s = {
    kdc = %[2]s
  }
`, e.realm, e.kdc))
	if err != nil {
		t.Fatalf("krb5 config: %v", err)
	}
	cl := client.NewWithPassword(e.user, e.realm, e.password, cfg, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		t.Fatalf("Kerberos login as %s@%s: %v", e.user, e.realm, err)
	}
	t.Cleanup(cl.Destroy)
	return spnego.NewClient(cl, e.httpClient(), "HTTP/"+u.Hostname())
}

func soapPost(t *testing.T, do func(*http.Request) (*http.Response, error), endpoint, body string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	resp, err := do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, out
}

func getPoliciesSOAP() string {
	return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header><a:Action>` + getPoliciesAction + `</a:Action></s:Header>
  <s:Body>
    <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <client><lastUpdate/><preferredLanguage/></client>
      <requestFilter/>
    </GetPolicies>
  </s:Body>
</s:Envelope>`
}

func wstepSOAP(csrDER []byte, tokenType string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Header><a:Action>` + wstepAction + `</a:Action></s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>` + tokenType + `</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wst:BinarySecurityToken>` + base64.StdEncoding.EncodeToString(csrDER) + `</wst:BinarySecurityToken>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`
}

// policiesResponse is the part of MS-XCEP GetPoliciesResponse checked here.
type policiesResponse struct {
	Policies []struct {
		CommonName       string `xml:"attributes>commonName"`
		SubjectNameFlags uint64 `xml:"attributes>subjectNameFlags"`
		GeneralFlags     uint64 `xml:"attributes>generalFlags"`
	} `xml:"Body>GetPoliciesResponse>response>policies>policy"`
	CACertificate string `xml:"Body>GetPoliciesResponse>cAs>cA>certificate"`
}

// rstrResponse holds the issued certificate of an MS-WSTEP RSTR.
type rstrResponse struct {
	Issued []string `xml:"Body>RequestSecurityTokenResponseCollection>RequestSecurityTokenResponse>RequestedSecurityToken>BinarySecurityToken"`
}

func TestUserContextEnrollment(t *testing.T) {
	e := loadEnv(t)
	xcepURL, wstepURL := e.base+"/xcep", e.base+"/wstep"

	t.Run("anonymous requests are challenged", func(t *testing.T) {
		for _, ep := range []string{xcepURL, wstepURL} {
			code, hdr, _ := soapPost(t, e.httpClient().Do, ep, getPoliciesSOAP())
			if code != http.StatusUnauthorized || !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "Negotiate") {
				t.Errorf("%s anonymous: status %d, WWW-Authenticate %q; want 401 Negotiate", ep, code, hdr.Get("WWW-Authenticate"))
			}
		}
	})

	krb := e.kerberosClient(t)

	code, _, body := soapPost(t, krb.Do, xcepURL, getPoliciesSOAP())
	if code != http.StatusOK {
		t.Fatalf("GetPolicies as %s: status %d: %.300s", e.user, code, body)
	}
	var pol policiesResponse
	if err := xml.Unmarshal(body, &pol); err != nil {
		t.Fatalf("parse GetPoliciesResponse: %v", err)
	}
	if len(pol.Policies) == 0 {
		t.Fatal("GetPolicies offered no templates to the user")
	}
	for _, p := range pol.Policies {
		// A user must be offered user templates: subject from the
		// directory CN, and not marked machine type.
		if p.SubjectNameFlags != subjectCNFromDir || p.GeneralFlags&generalMachineType != 0 {
			t.Errorf("template %s offered to a user with subjectNameFlags %#x generalFlags %#x; want %#x and no machine flag",
				p.CommonName, p.SubjectNameFlags, p.GeneralFlags, subjectCNFromDir)
		}
	}
	caDER, err := base64.StdEncoding.DecodeString(pol.CACertificate)
	if err != nil {
		t.Fatalf("policy CA certificate: %v", err)
	}
	issuer, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("policy CA certificate: %v", err)
	}

	// The CSR names someone else: the hub must ignore that and issue to the
	// authenticated user.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Administrator", Organization: []string{"Domain Admins"}},
		DNSNames: []string{"not-me.example"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	tokenType := x509v3TokenType
	if e.templateOID != "" {
		tokenType = e.templateOID
	}
	code, _, body = soapPost(t, krb.Do, wstepURL, wstepSOAP(csrDER, tokenType))
	if code != http.StatusOK {
		t.Fatalf("WSTEP enroll as %s: status %d: %.300s", e.user, code, body)
	}
	var rstr rstrResponse
	if err := xml.Unmarshal(body, &rstr); err != nil || len(rstr.Issued) != 1 {
		t.Fatalf("parse RSTR: %v (%d certificates): %.300s", err, len(rstr.Issued), body)
	}
	certDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rstr.Issued[0]))
	if err != nil {
		t.Fatalf("issued certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("issued certificate: %v", err)
	}
	fingerprint := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(fingerprint[:])
	t.Logf("issued serial %s to %s, valid until %s", cert.SerialNumber.Text(16), cert.Subject, cert.NotAfter.UTC().Format(time.RFC3339))
	if e.apiToken != "" {
		t.Cleanup(func() { revoke(t, e, fp) })
	}

	if got := cert.Subject.String(); got != "CN="+e.user {
		t.Errorf("subject %q, want CN=%s: the hub must name the Kerberos user, not the CSR", got, e.user)
	}
	if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) != 0 {
		t.Errorf("user certificate carries SANs %v %v %v %v; want none", cert.DNSNames, cert.IPAddresses, cert.URIs, cert.EmailAddresses)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Error("issued certificate is not for the CSR's key")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("EKU %v, want clientAuth only", cert.ExtKeyUsage)
	}
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		t.Errorf("issued certificate does not verify against the policy's CA: %v", err)
	}

	if e.apiToken != "" {
		checkInventory(t, e, fp)
	}
}

func apiRequest(t *testing.T, e liveEnv, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, e.base+"/api/v1"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e.apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out
}

// checkInventory proves the issuance reached the hub's inventory as a WSTEP
// row for the user, carrying the template it was held to, if one was named.
func checkInventory(t *testing.T, e liveEnv, fp string) {
	t.Helper()
	code, body := apiRequest(t, e, http.MethodGet, "/certificates/"+fp, nil)
	if code != http.StatusOK {
		t.Fatalf("inventory lookup: status %d: %.200s", code, body)
	}
	var got struct {
		Data struct {
			Source     string `json:"source"`
			CommonName string `json:"common_name"`
			TemplateID string `json:"template_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("inventory row: %v", err)
	}
	if got.Data.Source != "wstep" || got.Data.CommonName != e.user {
		t.Errorf("inventory row source=%q cn=%q, want wstep and %s", got.Data.Source, got.Data.CommonName, e.user)
	}
	if e.templateOID != "" && got.Data.TemplateID == "" {
		t.Error("inventory row has no template_id for a template-governed issuance")
	}
	t.Logf("inventory: source=%s cn=%s template_id=%s", got.Data.Source, got.Data.CommonName, got.Data.TemplateID)
}

func revoke(t *testing.T, e liveEnv, fp string) {
	code, body := apiRequest(t, e, http.MethodPost, "/certificates/"+fp+"/revoke", []byte(`{"reason_code":4,"reason_text":"W19-10 live test certificate"}`))
	if code != http.StatusOK {
		t.Errorf("revoke test certificate %s: status %d: %.200s", fp, code, body)
	}
}
