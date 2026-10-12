// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package xcep

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/wstep"
)

func testCACert(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The decode targets mirror MS-XCEP 3.1.4.1.2.2 and 3.1.4.1.3.x, keeping
// the fields a Windows client dereferences.
type xNil struct {
	Nil   string `xml:"http://www.w3.org/2001/XMLSchema-instance nil,attr"`
	Value string `xml:",chardata"`
}

type xEnvelope struct {
	Header struct {
		Action    string `xml:"Action"`
		RelatesTo string `xml:"RelatesTo"`
	} `xml:"Header"`
	Body struct {
		Resp struct {
			Response struct {
				PolicyID           string `xml:"policyID"`
				PoliciesNotChanged xNil   `xml:"policiesNotChanged"`
				Policies           *struct {
					Nil    string    `xml:"http://www.w3.org/2001/XMLSchema-instance nil,attr"`
					Policy []xPolicy `xml:"policy"`
				} `xml:"policies"`
			} `xml:"response"`
			CAs struct {
				CA []struct {
					URIs struct {
						CAURI []struct {
							ClientAuthentication int    `xml:"clientAuthentication"`
							URI                  string `xml:"uri"`
							RenewalOnly          bool   `xml:"renewalOnly"`
						} `xml:"cAURI"`
					} `xml:"uris"`
					Certificate    string `xml:"certificate"`
					CAReferenceID  int    `xml:"cAReferenceID"`
					EnrollPermited bool   `xml:"enrollPermission"`
				} `xml:"cA"`
			} `xml:"cAs"`
			OIDs struct {
				Nil string `xml:"http://www.w3.org/2001/XMLSchema-instance nil,attr"`
				OID []struct {
					Value string `xml:"value"`
					Group int    `xml:"group"`
					Ref   int    `xml:"oIDReferenceID"`
					Name  string `xml:"defaultName"`
				} `xml:"oID"`
			} `xml:"oIDs"`
		} `xml:"GetPoliciesResponse"`
	} `xml:"Body"`
}

type xPolicy struct {
	OIDRef int   `xml:"policyOIDReference"`
	CARefs []int `xml:"cAs>cAReference"`
	Attrs  struct {
		CommonName    string `xml:"commonName"`
		PolicySchema  int    `xml:"policySchema"`
		Validity      uint64 `xml:"certificateValidity>validityPeriodSeconds"`
		Renewal       uint64 `xml:"certificateValidity>renewalPeriodSeconds"`
		Enroll        bool   `xml:"permission>enroll"`
		AutoEnroll    bool   `xml:"permission>autoEnroll"`
		MinKey        int    `xml:"privateKeyAttributes>minimalKeyLength"`
		Major         int    `xml:"revision>majorRevision"`
		SubjectFlags  uint32 `xml:"subjectNameFlags"`
		GeneralFlags  uint32 `xml:"generalFlags"`
		HashAlgorithm xNil   `xml:"hashAlgorithmOIDReference"`
		Extensions    []struct {
			OIDRef   int    `xml:"oIDReference"`
			Critical bool   `xml:"critical"`
			Value    string `xml:"value"`
		} `xml:"extensions>extension"`
	} `xml:"attributes"`
}

const getPoliciesAction2 = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"

func requestWithMessageID(id string) string {
	return strings.Replace(getPoliciesSOAP(getPoliciesAction2), "</a:Action>", "</a:Action><a:MessageID>"+id+"</a:MessageID>", 1)
}

func fetchPolicies(t *testing.T, srv *Server, who wstep.Identity, body string) xEnvelope {
	t.Helper()
	srv.WithAuthenticator(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(wstep.WithIdentity(r.Context(), who)))
		})
	})
	req := httptest.NewRequest(http.MethodPost, "https://hub.corp.example:8443/xcep", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var env xEnvelope
	if err := xml.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("response is not XML: %v\n%s", err, w.Body.String())
	}
	return env
}

func TestGetPoliciesResponseFollowsSchema(t *testing.T) {
	ca := testCACert(t)
	srv := NewServer(func() ([]Template, error) {
		return []Template{{Name: "KKMachine", DisplayName: "KK Machine", OID: "1.3.6.1.4.1.311.21.8.4150237.1.1", AutoEnroll: true, Revision: 3}}, nil
	}, "kk-policy").WithIssuer(ca, "")
	machine := wstep.IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	env := fetchPolicies(t, srv, machine, requestWithMessageID("urn:uuid:5fb5f6fd-4709-414b-8afa-0c05f6686d1c"))
	r := env.Body.Resp

	if env.Header.RelatesTo != "urn:uuid:5fb5f6fd-4709-414b-8afa-0c05f6686d1c" {
		t.Fatalf("RelatesTo %q must echo the request MessageID", env.Header.RelatesTo)
	}
	if r.Response.PolicyID != "kk-policy" || r.Response.PoliciesNotChanged.Nil != "true" {
		t.Fatalf("response header fields %+v", r.Response)
	}
	if r.Response.Policies == nil || len(r.Response.Policies.Policy) != 1 {
		t.Fatalf("policies %+v", r.Response.Policies)
	}
	p := r.Response.Policies.Policy[0]

	// policyOIDReference is an int that must resolve in <oIDs> to the
	// template OID as an enrollment object (group 9).
	var resolved bool
	for _, o := range r.OIDs.OID {
		if o.Ref == p.OIDRef && o.Value == "1.3.6.1.4.1.311.21.8.4150237.1.1" && o.Group == 9 && o.Name == "KK Machine" {
			resolved = true
		}
	}
	if !resolved {
		t.Fatalf("policyOIDReference %d does not resolve in oIDs %+v", p.OIDRef, r.OIDs.OID)
	}
	if len(r.CAs.CA) != 1 || !slices.Equal(p.CARefs, []int{r.CAs.CA[0].CAReferenceID}) {
		t.Fatalf("policy cAs %v must reference the CA %+v", p.CARefs, r.CAs.CA)
	}
	if got, _ := base64.StdEncoding.DecodeString(r.CAs.CA[0].Certificate); string(got) != string(ca) {
		t.Fatal("CA certificate is not the issuer's DER")
	}
	uris := r.CAs.CA[0].URIs.CAURI
	// Only Kerberos: 8 would promise WS-Security message signing, which the
	// hub does not implement.
	if len(uris) != 1 || uris[0].ClientAuthentication != 2 || uris[0].RenewalOnly {
		t.Fatalf("want one Kerberos URI for enroll and renew, got %+v", uris)
	}
	for _, u := range uris {
		if u.URI != "https://hub.corp.example:8443/wstep" {
			t.Fatalf("CES URI %q must be on the host the client used", u.URI)
		}
	}

	a := p.Attrs
	if a.CommonName != "KKMachine" || a.PolicySchema != 2 || a.HashAlgorithm.Nil != "true" {
		t.Fatalf("schema-2 attributes need a nil hashAlgorithmOIDReference: %+v", a)
	}
	if a.Validity != 365*24*3600 || a.Renewal == 0 || a.Renewal >= a.Validity {
		t.Fatalf("certificateValidity %d/%d", a.Validity, a.Renewal)
	}
	if !a.Enroll || !a.AutoEnroll || a.MinKey != 2048 || a.Major != 3 {
		t.Fatalf("attributes %+v", a)
	}
	// The policy hands the client the CertificateTemplate extension to put
	// in its request: template OID and the advertised major revision.
	if len(a.Extensions) != 1 || a.Extensions[0].Critical {
		t.Fatalf("extensions %+v", a.Extensions)
	}
	var extOID string
	for _, o := range r.OIDs.OID {
		if o.Ref == a.Extensions[0].OIDRef {
			extOID = o.Value
			if o.Group != 6 {
				t.Fatalf("extension OID group %d, want 6", o.Group)
			}
		}
	}
	if extOID != "1.3.6.1.4.1.311.21.7" {
		t.Fatalf("extension OID %q", extOID)
	}
	raw, _ := base64.StdEncoding.DecodeString(a.Extensions[0].Value)
	var tmpl struct {
		ID           asn1.ObjectIdentifier
		Major, Minor int64
	}
	if rest, err := asn1.Unmarshal(raw, &tmpl); err != nil || len(rest) != 0 {
		t.Fatalf("template extension value: %v", err)
	}
	if tmpl.ID.String() != "1.3.6.1.4.1.311.21.8.4150237.1.1" || tmpl.Major != 3 || tmpl.Minor != 0 {
		t.Fatalf("template extension %+v", tmpl)
	}
	refs := map[int]bool{}
	for _, o := range r.OIDs.OID {
		if refs[o.Ref] {
			t.Fatalf("duplicate oIDReferenceID %d", o.Ref)
		}
		refs[o.Ref] = true
	}

	if a.GeneralFlags != 0x40 || a.SubjectFlags != 0x10000000|0x08000000 {
		t.Fatalf("machine caller: generalFlags %#x subjectNameFlags %#x", a.GeneralFlags, a.SubjectFlags)
	}
}

func TestGetPoliciesForUserIsUserTemplate(t *testing.T) {
	srv := NewServer(func() ([]Template, error) {
		return []Template{{Name: "KKUser", OID: "1.2.3.4", Enrollee: wstep.EnrolleeUser}}, nil
	}, "p").WithIssuer(testCACert(t), "https://explicit.example/wstep")
	env := fetchPolicies(t, srv, wstep.IdentityForPrincipal("alice", "CORP.EXAMPLE"), getPoliciesSOAP(getPoliciesAction2))
	a := env.Body.Resp.Response.Policies.Policy[0].Attrs
	if a.GeneralFlags != 0 || a.SubjectFlags != 0x40000000 {
		t.Fatalf("user caller: generalFlags %#x subjectNameFlags %#x", a.GeneralFlags, a.SubjectFlags)
	}
	if u := env.Body.Resp.CAs.CA[0].URIs.CAURI[0].URI; u != "https://explicit.example/wstep" {
		t.Fatalf("configured CES URL ignored: %q", u)
	}
	if env.Header.RelatesTo != "" {
		t.Fatalf("no MessageID, no RelatesTo; got %q", env.Header.RelatesTo)
	}
}

func TestGetPoliciesRenewalWindowOverride(t *testing.T) {
	srv := NewServer(func() ([]Template, error) {
		return []Template{{Name: "A", OID: "1.2.3", RenewalSeconds: 100, Enrollee: wstep.EnrolleeUser}, {Name: "B", OID: "1.2.4", RenewalSeconds: 365 * 24 * 3600, Enrollee: wstep.EnrolleeUser}}, nil
	}, "p").WithIssuer(testCACert(t), "")
	pol := fetchPolicies(t, srv, wstep.IdentityForPrincipal("alice", "CORP.EXAMPLE"), getPoliciesSOAP(getPoliciesAction2)).Body.Resp.Response.Policies.Policy
	if pol[0].Attrs.Renewal != 100 {
		t.Fatalf("renewal override %d", pol[0].Attrs.Renewal)
	}
	if pol[1].Attrs.Renewal >= pol[1].Attrs.Validity {
		t.Fatalf("a renewal window at or past the validity must fall back: %d", pol[1].Attrs.Renewal)
	}
	if pol[0].OIDRef == pol[1].OIDRef {
		t.Fatal("oIDReferenceIDs must be unique")
	}
}

func TestGetPoliciesWithoutTemplatesIsNil(t *testing.T) {
	srv := NewServer(func() ([]Template, error) {
		return []Template{{Name: "no-oid"}, {Name: "bad-oid", OID: "1.2.x"}}, nil
	}, "p").WithIssuer(testCACert(t), "")
	env := fetchPolicies(t, srv, wstep.IdentityForPrincipal("alice", "CORP.EXAMPLE"), getPoliciesSOAP(getPoliciesAction2))
	if p := env.Body.Resp.Response.Policies; p == nil || p.Nil != "true" || len(p.Policy) != 0 {
		t.Fatalf("policies must be xsi:nil when nothing is offered: %+v", p)
	}
	if env.Body.Resp.OIDs.Nil != "true" {
		t.Fatal("oIDs must be xsi:nil when empty (minOccurs=1)")
	}
}

func TestGetPoliciesWithoutIssuerFaults(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "p").WithIssuer(nil, "")
	srv.caCertDER = []byte{}
	req := httptest.NewRequest(http.MethodPost, "/xcep", strings.NewReader(getPoliciesSOAP(getPoliciesAction2)))
	w := httptest.NewRecorder()
	srv.WithAuthenticator(signedIn).Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "No issuing CA") {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}

// W20-17: each caller is offered only templates of its own kind.
func TestGetPoliciesOffersOnlyCallersEnrolleeType(t *testing.T) {
	srv := NewServer(func() ([]Template, error) {
		return []Template{
			{Name: "KKMachine", OID: "1.2.3.1"},
			{Name: "KKUser", OID: "1.2.3.2", Enrollee: wstep.EnrolleeUser},
			{Name: "KKMachine2", OID: "1.2.3.3", Enrollee: wstep.EnrolleeMachine},
		}, nil
	}, "p").WithIssuer(testCACert(t), "")
	names := func(who wstep.Identity) []string {
		var out []string
		for _, p := range fetchPolicies(t, srv, who, getPoliciesSOAP(getPoliciesAction2)).Body.Resp.Response.Policies.Policy {
			out = append(out, p.Attrs.CommonName)
		}
		return out
	}
	if got := names(wstep.IdentityForPrincipal("WS01$", "CORP.EXAMPLE")); len(got) != 2 || got[0] != "KKMachine" || got[1] != "KKMachine2" {
		t.Errorf("machine offered %v, want [KKMachine KKMachine2]", got)
	}
	if got := names(wstep.IdentityForPrincipal("alice", "CORP.EXAMPLE")); len(got) != 1 || got[0] != "KKUser" {
		t.Errorf("user offered %v, want [KKUser]", got)
	}
}
