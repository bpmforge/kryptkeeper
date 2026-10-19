// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"
)

type pkiNode struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

type nodeOpts struct {
	cn        string
	ca        bool
	notBefore time.Time
	notAfter  time.Time
}

// issue signs a new cert with parent (nil = self-signed). All keys are
// generated in-test and never leave it.
func issue(t *testing.T, parent *pkiNode, o nodeOpts) *pkiNode {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: o.cn},
		DNSNames:              []string{o.cn},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		BasicConstraintsValid: true,
		IsCA:                  o.ca,
	}
	if o.ca {
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pkiNode{cert: c, key: key}
}

func chainOf(nodes ...*pkiNode) []*x509.Certificate {
	out := make([]*x509.Certificate, len(nodes))
	for i, n := range nodes {
		out[i] = n.cert
	}
	return out
}

func poolOf(nodes ...*pkiNode) *x509.CertPool {
	p := x509.NewCertPool()
	for _, n := range nodes {
		p.AddCert(n.cert)
	}
	return p
}

func TestClassifyChain(t *testing.T) {
	now := time.Now()

	hubRoot := issue(t, nil, nodeOpts{cn: "Hub Root", ca: true})
	hubInt := issue(t, hubRoot, nodeOpts{cn: "Hub Issuing", ca: true})
	hubLeaf := issue(t, hubInt, nodeOpts{cn: "app.hub.test"})
	hub := chainOf(hubRoot, hubInt)

	pubRoot := issue(t, nil, nodeOpts{cn: "Test Public Root", ca: true})
	pubInt := issue(t, pubRoot, nodeOpts{cn: "Test Public Issuing", ca: true})
	pubLeaf := issue(t, pubInt, nodeOpts{cn: "www.public.test"})
	system := poolOf(pubRoot)

	otherRoot := issue(t, nil, nodeOpts{cn: "Other Root", ca: true})
	otherInt := issue(t, otherRoot, nodeOpts{cn: "Other Issuing", ca: true})
	otherLeaf := issue(t, otherInt, nodeOpts{cn: "svc.other.test"})

	selfCA := issue(t, nil, nodeOpts{cn: "self-ca.test", ca: true})
	selfLeaf := issue(t, nil, nodeOpts{cn: "self-leaf.test"})

	anchors := TrustAnchors{System: system, Hub: hub}
	// A platform-style system pool that also knows the public intermediate, so
	// a leaf served alone still verifies -- through a certificate the server
	// withheld.
	platform := TrustAnchors{System: poolOf(pubRoot, pubInt), Hub: hub}

	// completeness: "yes" (known complete), "no" (provably incomplete),
	// "unknown" (cannot be judged; stored NULL, never flagged).
	cases := []struct {
		name     string
		served   []*x509.Certificate
		anchors  TrustAnchors
		class    string
		complete string
		trusted  bool
		flags    []string
	}{
		{"hub full chain", chainOf(hubLeaf, hubInt, hubRoot), anchors, TrustManaged, "yes", true, nil},
		{"hub leaf with its intermediate, root not served, is complete", chainOf(hubLeaf, hubInt), anchors, TrustManaged, "yes", true, nil},
		{"hub leaf served alone under a hub intermediate is incomplete", chainOf(hubLeaf), anchors, TrustManaged, "no", true, []string{FlagIncompleteChain}},
		{"public chain with intermediate served, root omitted, is complete", chainOf(pubLeaf, pubInt), anchors, TrustPublic, "yes", true, nil},
		{"public full chain is complete", chainOf(pubLeaf, pubInt, pubRoot), anchors, TrustPublic, "yes", true, nil},
		{"public leaf served alone, intermediate supplied by the verifier, is incomplete", chainOf(pubLeaf), platform, TrustPublic, "no", true, []string{FlagIncompleteChain}},
		{"public chain served with intermediate is complete even when the verifier knows it too", chainOf(pubLeaf, pubInt), platform, TrustPublic, "yes", true, nil},
		{"public leaf served alone cannot be traced (no AIA fetch): unknown, not flagged", chainOf(pubLeaf), anchors, TrustPrivateOther, "unknown", false, nil},
		{"other private full chain: untrusted root, complete", chainOf(otherLeaf, otherInt, otherRoot), anchors, TrustPrivateOther, "yes", false, []string{FlagUntrustedRoot}},
		{"other private leaf+intermediate without root is not flagged", chainOf(otherLeaf, otherInt), anchors, TrustPrivateOther, "unknown", false, nil},
		{"other private leaf served alone is not flagged", chainOf(otherLeaf), anchors, TrustPrivateOther, "unknown", false, nil},
		{"self-signed CA:TRUE leaf", chainOf(selfCA), anchors, TrustSelfSigned, "yes", false, nil},
		{"self-signed CA:FALSE leaf", chainOf(selfLeaf), anchors, TrustSelfSigned, "yes", false, nil},
		{"public chain with no system pool injected", chainOf(pubLeaf, pubInt, pubRoot), TrustAnchors{Hub: hub}, TrustPrivateOther, "yes", false, []string{FlagUntrustedRoot}},
		{"hub chain with no hub CAs known", chainOf(hubLeaf, hubInt, hubRoot), TrustAnchors{System: system}, TrustPrivateOther, "yes", false, []string{FlagUntrustedRoot}},
		{"unrelated extra cert after the leaf does not complete it", chainOf(otherLeaf, hubRoot), TrustAnchors{System: system}, TrustPrivateOther, "unknown", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := ClassifyChain(tc.served, tc.anchors, now)
			got := "unknown"
			if v.CompleteKnown {
				got = map[bool]string{true: "yes", false: "no"}[v.Complete]
			}
			if v.Class != tc.class || got != tc.complete || v.Trusted != tc.trusted {
				t.Fatalf("got class=%s complete=%s trusted=%v, want %s/%s/%v", v.Class, got, v.Trusted, tc.class, tc.complete, tc.trusted)
			}
			if !slices.Equal(v.Flags, tc.flags) {
				t.Fatalf("flags = %v, want %v", v.Flags, tc.flags)
			}
		})
	}
}

// leafNamesHubIntermediate backs the one INCOMPLETE_CHAIN proof that does not
// need a successful verification: a lone leaf naming a hub intermediate.
func TestLeafNamesHubIntermediate(t *testing.T) {
	root := issue(t, nil, nodeOpts{cn: "Hub Root", ca: true})
	inter := issue(t, root, nodeOpts{cn: "Hub Issuing", ca: true})
	leaf := issue(t, inter, nodeOpts{cn: "app.hub.test"})
	other := issue(t, nil, nodeOpts{cn: "Other Root", ca: true})
	otherLeaf := issue(t, issue(t, other, nodeOpts{cn: "Other Issuing", ca: true}), nodeOpts{cn: "svc.other.test"})

	if !leafNamesHubIntermediate(leaf.cert, chainOf(root, inter)) {
		t.Fatal("leaf AKI must match the hub intermediate's SKI")
	}
	if leafNamesHubIntermediate(leaf.cert, chainOf(root)) {
		t.Fatal("a self-signed hub root is not an intermediate")
	}
	if leafNamesHubIntermediate(otherLeaf.cert, chainOf(root, inter)) {
		t.Fatal("an unrelated leaf must not match a hub intermediate")
	}
}

func TestClassifyChainEmpty(t *testing.T) {
	if v := ClassifyChain(nil, TrustAnchors{}, time.Now()); v.Class != TrustUnknown {
		t.Fatalf("empty chain class = %s, want unknown", v.Class)
	}
}

// An expired leaf must still be attributed to its issuer: expiry is a
// separate finding, and hiding whose cert it is would defeat the point.
func TestClassifyChainExpiredLeafKeepsAttribution(t *testing.T) {
	root := issue(t, nil, nodeOpts{cn: "Hub Root", ca: true, notBefore: time.Now().Add(-800 * 24 * time.Hour)})
	expired := issue(t, root, nodeOpts{
		cn:        "old.hub.test",
		notBefore: time.Now().Add(-400 * 24 * time.Hour),
		notAfter:  time.Now().Add(-35 * 24 * time.Hour),
	})
	hub := TrustAnchors{Hub: chainOf(root)}
	if v := ClassifyChain(chainOf(expired, root), hub, time.Now()); v.Class != TrustManaged || !v.Trusted {
		t.Fatalf("expired hub leaf: %+v, want managed/trusted", v)
	}
	if v := ClassifyChain(chainOf(expired, root), TrustAnchors{System: poolOf(root)}, time.Now()); v.Class != TrustPublic {
		t.Fatalf("expired public leaf: %+v, want public", v)
	}
}

// An issuing CA that has since lapsed must not hide whose leaf this is.
func TestClassifyChainExpiredIntermediateKeepsAttribution(t *testing.T) {
	root := issue(t, nil, nodeOpts{cn: "Hub Root", ca: true, notBefore: time.Now().Add(-1500 * 24 * time.Hour), notAfter: time.Now().Add(1000 * 24 * time.Hour)})
	inter := issue(t, root, nodeOpts{cn: "Old Issuing", ca: true, notBefore: time.Now().Add(-1000 * 24 * time.Hour), notAfter: time.Now().Add(-10 * 24 * time.Hour)})
	leaf := issue(t, inter, nodeOpts{cn: "app.hub.test", notBefore: time.Now().Add(-900 * 24 * time.Hour), notAfter: time.Now().Add(-100 * 24 * time.Hour)})
	v := ClassifyChain(chainOf(leaf, inter), TrustAnchors{Hub: chainOf(root)}, time.Now())
	if v.Class != TrustManaged || !v.Trusted {
		t.Fatalf("leaf under an expired hub intermediate: %+v, want managed/trusted", v)
	}
}

// The expiry retry only forgives a validity-window failure. A wrong
// signature must never be rescued by it.
func TestClassifyChainRetryDoesNotForgiveBadSignature(t *testing.T) {
	root := issue(t, nil, nodeOpts{cn: "Hub Root", ca: true})
	impostorRoot := issue(t, nil, nodeOpts{cn: "Hub Root", ca: true}) // same subject, different key
	forged := issue(t, impostorRoot, nodeOpts{
		cn:        "forged.hub.test",
		notBefore: time.Now().Add(-400 * 24 * time.Hour),
		notAfter:  time.Now().Add(-35 * 24 * time.Hour),
	})
	v := ClassifyChain(chainOf(forged, impostorRoot), TrustAnchors{Hub: chainOf(root)}, time.Now())
	if v.Trusted || v.Class == TrustManaged {
		t.Fatalf("forged leaf under a look-alike root was trusted: %+v", v)
	}
}

func TestApplyTrust(t *testing.T) {
	root := issue(t, nil, nodeOpts{cn: "Other Root", ca: true})
	inter := issue(t, root, nodeOpts{cn: "Other Issuing", ca: true})
	leaf := issue(t, inter, nodeOpts{cn: "svc.other.test"})

	ep := DiscoveredEndpoint{Host: "svc.other.test", Port: 443}
	for i, n := range chainOf(leaf, inter, root) {
		dc := certToDiscovered(n, "svc.other.test", i == 0)
		dc.Served = true
		ep.Certs = append(ep.Certs, dc)
	}
	before := ep.Certs[0].RiskScore
	ApplyTrust(&ep, TrustAnchors{}, time.Now())

	l := ep.Certs[0]
	if l.TrustClass != TrustPrivateOther || !l.ChainComplete || !l.ChainCompleteKnown || l.ChainTrusted || l.ChainCA {
		t.Fatalf("leaf = %+v", l)
	}
	if !slices.Contains(l.RiskFlags, FlagUntrustedRoot) || l.RiskScore != before+untrustedRootScore {
		t.Fatalf("flags=%v score=%d (before %d)", l.RiskFlags, l.RiskScore, before)
	}
	if !ep.Certs[1].ChainCA || !ep.Certs[2].ChainCA {
		t.Fatal("intermediate and root must be marked as chain CAs")
	}
	if ep.Certs[1].TrustClass != "" {
		t.Fatalf("chain CA must not carry a leaf verdict, got %q", ep.Certs[1].TrustClass)
	}

	// Re-applying must not double-count the score.
	score := l.RiskScore
	ApplyTrust(&ep, TrustAnchors{}, time.Now())
	if ep.Certs[0].RiskScore != score {
		t.Fatalf("score changed on re-apply: %d -> %d", score, ep.Certs[0].RiskScore)
	}
}

func TestApplyTrustLeavesNonServedAlone(t *testing.T) {
	c := issue(t, nil, nodeOpts{cn: "store.test", ca: true})
	ep := DiscoveredEndpoint{Certs: []DiscoveredCert{certToDiscovered(c.cert, "h", true)}}
	ApplyTrust(&ep, TrustAnchors{}, time.Now())
	if ep.Certs[0].TrustClass != "" || ep.Certs[0].ChainCA {
		t.Fatalf("non-served cert was classified: %+v", ep.Certs[0])
	}
}

func TestApplyTrustUnparseableLeafIsUnknown(t *testing.T) {
	ep := DiscoveredEndpoint{Certs: []DiscoveredCert{{Served: true, Raw: []byte("not der")}}}
	ApplyTrust(&ep, TrustAnchors{}, time.Now())
	if ep.Certs[0].TrustClass != TrustUnknown {
		t.Fatalf("class = %q, want unknown", ep.Certs[0].TrustClass)
	}
}

func TestIsTrustClass(t *testing.T) {
	for _, c := range TrustClasses {
		if !IsTrustClass(c) {
			t.Errorf("%s should be valid", c)
		}
	}
	if IsTrustClass("bogus") || IsTrustClass("") {
		t.Error("unexpected valid class")
	}
}

// W34-06: issuer_class refines trust_class with the operator's declaration.
func TestClassifyIssuer(t *testing.T) {
	now := time.Now()
	hubRoot := issue(t, nil, nodeOpts{cn: "Hub Root", ca: true})
	hubLeaf := issue(t, hubRoot, nodeOpts{cn: "hub.example"})
	extRoot := issue(t, nil, nodeOpts{cn: "Corp Legacy Root", ca: true})
	extInt := issue(t, extRoot, nodeOpts{cn: "Corp Issuing CA", ca: true})
	extLeaf := issue(t, extInt, nodeOpts{cn: "legacy.example"})
	otherRoot := issue(t, nil, nodeOpts{cn: "Random Private Root", ca: true})
	otherLeaf := issue(t, otherRoot, nodeOpts{cn: "stranger.example"})
	self := issue(t, nil, nodeOpts{cn: "self.example"})

	base := TrustAnchors{Hub: []*x509.Certificate{hubRoot.cert}, IssuerClassKnown: true}
	withCA := base
	withCA.Authorized = []*x509.Certificate{extRoot.cert}
	withInt := base
	withInt.Authorized = []*x509.Certificate{extInt.cert}
	withDN := base
	withDN.IssuerRules = []IssuerRule{{IssuerRuleDN, "cn=corp issuing ca"}}
	withSPKI := base
	withSPKI.IssuerRules = []IssuerRule{{IssuerRuleSPKI, SPKIHash(extInt.cert)}}
	wrongRules := base
	wrongRules.IssuerRules = []IssuerRule{{IssuerRuleDN, "CN=Somebody Else"}, {IssuerRuleSPKI, SPKIHash(otherRoot.cert)}}

	cases := []struct {
		name   string
		served []*x509.Certificate
		trust  string
		a      TrustAnchors
		want   string
	}{
		{"hub", chainOf(hubLeaf), TrustManaged, base, IssuerHub},
		{"self signed", chainOf(self), TrustSelfSigned, base, IssuerSelfSigned},
		{"public stays public with no rule", chainOf(extLeaf), TrustPublic, base, IssuerPublic},
		{"private stays private_unknown", chainOf(otherLeaf), TrustPrivateOther, base, IssuerPrivateUnknown},
		{"unknown trust is unknown", chainOf(otherLeaf), TrustUnknown, base, IssuerUnknown},
		{"authorized by CA cert, full chain", chainOf(extLeaf, extInt), TrustPrivateOther, withCA, IssuerAuthorized},
		{"authorized by issuing CA cert, lone leaf", chainOf(extLeaf), TrustPrivateOther, withInt, IssuerAuthorized},
		{"authorized root cannot vouch for a lone leaf under an unseen intermediate", chainOf(extLeaf), TrustPrivateOther, withCA, IssuerPrivateUnknown},
		{"authorized outranks public (a declared public CA is sanctioned)", chainOf(extLeaf), TrustPublic, withDN, IssuerAuthorized},
		{"authorized by issuer DN, lone leaf", chainOf(extLeaf), TrustPrivateOther, withDN, IssuerAuthorized},
		{"authorized by SPKI needs the issuer served", chainOf(extLeaf, extInt), TrustPrivateOther, withSPKI, IssuerAuthorized},
		{"SPKI cannot match a lone leaf", chainOf(extLeaf), TrustPrivateOther, withSPKI, IssuerPrivateUnknown},
		{"unrelated rules do not authorize", chainOf(extLeaf), TrustPrivateOther, wrongRules, IssuerPrivateUnknown},
		{"hub outranks a rule that also matches", chainOf(hubLeaf), TrustManaged, withDN, IssuerHub},
		{"unserved file cert issued by a hub CA", chainOf(hubLeaf), "", base, IssuerHub},
		{"unserved self-signed", chainOf(self), "", base, IssuerSelfSigned},
		{"unserved authorized by DN", chainOf(extLeaf), "", withDN, IssuerAuthorized},
		{"unserved unrelated is unknown", chainOf(otherLeaf), "", base, IssuerUnknown},
	}
	for _, c := range cases {
		if got := ClassifyIssuer(c.served, c.trust, c.a, now); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	if ClassifyIssuer(nil, "", base, now) != IssuerUnknown {
		t.Error("empty chain is unknown")
	}
}

func TestNormalizeDN(t *testing.T) {
	if NormalizeDN("CN=Corp Issuing CA, O=Corp, C=US") != NormalizeDN("cn=corp issuing ca,o=corp,c=us") {
		t.Error("DN comparison must ignore case and spacing after separators")
	}
}

func TestApplyTrustSetsIssuerClassOnlyWhenKnown(t *testing.T) {
	root := issue(t, nil, nodeOpts{cn: "Corp Root", ca: true})
	leaf := issue(t, root, nodeOpts{cn: "svc.example"})
	mk := func() *DiscoveredEndpoint {
		return &DiscoveredEndpoint{Certs: []DiscoveredCert{{Raw: leaf.cert.Raw, Served: true}}}
	}
	ep := mk()
	ApplyTrust(ep, TrustAnchors{}, time.Now())
	if ep.Certs[0].IssuerClass != "" {
		t.Fatalf("issuer class must stay empty when the declared set was not read, got %q", ep.Certs[0].IssuerClass)
	}
	ep = mk()
	ApplyTrust(ep, TrustAnchors{Authorized: []*x509.Certificate{root.cert}, IssuerClassKnown: true}, time.Now())
	if ep.Certs[0].IssuerClass != IssuerAuthorized || ep.Certs[0].TrustClass != TrustPrivateOther {
		t.Fatalf("issuer=%q trust=%q: trust_class must be untouched by authorization", ep.Certs[0].IssuerClass, ep.Certs[0].TrustClass)
	}
}

func TestApplyIssuerClassForUnservedCerts(t *testing.T) {
	root := issue(t, nil, nodeOpts{cn: "Corp Root", ca: true})
	leaf := issue(t, root, nodeOpts{cn: "file.example"})
	ep := &DiscoveredEndpoint{Certs: []DiscoveredCert{{Raw: leaf.cert.Raw}, {Raw: []byte("junk")}, {Raw: leaf.cert.Raw, Served: true}}}
	ApplyIssuerClass(ep, TrustAnchors{IssuerRules: []IssuerRule{{IssuerRuleDN, root.cert.Subject.String()}}, IssuerClassKnown: true}, time.Now())
	if ep.Certs[0].IssuerClass != IssuerAuthorized || ep.Certs[1].IssuerClass != IssuerUnknown || ep.Certs[2].IssuerClass != "" {
		t.Fatalf("classes = %q %q %q", ep.Certs[0].IssuerClass, ep.Certs[1].IssuerClass, ep.Certs[2].IssuerClass)
	}
	ep2 := &DiscoveredEndpoint{Certs: []DiscoveredCert{{Raw: leaf.cert.Raw}}}
	ApplyIssuerClass(ep2, TrustAnchors{}, time.Now())
	if ep2.Certs[0].IssuerClass != "" {
		t.Fatal("not known => untouched")
	}
}
