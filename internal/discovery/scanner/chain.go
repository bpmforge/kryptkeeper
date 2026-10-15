// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"crypto/x509"
	"errors"
	"slices"
	"time"
)

// Trust classes answer "whose certificate is this?" for a leaf a server
// presented. They come from a real x509 Verify of the presented chain, never
// from the handshake (which stays permissive so bad certs can be inspected).
const (
	// TrustManaged: the leaf chains to one of this hub's own CAs.
	TrustManaged = "managed"
	// TrustPublic: the leaf chains to a system root (a public WebPKI CA).
	TrustPublic = "public"
	// TrustPrivateOther: neither of the above, and the leaf is not self-signed:
	// issued by some other private CA (or one whose chain we cannot see).
	TrustPrivateOther = "private_other"
	// TrustSelfSigned: the leaf vouches only for itself (CA bit irrelevant).
	TrustSelfSigned = "self_signed"
	// TrustUnknown: the verdict could not be reached (unparseable chain, or a
	// verification failure that is neither "unknown issuer" nor expiry).
	TrustUnknown = "unknown"
)

// Chain risk flags added to the leaf of a classified chain.
const (
	// FlagIncompleteChain: an intermediate is PROVABLY missing -- the chain
	// only verifies because of a CA certificate the server did not send (a hub
	// intermediate, or one the platform verifier supplied), so a client that
	// does not already hold it cannot validate. Omitting the ROOT is normal and
	// never flagged; nor is a private chain this hub cannot judge.
	FlagIncompleteChain = "INCOMPLETE_CHAIN"
	// FlagUntrustedRoot: the served chain is internally consistent and ends in
	// a self-signed root that is in neither the system nor the hub pool.
	FlagUntrustedRoot = "UNTRUSTED_ROOT"
)

// FlagHostnameMismatch is set by the scanner on a served leaf that does not
// vouch for the name it was reached at.
const FlagHostnameMismatch = "HOSTNAME_MISMATCH"

const (
	incompleteChainScore  = 15
	untrustedRootScore    = 20
	hostnameMismatchScore = 20
)

// EndpointFlags are the facts about a certificate AS SERVED BY ONE ENDPOINT:
// the same certificate can match the name on one endpoint and not on another,
// or be served with its intermediate in one place and without it elsewhere.
// They live on the certificate<->endpoint link, never on the shared
// certificate row. Everything else (EXPIRED, WEAK_KEY, SELF_SIGNED, ...) is a
// property of the certificate itself.
var EndpointFlags = []string{FlagHostnameMismatch, FlagIncompleteChain, FlagUntrustedRoot}

// IsEndpointFlag reports whether f is endpoint-scoped.
func IsEndpointFlag(f string) bool { return slices.Contains(EndpointFlags, f) }

// SplitEndpointFlags separates a scanner flag list into certificate-intrinsic
// and endpoint-scoped flags, and returns the endpoint flags' summed score.
func SplitEndpointFlags(flags []string) (certFlags, endpointFlags []string, endpointScore int) {
	for _, f := range flags {
		if !IsEndpointFlag(f) {
			certFlags = append(certFlags, f)
			continue
		}
		if !slices.Contains(endpointFlags, f) {
			endpointFlags = append(endpointFlags, f)
			endpointScore += EndpointFlagScore(f)
		}
	}
	return certFlags, endpointFlags, endpointScore
}

// EndpointFlagScore is the risk weight of an endpoint-scoped flag.
func EndpointFlagScore(flag string) int {
	if flag == FlagHostnameMismatch {
		return hostnameMismatchScore
	}
	return ChainFlagScore(flag)
}

// TrustClasses is the closed vocabulary, in display order.
var TrustClasses = []string{TrustManaged, TrustPublic, TrustPrivateOther, TrustSelfSigned, TrustUnknown}

// IsTrustClass reports whether s is a member of the closed vocabulary.
func IsTrustClass(s string) bool { return slices.Contains(TrustClasses, s) }

// TrustAnchors are the pools a served chain is judged against. System is the
// platform root pool (injected, so tests never depend on the machine's roots);
// Hub holds every CA certificate this hub owns, roots and intermediates alike.
// A nil System means "no public roots": it is never forwarded as a nil
// x509.VerifyOptions.Roots, which Go would read as "use the system roots".
type TrustAnchors struct {
	System *x509.CertPool
	Hub    []*x509.Certificate
}

// ChainVerdict is the classification of one served leaf.
type ChainVerdict struct {
	Class string
	// CompleteKnown is false when completeness cannot be judged: a private
	// chain whose issuer this hub does not hold, so there is no way to tell a
	// withheld intermediate from a normal root-less chain. The stored value is
	// then NULL, never false. When known, Complete means no CA certificate the
	// chain needs was withheld by the server (the ROOT may always be omitted).
	Complete      bool
	CompleteKnown bool
	// Trusted: the chain verifies to the system roots or a hub CA.
	Trusted bool
	Flags   []string
}

// ClassifyChain judges served (leaf first, then whatever intermediates and
// root the server sent, in order) against anchors at time now.
//
// Rules, in order:
//
//  1. Verify(leaf, intermediates = rest of served chain) against the hub CAs
//     -> managed; else against the system roots -> public. KeyUsages is
//     ExtKeyUsageAny: this answers who issued the cert, not whether to accept
//     it for a particular TLS use, so an mTLS-only or code-signing leaf is
//     still attributed to its issuer.
//  2. Otherwise a self-signed leaf -> self_signed.
//  3. Otherwise a failure that is not "issuer unknown" -> unknown.
//  4. Otherwise -> private_other, flagged UNTRUSTED_ROOT when the served chain
//     ends in a self-signed root.
//
// Expiry never changes the answer: a verification that fails only because a
// certificate is outside its validity window is retried at the ends of the
// leaf's own validity window, so an expired cert is still
// recognised as ours or public (EXPIRED is flagged separately by the risk
// scorer). Any other failure is final.
//
// Completeness (INCOMPLETE_CHAIN) is flagged only on proof. Omitting the root
// is normal, so a chain is judged by whether the path that verified needed a
// CA certificate the server did not send: a leaf served alone under a hub
// intermediate verifies only because the hub holds that intermediate; a
// platform verifier may likewise build a public path through intermediates
// the server withheld. A private chain that does not verify (an issuing CA we
// do not hold) is left unknown rather than guessed at, with one exception: a
// lone leaf whose AuthorityKeyId names a hub intermediate is provably missing
// that intermediate.
//
// There is no AIA fetching: a public leaf served alone under an intermediate
// no pool holds cannot be traced, so it reads private_other with unknown
// completeness.
func ClassifyChain(served []*x509.Certificate, anchors TrustAnchors, now time.Time) ChainVerdict {
	if len(served) == 0 || served[0] == nil {
		return ChainVerdict{Class: TrustUnknown}
	}
	leaf := served[0]
	inter := x509.NewCertPool()
	for _, c := range served[1:] {
		if c != nil {
			inter.AddCert(c)
		}
	}

	hubAll := x509.NewCertPool()
	for _, c := range anchors.Hub {
		if c != nil {
			hubAll.AddCert(c)
		}
	}
	system := anchors.System
	if system == nil {
		system = x509.NewCertPool()
	}

	hubChains, hubErr := verifyAt(leaf, inter, hubAll, now)
	sysChains, sysErr := verifyAt(leaf, inter, system, now)
	v := ChainVerdict{}
	var verified [][]*x509.Certificate

	switch {
	case hubErr == nil:
		v.Class, v.Trusted, verified = TrustManaged, true, hubChains
	case sysErr == nil:
		v.Class, v.Trusted, verified = TrustPublic, true, sysChains
	case isSelfSigned(leaf):
		v.Class = TrustSelfSigned
	case reachedButRejected(hubErr) || reachedButRejected(sysErr):
		v.Class = TrustUnknown
	default:
		v.Class = TrustPrivateOther
	}

	if v.Class == TrustSelfSigned {
		v.Complete, v.CompleteKnown = true, true
		return v
	}
	if v.Class == TrustUnknown {
		return v
	}

	top := linkedTop(served)
	switch {
	case len(verified) > 0:
		v.Complete, v.CompleteKnown = servedCoversSomePath(verified, served), true
	case isSelfSigned(top):
		v.Complete, v.CompleteKnown = true, true
		if len(served) > 1 {
			v.Flags = append(v.Flags, FlagUntrustedRoot)
		}
	case top == leaf && leafNamesHubIntermediate(leaf, anchors.Hub):
		v.CompleteKnown = true // Complete stays false: the named intermediate was not sent
	}
	if v.CompleteKnown && !v.Complete {
		v.Flags = append(v.Flags, FlagIncompleteChain)
	}
	return v
}

// servedCoversSomePath reports whether at least one verified path consists
// only of certificates the server sent, apart from a self-signed root at its
// end (which servers normally omit). A path ending in a non-self-signed
// anchor (a hub intermediate) must have that anchor served too.
func servedCoversSomePath(paths [][]*x509.Certificate, served []*x509.Certificate) bool {
	sent := func(c *x509.Certificate) bool {
		return slices.ContainsFunc(served, func(s *x509.Certificate) bool {
			return s != nil && bytes.Equal(s.Raw, c.Raw)
		})
	}
	return slices.ContainsFunc(paths, func(path []*x509.Certificate) bool {
		for i, c := range path {
			if i == len(path)-1 && isSelfSigned(c) {
				continue
			}
			if !sent(c) {
				return false
			}
		}
		return true
	})
}

// leafNamesHubIntermediate reports whether leaf's AuthorityKeyId matches the
// SubjectKeyId of a non-self-signed CA this hub owns.
func leafNamesHubIntermediate(leaf *x509.Certificate, hub []*x509.Certificate) bool {
	if len(leaf.AuthorityKeyId) == 0 {
		return false
	}
	return slices.ContainsFunc(hub, func(c *x509.Certificate) bool {
		return c != nil && !isSelfSigned(c) && bytes.Equal(c.SubjectKeyId, leaf.AuthorityKeyId)
	})
}

// ChainFlagScore is the risk weight of a chain flag (0 for others).
func ChainFlagScore(flag string) int {
	switch flag {
	case FlagIncompleteChain:
		return incompleteChainScore
	case FlagUntrustedRoot:
		return untrustedRootScore
	}
	return 0
}

// verifyAt runs a real x509 Verify and returns the verified paths. roots is
// never nil here.
func verifyAt(c *x509.Certificate, inter, roots *x509.CertPool, now time.Time) ([][]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	chains, err := c.Verify(opts)
	if err == nil {
		return chains, nil
	}
	var invalid x509.CertificateInvalidError
	if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
		return nil, err
	}
	// Validity-window failure only: re-judge at the two ends of the leaf's own
	// window, since an issuer may have rotated mid-way. Any other failure is
	// final, so this cannot rescue a bad signature or a wrong issuer.
	for _, t := range []time.Time{c.NotAfter.Add(-time.Second), c.NotBefore.Add(time.Second)} {
		opts.CurrentTime = t
		retried, retryErr := c.Verify(opts)
		if retryErr == nil {
			return retried, nil
		}
		err = retryErr
	}
	return nil, err
}

// reachedButRejected reports a verification failure that is not the plain
// "no path to an anchor" outcome: the chain reached something but a policy
// check (name constraints, key usage, still-invalid after the expiry retry)
// refused it, so we cannot call it someone else's private CA either.
func reachedButRejected(err error) bool {
	if err == nil {
		return false
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return false
	}
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid)
}

// linkedTop returns the last certificate of the prefix of served in which each
// cert is signed by the next; an unrelated extra cert ends the walk.
func linkedTop(served []*x509.Certificate) *x509.Certificate {
	top := served[0]
	for i := 0; i+1 < len(served); i++ {
		if served[i+1] == nil || served[i].CheckSignatureFrom(served[i+1]) != nil {
			break
		}
		top = served[i+1]
	}
	return top
}

// ApplyTrust classifies a TLS-served endpoint in place: it sets the verdict
// and chain flags on the leaf and marks every other served cert as a chain CA.
// Endpoints whose certs did not come from a presented chain (SSH, mesh,
// store enumeration) are left untouched.
func ApplyTrust(ep *DiscoveredEndpoint, anchors TrustAnchors, now time.Time) {
	if len(ep.Certs) == 0 || !ep.Certs[0].Served {
		return
	}
	parsed := make([]*x509.Certificate, len(ep.Certs))
	for i := range ep.Certs {
		if c, err := x509.ParseCertificate(ep.Certs[i].Raw); err == nil {
			parsed[i] = c
		}
		if i > 0 {
			ep.Certs[i].ChainCA = true
		}
	}
	leaf := &ep.Certs[0]
	var v ChainVerdict
	if parsed[0] == nil {
		v = ChainVerdict{Class: TrustUnknown}
	} else {
		v = ClassifyChain(parsed, anchors, now)
	}
	leaf.TrustClass, leaf.ChainComplete, leaf.ChainCompleteKnown, leaf.ChainTrusted = v.Class, v.Complete, v.CompleteKnown, v.Trusted
	for _, f := range v.Flags {
		if !slices.Contains(leaf.RiskFlags, f) {
			leaf.RiskFlags = append(leaf.RiskFlags, f)
			leaf.RiskScore = min(leaf.RiskScore+ChainFlagScore(f), 100)
		}
	}
}
