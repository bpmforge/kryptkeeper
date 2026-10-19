// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"kryptkeeper/internal/logging"
)

// W7-01: the real SPIFFE Workload API over gRPC, complementing the REST
// join-token mint (which stays for bootstrap enrolment).
//
// The Workload API cannot carry a bearer token: FetchX509SVID is
// server-streaming, X509SVIDRequest has no fields, and the contract
// attests the caller out-of-band from the Unix-socket peer credentials
// (SO_PEERCRED / LOCAL_PEERCRED). That kernel-attested UID — unforgeable
// by the peer — is the selector this server maps to a registered SPIFFE
// ID. proposer≠approver still holds: registering a UID→ID binding is the
// human approval; a workload can only ever receive the identity an
// operator bound to its UID, never one it names itself.

// SelectorRegistry maps a kernel-attested peer UID to the SPIFFE ID an
// operator registered for it. In-memory and constructor-injected;
// bindings are bootstrap policy, safe to reload on restart.
type SelectorRegistry struct {
	mu    sync.RWMutex
	byUID map[uint32]string
}

func NewSelectorRegistry() *SelectorRegistry {
	return &SelectorRegistry{byUID: map[uint32]string{}}
}

// RegisterUID binds a peer UID to a SPIFFE ID (the operator's approval).
func (r *SelectorRegistry) RegisterUID(uid uint32, spiffeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byUID[uid] = spiffeID
}

// SelectorBinding is one UID→SPIFFE ID binding, for the operator API.
type SelectorBinding struct {
	UID      uint32 `json:"uid"`
	SPIFFEID string `json:"spiffe_id"`
}

// List returns every binding. It carries no secret material — a binding
// is a UID and an identity name, both non-sensitive by design.
func (r *SelectorRegistry) List() []SelectorBinding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SelectorBinding, 0, len(r.byUID))
	for uid, id := range r.byUID {
		out = append(out, SelectorBinding{UID: uid, SPIFFEID: id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

func (r *SelectorRegistry) lookup(uid uint32) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byUID[uid]
	return id, ok
}

// --- peer-credential transport credentials ---------------------------------

type peerCredAuthInfo struct {
	uid uint32
	credentials.CommonAuthInfo
}

func (peerCredAuthInfo) AuthType() string { return "peercred" }

// peerCredTransportCreds attests every accepted connection by its
// Unix-socket peer credentials during the gRPC handshake, so the handler
// reads an authenticated UID off the context and never trusts the wire.
type peerCredTransportCreds struct{}

func (peerCredTransportCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, errors.New("peercred: Workload API requires a Unix-domain socket")
	}
	uid, err := peerCredUID(uc)
	if err != nil {
		return nil, nil, err
	}
	return conn, peerCredAuthInfo{uid: uid, CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}}, nil
}

func (peerCredTransportCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, peerCredAuthInfo{}, nil // client side unused; the server attests
}

func (peerCredTransportCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}
func (c peerCredTransportCreds) Clone() credentials.TransportCredentials { return c }
func (peerCredTransportCreds) OverrideServerName(string) error           { return nil }

// peerCredUID pulls the attested UID off a live Unix connection. The
// platform peerCredFromFD does the syscall (build-tag guarded).
func peerCredUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var opErr error
	if err := raw.Control(func(fd uintptr) { uid, opErr = peerCredFromFD(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, opErr
}

// --- the Workload API server -----------------------------------------------

type workloadAPIServer struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	registry  *SelectorRegistry
	signingCA string
	audit     AuditProvider
}

func (s *workloadAPIServer) recordAttest(ctx context.Context, spiffeID string, outcome AuditOutcome) {
	if s.audit == nil {
		return
	}
	if err := s.audit.AppendEntry(ctx, AuditEntry{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Action:       "spiffe.workload_attest",
		ActorType:    "workload",
		ActorID:      spiffeID,
		ResourceType: "svid",
		ResourceID:   spiffeID,
		Outcome:      outcome,
	}); err != nil {
		logging.Warnf("audit append failed action=spiffe.workload_attest outcome=%s: %v", outcome, err)
	}
}

// FetchX509SVID attests the caller by peer credential and streams the
// SVID for the identity bound to its UID. The SPIFFE spec requires the
// client to send the "workload.spiffe.io: true" security header; a call
// without it is refused (defence against confused-deputy calls from
// browsers/agents that cannot set gRPC metadata).
func (s *workloadAPIServer) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	ctx := stream.Context()
	if md, ok := metadata.FromIncomingContext(ctx); !ok || len(md.Get("workload.spiffe.io")) == 0 {
		return status.Error(codes.InvalidArgument, "missing security header workload.spiffe.io")
	}

	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Internal, "no peer on context")
	}
	ai, ok := p.AuthInfo.(peerCredAuthInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "peer credentials unavailable")
	}

	spiffeID, ok := s.registry.lookup(ai.uid)
	if !ok {
		s.recordAttest(ctx, "", AuditOutcomeDenied)
		return status.Errorf(codes.PermissionDenied, "uid %d is not a registered workload", ai.uid)
	}

	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		return status.Errorf(codes.Internal, "registered SPIFFE ID %q is not a URI", spiffeID)
	}
	// send mints a fresh SVID and pushes it down the stream.
	send := func() error {
		svidPEM, keyPEM, bundlePEM, err := mintWorkloadSVID(spiffeURI, s.signingCA)
		if err != nil {
			s.recordAttest(ctx, spiffeID, AuditOutcomeFailure)
			return status.Errorf(codes.Internal, "mint SVID: %v", err)
		}
		if err := stream.Send(&workload.X509SVIDResponse{Svids: []*workload.X509SVID{{
			SpiffeId:    spiffeID,
			X509Svid:    firstPEMDER(svidPEM),
			X509SvidKey: firstPEMDER(keyPEM),
			Bundle:      allPEMDER(bundlePEM),
		}}}); err != nil {
			return err
		}
		s.recordAttest(ctx, spiffeID, AuditOutcomeSuccess)
		return nil
	}
	if err := send(); err != nil {
		return err
	}

	// Rotation (W29-01): hold the stream open and push a fresh SVID at half
	// the configured lifetime, so a streaming client (go-spiffe X509Source)
	// always holds a certificate with at least 50% of its life left, with
	// no restart. The loop ends when the workload disconnects.
	for {
		timer := time.NewTimer(spiffeSVIDTTL() / 2)
		select {
		case <-ctx.Done():
			timer.Stop()
			return status.FromContextError(ctx.Err()).Err()
		case <-timer.C:
			if err := send(); err != nil {
				return err
			}
		}
	}
}

// firstPEMDER returns the DER bytes of the first PEM block.
func firstPEMDER(p []byte) []byte {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil
	}
	return block.Bytes
}

// allPEMDER concatenates the DER bytes of every PEM block (a trust
// bundle may carry a chain).
func allPEMDER(p []byte) []byte {
	var out []byte
	for {
		block, rest := pem.Decode(p)
		if block == nil {
			break
		}
		out = append(out, block.Bytes...)
		p = rest
	}
	return out
}

// startWorkloadAPIServer serves the Workload API on a Unix socket with
// peer-credential attestation. The socket path defaults to the SPIFFE
// endpoint-socket convention.
func startWorkloadAPIServer(socketPath string, registry *SelectorRegistry, audit AuditProvider) (*grpc.Server, error) {
	if socketPath == "" {
		return nil, errors.New("workload API requires a socket path")
	}
	_ = os.Remove(socketPath) // a stale socket from a crash would block Listen
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	srv := grpc.NewServer(grpc.Creds(peerCredTransportCreds{}))
	workload.RegisterSpiffeWorkloadAPIServer(srv, &workloadAPIServer{
		registry:  registry,
		signingCA: strings.TrimSpace(os.Getenv("SPIFFE_SIGNING_CA_ID")),
		audit:     audit,
	})
	go func() { _ = srv.Serve(ln) }()
	return srv, nil
}
