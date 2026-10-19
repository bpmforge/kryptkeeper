// svidclient is the W26-19 live-UAT workload: it fetches an X509-SVID from the
// hub's SPIFFE Workload API (Unix socket) and runs mutual TLS between two
// workloads, authorizing the peer by SPIFFE ID and verifying its chain against
// the bundle the Workload API returned.
//
//	svidclient serve     --listen :8443 --allow spiffe://td/ns/uat/sa/client
//	svidclient call      --addr svid-server:8443 --allow spiffe://td/ns/uat/sa/server
//	svidclient denycheck            (raw FetchX509SVID, prints the gRPC status code)
//
// Output lines the harness greps: PEER <id>, CHAIN_OK, BUNDLE_ROOT_SHA256 <hex>,
// LEAF_PEM_BEGIN/END (call only), RPC_CODE <code> (denycheck).
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const defaultSocket = "unix:///run/kk-spiffe/api.sock"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: svidclient serve|call|denycheck [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "Workload API address")
	listen := fs.String("listen", ":8443", "serve: listen address")
	addr := fs.String("addr", "", "call: server address")
	allow := fs.String("allow", "", "SPIFFE ID the peer must present")
	wait := fs.Duration("wait", 90*time.Second, "how long to wait for the SVID / the peer")
	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "serve":
		os.Exit(serve(*socket, *listen, *allow, *wait))
	case "call":
		os.Exit(call(*socket, *addr, *allow, *wait))
	case "denycheck":
		os.Exit(denycheck(*socket, *wait))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}

func openSource(socket string, wait time.Duration) (*workloadapi.X509Source, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
}

func announce(src *workloadapi.X509Source) (spiffeid.ID, error) {
	svid, err := src.GetX509SVID()
	if err != nil {
		return spiffeid.ID{}, err
	}
	fmt.Printf("SVID %s\n", svid.ID)
	b, err := src.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return svid.ID, err
	}
	for _, c := range b.X509Authorities() {
		sum := sha256.Sum256(c.Raw)
		fmt.Printf("BUNDLE_ROOT_SHA256 %s\n", hex.EncodeToString(sum[:]))
	}
	return svid.ID, nil
}

func serve(socket, listen, allow string, wait time.Duration) int {
	src, err := openSource(socket, wait)
	if err != nil {
		fmt.Printf("SVID_FAIL %v\n", err)
		return 1
	}
	defer src.Close()
	me, err := announce(src)
	if err != nil {
		fmt.Printf("SVID_FAIL %v\n", err)
		return 1
	}
	peer, err := spiffeid.FromString(allow)
	if err != nil {
		fmt.Printf("BAD_ALLOW %v\n", err)
		return 2
	}
	ln, err := tls.Listen("tcp", listen, tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeID(peer)))
	if err != nil {
		fmt.Printf("LISTEN_FAIL %v\n", err)
		return 1
	}
	fmt.Printf("LISTENING %s\n", listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Printf("ACCEPT_FAIL %v\n", err)
			return 1
		}
		go func(c net.Conn) {
			defer c.Close()
			tc := c.(*tls.Conn)
			_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
			if err := tc.Handshake(); err != nil {
				fmt.Printf("HANDSHAKE_FAIL %v\n", err)
				return
			}
			printPeer(tc.ConnectionState())
			_, _ = fmt.Fprintf(c, "hello from %s\n", me)
		}(c)
	}
}

func printPeer(cs tls.ConnectionState) {
	if len(cs.PeerCertificates) == 0 || len(cs.PeerCertificates[0].URIs) == 0 {
		fmt.Println("PEER none")
		return
	}
	// go-spiffe's VerifyPeerCertificate already verified the chain against the
	// Workload-API bundle and the SPIFFE ID allow-list before the handshake
	// completed, so reaching here means the chain is good.
	fmt.Printf("PEER %s\n", cs.PeerCertificates[0].URIs[0])
	fmt.Println("CHAIN_OK")
}

func call(socket, addr, allow string, wait time.Duration) int {
	src, err := openSource(socket, wait)
	if err != nil {
		fmt.Printf("SVID_FAIL %v\n", err)
		return 1
	}
	defer src.Close()
	if _, err := announce(src); err != nil {
		fmt.Printf("SVID_FAIL %v\n", err)
		return 1
	}
	svid, _ := src.GetX509SVID()
	fmt.Println("LEAF_PEM_BEGIN")
	_ = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: svid.Certificates[0].Raw})
	fmt.Println("LEAF_PEM_END")
	peer, err := spiffeid.FromString(allow)
	if err != nil {
		fmt.Printf("BAD_ALLOW %v\n", err)
		return 2
	}
	cfg := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeID(peer))
	deadline := time.Now().Add(wait)
	for {
		d := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
		if err == nil {
			defer conn.Close()
			printPeer(conn.ConnectionState())
			body, _ := io.ReadAll(io.LimitReader(conn, 1024))
			fmt.Printf("REPLY %s", body)
			return 0
		}
		if time.Now().After(deadline) {
			fmt.Printf("CALL_FAIL %v\n", err)
			return 1
		}
		time.Sleep(2 * time.Second)
	}
}

// denycheck speaks the raw Workload API (no go-spiffe retry loop) so the gRPC
// status of a refused attestation is visible.
func denycheck(socket string, wait time.Duration) int {
	conn, err := grpc.NewClient(socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("DIAL_FAIL %v\n", err)
		return 1
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")
	stream, err := workload.NewSpiffeWorkloadAPIClient(conn).FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err == nil {
		var resp *workload.X509SVIDResponse
		resp, err = stream.Recv()
		if err == nil {
			fmt.Printf("RPC_OK svids=%d\n", len(resp.GetSvids()))
			return 0
		}
	}
	st, _ := status.FromError(err)
	fmt.Printf("RPC_CODE %s\nRPC_MESSAGE %s\n", st.Code(), st.Message())
	return 0
}
