// rdpstub answers the RDP X.224 connection request with a TLS-selected
// confirmation and then terminates TLS with the given certificate. It is the
// W24-03 fallback when real xrdp does not come up inside the container.
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
)

func main() {
	crt := flag.String("cert", "/etc/kk-certs/rdp.crt", "certificate")
	key := flag.String("key", "/etc/kk-certs/rdp.key", "private key")
	addr := flag.String("listen", ":3389", "listen address")
	flag.Parse()
	cert, err := tls.LoadX509KeyPair(*crt, *key)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	confirm := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer c.Close()
			req := make([]byte, 19)
			if _, err := io.ReadFull(c, req); err != nil {
				return
			}
			if _, err := c.Write(confirm); err != nil {
				return
			}
			tc := tls.Server(c, cfg)
			if tc.Handshake() == nil {
				_, _ = io.Copy(io.Discard, tc)
			}
		}()
	}
}
