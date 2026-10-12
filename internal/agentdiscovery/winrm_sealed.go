// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

// W18-09: WinRM over plain HTTP. AllowUnencrypted=false (the Windows default)
// rejects an unencrypted SOAP body even after authentication succeeds, so over
// http the body must be sealed with the NTLM session key and framed as
// multipart/encrypted (MS-WSMV 2.2.9.1.1). This is the fallback for hosts that
// cannot present an HTTPS listener; https remains the supported path.
//
// There is no unsealed fallback by construction: over http this file is the
// only code path, it never calls SetBasicAuth, and a 2xx answer that is not
// sealed is an error rather than a response.

const (
	sealedBoundary = "--Encrypted Boundary"
	sealedProtocol = "application/HTTP-SPNEGO-session-encrypted"
	sealedType     = `multipart/encrypted;protocol="` + sealedProtocol + `";boundary="Encrypted Boundary"`
	octetMarker    = "\tContent-Type: application/octet-stream\r\n"
	maxSealedReply = 8 << 20
)

// sealedSession is the connection-bound NTLM context. NTLM authenticates a TCP
// connection, so the context is only valid while that connection lives; any
// transport error discards it and the next call re-authenticates.
type sealedSession struct {
	mu sync.Mutex
	nc *ntlmClient
}

// splitWinRMUser accepts DOMAIN\user, user@realm (UPN, sent whole with an empty
// domain) and a bare local user.
func splitWinRMUser(u string) (domain, user string) {
	if i := strings.IndexByte(u, '\\'); i >= 0 {
		return u[:i], u[i+1:]
	}
	return "", u
}

func (s *WSManShell) soapSealed(ctx context.Context, action string, plain []byte) ([]byte, error) {
	s.sealed.mu.Lock()
	defer s.sealed.mu.Unlock()

	if s.sealed.nc == nil {
		if err := s.ntlmHandshake(ctx); err != nil {
			return nil, err
		}
	}
	nc := s.sealed.nc
	sig, sealed := nc.seal(plain)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.EndpointURL, bytes.NewReader(buildSealedBody(len(plain), sig, sealed)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", sealedType)
	resp, err := s.client.Do(req)
	if err != nil {
		s.sealed.nc = nil
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxSealedReply)) // a short read surfaces as a parse error below

	if resp.StatusCode == http.StatusUnauthorized {
		s.sealed.nc = nil
		return nil, &WinRMError{Status: resp.StatusCode, Action: action, Sealed: true}
	}
	if !isSealedContentType(resp.Header.Get("Content-Type")) {
		s.sealed.nc = nil
		if resp.StatusCode >= 400 {
			// An unsealed error carries no authenticated detail; report the status only.
			return nil, &WinRMError{Status: resp.StatusCode, Action: action, Sealed: true}
		}
		return nil, fmt.Errorf("winrm: listener answered a sealed %s with an unsealed HTTP %d; refusing the response", action, resp.StatusCode)
	}
	body, err := openSealedBody(nc, raw)
	if err != nil {
		s.sealed.nc = nil
		return nil, fmt.Errorf("winrm %s: %w", action, err)
	}
	if resp.StatusCode >= 400 {
		detail, code := faultDetail(body)
		return nil, &WinRMError{Status: resp.StatusCode, FaultCode: code, Action: action, Detail: detail, Sealed: true}
	}
	return body, nil
}

func isSealedContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "multipart/encrypted") || strings.HasPrefix(ct, "multipart/x-multi-encrypted")
}

func buildSealedBody(origLen int, sig, sealed []byte) []byte {
	var b bytes.Buffer
	b.WriteString(sealedBoundary + "\r\n\tContent-Type: " + sealedProtocol + "\r\n" +
		"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + strconv.Itoa(origLen) + "\r\n" +
		sealedBoundary + "\r\n" + octetMarker)
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(sig)))
	b.Write(l[:])
	b.Write(sig)
	b.Write(sealed)
	b.WriteString(sealedBoundary + "--\r\n")
	return b.Bytes()
}

// openSealedBody unseals every encrypted part of a response, in order. The
// OriginalContent length is cross-checked when present.
func openSealedBody(nc *ntlmClient, raw []byte) ([]byte, error) {
	parts := bytes.Split(raw, []byte(sealedBoundary))
	var out []byte
	wantLen, haveLen := 0, false
	chunks := 0
	for _, p := range parts[1:] {
		if i := bytes.Index(p, []byte("OriginalContent:")); i >= 0 {
			if j := bytes.Index(p[i:], []byte("Length=")); j >= 0 {
				rest := p[i+j+len("Length="):]
				if e := bytes.IndexAny(rest, "\r\n;"); e >= 0 {
					if n, err := strconv.Atoi(string(rest[:e])); err == nil {
						wantLen += n
						haveLen = true
					}
				}
			}
			continue
		}
		i := bytes.Index(p, []byte(octetMarker))
		if i < 0 {
			continue // epilogue ("--\r\n")
		}
		payload := p[i+len(octetMarker):]
		if len(payload) < 4 {
			return nil, errors.New("sealed part too short")
		}
		sigLen := int(binary.LittleEndian.Uint32(payload))
		if sigLen != 16 || len(payload) < 4+sigLen {
			return nil, errors.New("sealed part has a malformed signature length")
		}
		plain, err := nc.unseal(payload[4:4+sigLen], payload[4+sigLen:])
		if err != nil {
			return nil, err
		}
		out = append(out, plain...)
		chunks++
	}
	if chunks == 0 {
		return nil, errors.New("sealed response contained no encrypted part")
	}
	if haveLen && wantLen != len(out) {
		return nil, fmt.Errorf("sealed response length %d does not match OriginalContent %d", len(out), wantLen)
	}
	return out, nil
}

// ntlmHandshake runs the two-leg NTLM exchange on the shell's connection with
// empty-bodied POSTs (the exchange authenticates the connection, not a message).
func (s *WSManShell) ntlmHandshake(ctx context.Context) error {
	domain, user := splitWinRMUser(s.cfg.Username)
	ws, _ := os.Hostname()
	if ws == "" {
		ws = "KRYPTKEEPER"
	}
	nc := newNTLMClient(domain, user, s.cfg.Password, strings.ToUpper(ws), rand.Reader)

	post := func(token []byte) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.EndpointURL, http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
		req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // drain so the connection (and its NTLM binding) is reused
		resp.Body.Close()
		return resp, nil
	}

	resp, err := post(nc.negotiateMessage())
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("winrm: listener answered the NTLM negotiate with HTTP %d, not a 401 challenge", resp.StatusCode)
	}
	challenge, err := ntlmChallengeFrom(resp)
	if err != nil {
		return err
	}
	authMsg, err := nc.authenticateMessage(challenge)
	if err != nil {
		return err
	}
	resp, err = post(authMsg)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return &WinRMError{Status: resp.StatusCode, Action: "authenticate", Sealed: true}
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("winrm: NTLM authenticate answered HTTP %d", resp.StatusCode)
	}
	s.sealed.nc = nc
	return nil
}

func ntlmChallengeFrom(resp *http.Response) ([]byte, error) {
	offered := false
	for _, h := range resp.Header.Values("WWW-Authenticate") {
		scheme, tok, _ := strings.Cut(strings.TrimSpace(h), " ")
		if !strings.EqualFold(scheme, "Negotiate") && !strings.EqualFold(scheme, "NTLM") {
			continue
		}
		offered = true
		if tok = strings.TrimSpace(tok); tok == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(tok)
		if err != nil {
			return nil, fmt.Errorf("winrm: undecodable NTLM challenge: %w", err)
		}
		if !bytes.HasPrefix(b, []byte("NTLMSSP\x00")) {
			return nil, errors.New("winrm: listener answered with a SPNEGO-wrapped challenge, which this client does not support; use an HTTPS endpoint")
		}
		return b, nil
	}
	if !offered {
		return nil, errors.New("winrm: listener over http does not offer Negotiate/NTLM; Basic is never sent over http, so use an HTTPS endpoint")
	}
	return nil, errors.New("winrm: listener offered Negotiate without a challenge")
}
