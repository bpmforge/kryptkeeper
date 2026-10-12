// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rc4" //nolint:gosec // see ntlm_session.go
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// sealedWinRM is an http WinRM listener with AllowUnencrypted=false semantics:
// connection-bound NTLM, then multipart/encrypted only. It verifies the client
// the way a Windows host would (NTProofStr, MIC, signatures, sequence numbers),
// so the fixture is a second implementation of the server half, not a replay.
type sealedWinRM struct {
	t        *testing.T
	srv      *httptest.Server
	password string

	mu             sync.Mutex
	conns          map[string]*sealedConn
	sawBasic       bool
	sawPlainSOAP   bool
	handshakes     int
	authedConns    map[string]bool
	offerNegotiate bool
	challenge      []byte // type-2 to send; tests may weaken it
	plainReply     bool   // answer sealed requests with unsealed XML
	tamperReply    bool   // flip a ciphertext bit in sealed replies
	stdout         string
}

type sealedConn struct {
	negotiate []byte
	srvSign   []byte
	srvSeal   *rc4.Cipher
	cliSign   []byte
	cliSeal   *rc4.Cipher
	seqIn     uint32
	seqOut    uint32
	authed    bool
}

func newSealedWinRM(t *testing.T) *sealedWinRM {
	f := &sealedWinRM{t: t, password: "Password", conns: map[string]*sealedConn{}, offerNegotiate: true,
		challenge: mustHex(t, vecChallenge), stdout: "S-1-16-12288 High Mandatory Level\n"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *sealedWinRM) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "basic ") {
		f.sawBasic = true
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	c := f.conns[r.RemoteAddr]
	if c == nil {
		c = &sealedConn{}
		f.conns[r.RemoteAddr] = c
	}
	switch {
	case strings.HasPrefix(auth, "Negotiate ") && !f.offerNegotiate:
		w.Header().Set("WWW-Authenticate", `Basic realm="WSMAN"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	case strings.HasPrefix(auth, "Negotiate "):
		tok, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Negotiate "))
		switch binary.LittleEndian.Uint32(tok[8:]) {
		case 1:
			f.handshakes++
			c.negotiate = tok
			w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(f.challenge))
			w.WriteHeader(http.StatusUnauthorized)
		case 3:
			if err := f.verifyAuthenticate(c, tok); err != nil {
				f.t.Logf("server rejected authenticate: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			c.authed = true
			w.WriteHeader(http.StatusOK)
		}
		return
	case !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/encrypted"):
		if len(body) > 0 {
			f.sawPlainSOAP = true
		}
		if f.offerNegotiate {
			w.Header().Set("WWW-Authenticate", "Negotiate")
		}
		w.Header().Add("WWW-Authenticate", `Basic realm="WSMAN"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	case !c.authed:
		w.WriteHeader(http.StatusUnauthorized) // sealed body on a connection that never authenticated
		return
	}
	soap, err := f.open(c, body)
	if err != nil {
		f.t.Errorf("server could not open client message: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reply := f.dispatch(string(soap))
	if f.plainReply {
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = io.WriteString(w, reply)
		return
	}
	sig, sealed := f.sealReply(c, []byte(reply))
	if f.tamperReply {
		sealed[0] ^= 1
	}
	w.Header().Set("Content-Type", sealedType)
	_, _ = w.Write(buildSealedBody(len(reply), sig, sealed))
}

func (f *sealedWinRM) verifyAuthenticate(c *sealedConn, a []byte) error {
	user, _ := field(a, 36)
	dom, _ := field(a, 28)
	nt, err := field(a, 20)
	if err != nil || len(nt) < 16+28 {
		return errors.New("bad NT response")
	}
	encKey, _ := field(a, 52)
	respKey := ntowfV2(f.password, "User", "Domain")
	_ = user
	_ = dom
	serverChallenge := f.challenge[24:32]
	proof := hmacMD5(respKey, serverChallenge, nt[16:])
	if !hmac.Equal(proof, nt[:16]) {
		return errors.New("NTProofStr mismatch (wrong password)")
	}
	rc, _ := rc4.NewCipher(hmacMD5(respKey, proof)) //nolint:gosec
	exported := make([]byte, 16)
	rc.XORKeyStream(exported, encKey)
	// MIC over negotiate||challenge||authenticate-with-zero-MIC.
	zeroed := append([]byte(nil), a...)
	copy(zeroed[72:88], make([]byte, 16))
	if !hmac.Equal(hmacMD5(exported, c.negotiate, f.challenge, zeroed), a[72:88]) {
		return errors.New("MIC mismatch")
	}
	probe := &ntlmClient{}
	probe.deriveKeys(exported)
	c.cliSign, c.cliSeal, c.srvSign, c.srvSeal = probe.signC, probe.sealC, probe.signS, probe.sealS
	return nil
}

func (f *sealedWinRM) open(c *sealedConn, raw []byte) ([]byte, error) {
	var out []byte
	for _, p := range bytes.Split(raw, []byte(sealedBoundary))[1:] {
		i := bytes.Index(p, []byte(octetMarker))
		if i < 0 {
			continue
		}
		pl := p[i+len(octetMarker):]
		sig, ct := pl[4:20], pl[20:]
		plain := make([]byte, len(ct))
		c.cliSeal.XORKeyStream(plain, ct)
		want := ntlmChecksum(c.cliSign, c.seqIn, plain)
		c.cliSeal.XORKeyStream(want, want)
		if !bytes.Equal(want, sig[4:12]) || binary.LittleEndian.Uint32(sig[12:]) != c.seqIn {
			return nil, errors.New("client signature/sequence invalid")
		}
		c.seqIn++
		out = append(out, plain...)
	}
	return out, nil
}

func (f *sealedWinRM) sealReply(c *sealedConn, msg []byte) (sig, sealed []byte) {
	sealed = make([]byte, len(msg))
	c.srvSeal.XORKeyStream(sealed, msg)
	sum := ntlmChecksum(c.srvSign, c.seqOut, msg)
	c.srvSeal.XORKeyStream(sum, sum)
	sig = binary.LittleEndian.AppendUint32(nil, 1)
	sig = append(sig, sum...)
	sig = binary.LittleEndian.AppendUint32(sig, c.seqOut)
	c.seqOut++
	return sig, sealed
}

func (f *sealedWinRM) dispatch(body string) string {
	switch {
	case strings.Contains(body, "transfer/Create"):
		return `<s:Envelope xmlns:s="x"><s:Body><ResourceCreated><ReferenceParameters><SelectorSet><Selector Name="ShellId">SHELL-1</Selector></SelectorSet></ReferenceParameters></ResourceCreated></s:Body></s:Envelope>`
	case strings.Contains(body, "shell/Command"):
		return `<s:Envelope xmlns:s="x"><s:Body><CommandResponse><CommandId>CMD-1</CommandId></CommandResponse></s:Body></s:Envelope>`
	case strings.Contains(body, "shell/Receive"):
		return `<s:Envelope xmlns:s="x"><s:Body><ReceiveResponse><Stream Name="stdout">` + base64.StdEncoding.EncodeToString([]byte(f.stdout)) +
			`</Stream><CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><ExitCode>0</ExitCode></CommandState></ReceiveResponse></s:Body></s:Envelope>`
	}
	return `<s:Envelope xmlns:s="x"><s:Body/></s:Envelope>`
}

func (f *sealedWinRM) shell(user, pass string) *WSManShell {
	return NewWSManShell(WinRMConfig{EndpointURL: f.srv.URL, Username: user, Password: pass}, nil)
}

func TestSealedWinRMRunsACommandOverHTTP(t *testing.T) {
	f := newSealedWinRM(t)
	sh := f.shell(`Domain\User`, "Password")
	for i := 0; i < 2; i++ { // second run reuses the authenticated connection
		out, err := sh.Run(context.Background(), "whoami", "/groups")
		if err != nil || !strings.Contains(out, "S-1-16-12288") {
			t.Fatalf("run %d: %q, %v", i, out, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handshakes != 1 {
		t.Errorf("handshakes = %d, want 1 (connection-bound session reused)", f.handshakes)
	}
	if f.sawBasic || f.sawPlainSOAP {
		t.Errorf("client leaked: basic=%v plaintext SOAP=%v", f.sawBasic, f.sawPlainSOAP)
	}
}

func TestSealedWinRMWrongPasswordIsAnUnauthenticatedError(t *testing.T) {
	f := newSealedWinRM(t)
	_, err := f.shell(`Domain\User`, "nope").Run(context.Background(), "whoami")
	var we *WinRMError
	if !errors.As(err, &we) || we.Status != http.StatusUnauthorized || !we.Sealed {
		t.Fatalf("want sealed 401 WinRMError, got %v", err)
	}
	if f.sawBasic {
		t.Fatal("Basic sent after NTLM failure")
	}
}

func TestSealedWinRMNeverFallsBackToBasicOverHTTP(t *testing.T) {
	f := newSealedWinRM(t)
	f.offerNegotiate = false // only Basic offered
	_, err := f.shell(`Domain\User`, "Password").Run(context.Background(), "whoami")
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("want an error pointing at HTTPS, got %v", err)
	}
	if f.sawBasic || f.sawPlainSOAP {
		t.Fatalf("fell back: basic=%v plaintext=%v", f.sawBasic, f.sawPlainSOAP)
	}
}

func TestSealedWinRMRefusesAnUnsealedAnswer(t *testing.T) {
	f := newSealedWinRM(t)
	f.plainReply = true
	_, err := f.shell(`Domain\User`, "Password").Run(context.Background(), "whoami")
	if err == nil || !strings.Contains(err.Error(), "unsealed") {
		t.Fatalf("an unsealed 2xx must be refused, got %v", err)
	}
}

func TestSealedWinRMRefusesTamperedReply(t *testing.T) {
	f := newSealedWinRM(t)
	f.tamperReply = true
	if _, err := f.shell(`Domain\User`, "Password").Run(context.Background(), "whoami"); err == nil {
		t.Fatal("tampered sealed reply accepted")
	}
}

func TestSealedWinRMRefusesAServerThatOffersNoSealing(t *testing.T) {
	f := newSealedWinRM(t)
	weak := append([]byte(nil), f.challenge...)
	weak[23] &^= 0x20 // clear NEGOTIATE_128
	f.challenge = weak
	_, err := f.shell(`Domain\User`, "Password").Run(context.Background(), "whoami")
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("weak challenge must be refused, got %v", err)
	}
}

func TestPreflightWorksOverSealedHTTP(t *testing.T) {
	f := newSealedWinRM(t)
	got := PreflightWinRM(context.Background(), WinRMConfig{EndpointURL: f.srv.URL, Username: `Domain\User`, Password: "Password"}, nil)
	if got.Level != PreflightInstall {
		t.Fatalf("level = %q (%s)", got.Level, got.Detail)
	}
}

func TestBasicStillTravelsOverHTTPSOnly(t *testing.T) {
	// The https path is covered by the TLS fixtures above; this pins that an
	// unknown scheme is an error rather than a silent Basic attempt.
	sh := NewWSManShell(WinRMConfig{EndpointURL: "ftp://h/wsman", Username: "u", Password: "p"}, nil)
	if _, err := sh.Run(context.Background(), "whoami"); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("got %v", err)
	}
}
