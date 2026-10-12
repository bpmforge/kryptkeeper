// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"crypto/rc4" //nolint:gosec // see ntlm_session.go
	"encoding/binary"
)

// serverSeal is the server-to-client half of MS-NLMP sealing, test-only: the
// production client never seals in that direction. It uses a fresh cipher
// derived from the same exported key so callers can seal several messages.
type testServerSealer struct {
	sign []byte
	seal *rc4.Cipher
	seq  uint32
}

func newTestServerSealer(c *ntlmClient, exported []byte) *testServerSealer {
	probe := &ntlmClient{}
	probe.deriveKeys(exported)
	return &testServerSealer{sign: probe.signS, seal: probe.sealS}
}

func (s *testServerSealer) seal1(msg []byte) (sig, sealed []byte) {
	sealed = make([]byte, len(msg))
	s.seal.XORKeyStream(sealed, msg)
	sum := ntlmChecksum(s.sign, s.seq, msg)
	s.seal.XORKeyStream(sum, sum)
	sig = binary.LittleEndian.AppendUint32(nil, 1)
	sig = append(sig, sum...)
	sig = binary.LittleEndian.AppendUint32(sig, s.seq)
	s.seq++
	return sig, sealed
}
