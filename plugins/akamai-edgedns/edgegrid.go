// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
)

// EdgeGrid request signing (scheme EG1-HMAC-SHA256), implemented here
// because the plugin runs in a sandbox with no SDK and no filesystem
// (.edgerc is the operator's credential, passed in as fields instead).
//
// Algorithm, from Akamai's "Authenticate with EdgeGrid" and checked against
// the vendor's reference implementations (akamai/AkamaiOPEN-edgegrid-python
// edgegrid.py and its test vectors; akamai/AkamaiOPEN-edgegrid-golang
// signer.go):
//
//	auth      = "EG1-HMAC-SHA256 client_token=..;access_token=..;timestamp=..;nonce=..;"
//	key       = base64(HMAC-SHA256(key=client_secret, msg=timestamp))
//	toSign    = METHOD \t scheme \t host \t path?query \t canonical headers \t content hash \t auth
//	signature = base64(HMAC-SHA256(key=key, msg=toSign))
//	header    = auth + "signature=" + signature
//
// The timestamp is UTC, "yyyyMMddTHH:mm:ss+0000". Headers are signed only
// when named in a signed-header list; this client names none, so the
// canonical headers field is empty. The content hash is
// base64(SHA-256(body)) for POST requests only (the first max-body bytes,
// 131072 by default) and empty for every other method, including PUT.
// https://techdocs.akamai.com/developer/docs/authenticate-with-edgegrid
const (
	edgeGridScheme  = "EG1-HMAC-SHA256"
	edgeGridMaxBody = 131072
	edgeGridTime    = "20060102T15:04:05-0700"
)

type edgeGrid struct {
	clientToken, clientSecret, accessToken string
}

func hmacB64(key, msg string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func (e edgeGrid) signingKey(timestamp string) string { return hmacB64(e.clientSecret, timestamp) }

func contentHash(method string, body []byte) string {
	if method != "POST" || len(body) == 0 {
		return ""
	}
	if len(body) > edgeGridMaxBody {
		body = body[:edgeGridMaxBody]
	}
	sum := sha256.Sum256(body)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// authorization builds the signed Authorization header for a request whose
// target is https://host + pathQuery.
func (e edgeGrid) authorization(method, host, pathQuery string, body []byte, timestamp, nonce string) string {
	unsigned := edgeGridScheme + " client_token=" + e.clientToken + ";access_token=" + e.accessToken + ";timestamp=" + timestamp + ";nonce=" + nonce + ";"
	toSign := strings.Join([]string{method, "https", host, pathQuery, "", contentHash(method, body), unsigned}, "\t")
	return unsigned + "signature=" + hmacB64(e.signingKey(timestamp), toSign)
}

// sign stamps now and a fresh random nonce. The nonce must be unpredictable
// enough that a captured request cannot be replayed under a new signature
// window; 16 random bytes from the host's entropy source do that.
func (e edgeGrid) sign(method, host, pathQuery string, body []byte, now time.Time) (string, error) {
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return "", err
	}
	return e.authorization(method, host, pathQuery, body, now.UTC().Format(edgeGridTime), hex.EncodeToString(n[:])), nil
}
