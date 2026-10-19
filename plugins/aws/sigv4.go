// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// AWS Signature Version 4 with only the standard library, because the
// sandbox has no AWS SDK. Per the AWS signing documentation the signed
// headers are host, x-amz-date, and, when present, content-type,
// x-amz-security-token and x-amz-target.

type creds struct{ AccessKeyID, SecretAccessKey, SessionToken string }

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// uriEncode escapes every byte except A-Z a-z 0-9 - . _ ~ (space is %20).
func uriEncode(s string) string {
	const hexUpper = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexUpper[c>>4])
		b.WriteByte(hexUpper[c&15])
	}
	return b.String()
}

// signV4 adds X-Amz-Date, X-Amz-Security-Token (when a session token is set)
// and Authorization to req.Headers. The signature covers the exact req.Body.
func signV4(req *abi.HTTPRequest, service, region string, c creds, t time.Time) error {
	u, err := url.Parse(req.URL)
	if err != nil || u.Host == "" {
		return errors.New("sigv4: bad request URL")
	}
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	amzDate := t.UTC().Format("20060102T150405Z")
	req.Headers["X-Amz-Date"] = amzDate
	if c.SessionToken != "" {
		req.Headers["X-Amz-Security-Token"] = c.SessionToken
	}

	hdr := map[string]string{"host": u.Host}
	for k, v := range req.Headers {
		switch lk := strings.ToLower(k); lk {
		case "content-type", "x-amz-date", "x-amz-security-token", "x-amz-target":
			hdr[lk] = strings.Join(strings.Fields(v), " ")
		}
	}
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHdr strings.Builder
	for _, k := range names {
		canonHdr.WriteString(k + ":" + hdr[k] + "\n")
	}
	signed := strings.Join(names, ";")

	// Non-S3 services double-encode each path segment.
	path := u.Path
	if path == "" {
		path = "/"
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = uriEncode(uriEncode(s))
	}
	var pairs []string
	for k, vs := range u.Query() {
		for _, v := range vs {
			pairs = append(pairs, uriEncode(k)+"="+uriEncode(v))
		}
	}
	sort.Strings(pairs)

	canonical := strings.Join([]string{
		req.Method, strings.Join(segs, "/"), strings.Join(pairs, "&"), canonHdr.String(), signed, sha256Hex(req.Body),
	}, "\n")
	scope := amzDate[:8] + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))

	key := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), amzDate[:8])
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	req.Headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + c.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signed + ", Signature=" + hex.EncodeToString(hmacSHA256(key, toSign))
	return nil
}
