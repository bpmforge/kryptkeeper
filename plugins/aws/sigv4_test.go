// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// The AWS Signature V4 test-suite "get-vanilla" case.
func TestSigV4GetVanilla(t *testing.T) {
	req := abi.HTTPRequest{Method: "GET", URL: "https://example.amazonaws.com/"}
	c := creds{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	if err := signV4(&req, "service", "us-east-1", c, time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if req.Headers["Authorization"] != want {
		t.Fatalf("Authorization\n got %s\nwant %s", req.Headers["Authorization"], want)
	}
	if req.Headers["X-Amz-Date"] != "20150830T123600Z" {
		t.Errorf("X-Amz-Date %q", req.Headers["X-Amz-Date"])
	}
}

func TestSigV4SignedHeaders(t *testing.T) {
	req := abi.HTTPRequest{Method: "POST", URL: "https://acm.us-east-1.amazonaws.com/", Body: []byte(`{}`),
		Headers: map[string]string{"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "CertificateManager.GetCertificate", "If-Match": "x"}}
	c := creds{AccessKeyID: "AKID", SecretAccessKey: "secret", SessionToken: "tok"}
	if err := signV4(&req, "acm", "us-east-1", c, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.Headers["Authorization"], "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,") {
		t.Errorf("Authorization %s", req.Headers["Authorization"])
	}
	if req.Headers["X-Amz-Security-Token"] != "tok" {
		t.Error("session token header missing")
	}
}
