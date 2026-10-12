// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"mime"
	"strings"
	"testing"
)

func TestAttachmentDispositionNeutralisesHostileNames(t *testing.T) {
	for _, in := range []string{
		"a\"; filename*=UTF-8''evil.exe.pem",
		"web\r\nSet-Cookie: x=1.pem",
		"../../etc/passwd.pem",
		"*.example.com.pem",
		"",
		"тест.pem",
	} {
		got := attachmentDisposition(in)
		if strings.ContainsAny(got, "\r\n") || strings.Contains(got, "filename*") || strings.Contains(got, "/") {
			t.Errorf("%q -> unsafe header %q", in, got)
		}
		typ, params, err := mime.ParseMediaType(got)
		if err != nil || typ != "attachment" || params["filename"] == "" {
			t.Errorf("%q -> %q does not round-trip: %v %v", in, got, typ, err)
		}
	}
	if got := attachmentDisposition("host.example.com.pem"); got != `attachment; filename=host.example.com.pem` {
		t.Errorf("plain name changed: %q", got)
	}
}
