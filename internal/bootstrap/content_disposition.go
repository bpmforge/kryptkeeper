// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "mime"

// attachmentDisposition builds a Content-Disposition value for a download
// whose name derives from user-controlled data (a certificate CN, a key id).
// The name is reduced to [A-Za-z0-9._-] first, so a CN containing quotes,
// CR/LF or path separators cannot break out of the header or suggest a path,
// and mime.FormatMediaType then does the RFC 6266 quoting.
func attachmentDisposition(filename string) string {
	name := sanitizeFilenameComponent(filename)
	if name == "" {
		name = "download"
	}
	if v := mime.FormatMediaType("attachment", map[string]string{"filename": name}); v != "" {
		return v
	}
	return "attachment"
}
