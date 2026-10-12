// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime"
	"net/smtp"
	"os"
	"strconv"
	"strings"
)

// smtpSendFunc matches net/smtp.SendMail so it can be faked in tests.
type smtpSendFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

// EvidenceMailer sends evidence packs as email with a PDF attachment. SMTP is
// configured via env; when unconfigured, Enabled() is false and sends fail
// clearly rather than silently (matching the SIEM opt-in pattern).
type EvidenceMailer struct {
	host string
	port int
	from string
	user string
	pass string
	send smtpSendFunc
}

// NewEvidenceMailerFromEnv reads SMTP_HOST/PORT/FROM/USERNAME/PASSWORD.
func NewEvidenceMailerFromEnv() *EvidenceMailer {
	port := 587
	if raw := strings.TrimSpace(os.Getenv("SMTP_PORT")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			port = n
		}
	}
	return &EvidenceMailer{
		host: strings.TrimSpace(os.Getenv("SMTP_HOST")),
		port: port,
		from: strings.TrimSpace(os.Getenv("SMTP_FROM")),
		user: strings.TrimSpace(os.Getenv("SMTP_USERNAME")),
		pass: strings.TrimSpace(os.Getenv("SMTP_PASSWORD")),
		send: smtp.SendMail,
	}
}

// Enabled reports whether SMTP is configured enough to send.
func (m *EvidenceMailer) Enabled() bool {
	return m.host != "" && m.from != ""
}

// Send emails the PDF attachment to recipients with the given subject/body.
func (m *EvidenceMailer) Send(recipients []string, subject, body string, attachment []byte, filename string) error {
	if !m.Enabled() {
		return fmt.Errorf("smtp not configured (set SMTP_HOST and SMTP_FROM)")
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients")
	}
	msg := buildEvidenceMIME(m.from, recipients, subject, body, attachment, filename)
	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	var auth smtp.Auth
	if m.user != "" {
		auth = smtp.PlainAuth("", m.user, m.pass, m.host)
	}
	return m.send(addr, auth, m.from, recipients, msg)
}

// buildEvidenceMIME assembles a multipart/mixed message with a text body and a
// base64-encoded PDF attachment.
func buildEvidenceMIME(from string, to []string, subject, body string, attachment []byte, filename string) []byte {
	boundary := "kk-evidence-boundary-0xKRYPT"
	var b bytes.Buffer

	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", boundary)

	// Text body part.
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(body)
	b.WriteString("\r\n\r\n")

	// PDF attachment part.
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: application/pdf\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	fmt.Fprintf(&b, "Content-Disposition: attachment; filename=%q\r\n\r\n", filename)
	encoded := base64.StdEncoding.EncodeToString(attachment)
	// Wrap base64 at 76 columns per RFC 2045.
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		b.WriteString(encoded[i:end])
		b.WriteString("\r\n")
	}

	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}
