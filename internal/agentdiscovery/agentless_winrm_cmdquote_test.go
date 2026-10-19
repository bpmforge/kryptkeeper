// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"strings"
	"testing"
)

func TestCmdQuoteQuotesMetacharacters(t *testing.T) {
	cases := map[string]string{
		"plain":            "plain",
		"0.0.0.0:443&calc": `"0.0.0.0:443&calc"`,
		"a|b":              `"a|b"`,
		"has space":        `"has space"`,
		`say "hi"`:         `"say \"hi\""`,
		"":                 `""`,
		// A padded -EncodedCommand value must pass through bare.
		"JABzAD0AJwBNAHkAJwA=": "JABzAD0AJwBNAHkAJwA=",
		"ipport=0.0.0.0:443":   "ipport=0.0.0.0:443",
	}
	for in, want := range cases {
		if got := cmdQuote(in); got != want {
			t.Errorf("cmdQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArgTextEscapeKeepsQuotesLiteral(t *testing.T) {
	got := argTextEscape(cmdQuote(`C:\stage dir`) + " " + cmdQuote("(OI)(CI)F") + " a&b<c>")
	want := `"C:\stage dir" "(OI)(CI)F" a&amp;b&lt;c&gt;`
	if got != want {
		t.Fatalf("argTextEscape = %q, want %q", got, want)
	}
	if strings.Contains(got, "&#34;") {
		t.Fatalf("quote was entity-encoded: %q", got)
	}
}

// cmd.exe cannot carry a '"' inside a quoted argument (cmdQuote's \" closes
// the quote for cmd), so such an argument is refused rather than sent.
func TestWinRMArgumentsXMLRefusesQuotesAndLineBreaks(t *testing.T) {
	for _, a := range []string{`a" & calc & "`, "a\nb", "a\rb", "a\x00b"} {
		if _, err := winrmArgumentsXML([]string{"ok", a}); err == nil || !strings.Contains(err.Error(), "argument 2") {
			t.Fatalf("winrmArgumentsXML(%q) = %v, want refusal of argument 2", a, err)
		}
	}
	got, err := winrmArgumentsXML([]string{"ipport=0.0.0.0:443", `C:\stage dir`})
	if err != nil {
		t.Fatal(err)
	}
	if want := `<rsp:Arguments>ipport=0.0.0.0:443</rsp:Arguments><rsp:Arguments>"C:\stage dir"</rsp:Arguments>`; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
