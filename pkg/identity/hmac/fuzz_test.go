// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package hmac

import (
	"strings"
	"testing"
)

// FuzzParseAuth pounds the Authorization-header parser with arbitrary
// strings. The contract under fuzz is narrow but important:
//
//   - parseAuth must never panic on attacker-controlled input.
//   - When err == nil, both keyID and sig must be non-empty (the
//     factory relies on this to look up keys).
//   - keyID and sig must each be a substring of the input — the
//     parser is purely dissecting, never inventing content. This
//     catches a regression where, e.g., a buffer reuse leaks bytes
//     from a previous call.
//
// The HMAC verification step itself is tested elsewhere; here we
// only protect the input-handling perimeter.
func FuzzParseAuth(f *testing.F) {
	// Seed corpus: the formats parseAuth is documented to accept,
	// plus a few classic fuzzer prods (CRLF injection, empty,
	// embedded NULs, very long, unicode).
	seeds := []string{
		`keyId="abc", signature="dGVzdA=="`,
		`abc:dGVzdA==`,
		`KeyID = "x" , Signature = "y"`,
		``,
		` `,
		`,`,
		`=`,
		`:`,
		`a:`,
		`:b`,
		`keyId=`,
		`signature=`,
		`keyId="a",,signature="b"`,
		"keyId=\"a\"\r\n,signature=\"b\"",
		"\x00\x00\x00",
		strings.Repeat("a", 8192),
		strings.Repeat(`keyId="a",signature="b",`, 64),
		`keyId="\\\"weird\"",signature="="`,
		"keyId=\"日本語\",signature=\"中文\"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		// Bound input — saves fuzzer time and matches the real
		// http.Header limit (typically 8 KiB per header value).
		if len(s) > 64*1024 {
			t.Skip()
		}

		keyID, sig, err := func(s string) (string, string, error) {
			p, err := parseAuth(s)
			return p.keyID, p.signature, err
		}(s)
		if err != nil {
			// On error, the named returns must be empty — callers
			// rely on being able to log err without leaking a
			// half-parsed credential into the wrong place.
			if keyID != "" || sig != "" {
				t.Fatalf("parseAuth(%q) returned err=%v but keyID=%q sig=%q", s, err, keyID, sig)
			}
			return
		}
		if keyID == "" || sig == "" {
			t.Fatalf("parseAuth(%q): err=nil but keyID=%q sig=%q", s, keyID, sig)
		}
		// Conservative substring check: every byte of keyID/sig must
		// have come from the input. We compare on the trimmed input
		// because parseAuth trims before splitting.
		if !strings.Contains(s, keyID) {
			t.Fatalf("parseAuth(%q): keyID %q not a substring of input", s, keyID)
		}
		if !strings.Contains(s, sig) {
			t.Fatalf("parseAuth(%q): sig %q not a substring of input", s, sig)
		}
	})
}
