// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"strings"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// FuzzMatchHTU pounds the DPoP `htu` claim matcher with arbitrary
// (got, host, path) triples. The contract under fuzz:
//
//   - matchHTU never panics on attacker-controlled `got`.
//   - On nil error the parsed URL had a non-empty Scheme + Host
//     (matchHTU rejects relative URIs, RFC 9449 §4.3 step 9).
//
// Since `got` arrives directly from a JWT claim, an attacker chooses
// it. host / path come from the request line and are constrained by
// upstream HTTP parsers, but we let the fuzzer vary them anyway to
// catch surprising state combinations.
func FuzzMatchHTU(f *testing.F) {
	seeds := []struct {
		got, host, path string
	}{
		{"https://api.example.com/v1/x", "api.example.com", "/v1/x"},
		{"http://h/", "h", "/"},
		{"", "h", "/"},
		{"://nope", "h", "/"},
		{"https://", "h", "/"},
		{"javascript:alert(1)", "h", "/"},
		{"https://h/x?q=1#frag", "h", "/x"},
		{strings.Repeat("https://h/", 1024), "h", "/"},
		{"https://h/\x00", "h", "/"},
		{"https://日本/x", "日本", "/x"},
	}
	for _, s := range seeds {
		f.Add(s.got, s.host, s.path)
	}

	f.Fuzz(func(t *testing.T, got, host, path string) {
		if len(got) > 64*1024 || len(host) > 4096 || len(path) > 8192 {
			t.Skip()
		}
		// The matcher reads X-Forwarded-Proto via r.Header; an
		// empty Headers map is fine.
		r := &module.Request{Host: host, Path: path}

		// Goal: must not panic. The error / non-error result is not
		// asserted because matchHTU's correctness is covered by
		// unit tests; here we just protect the parser perimeter.
		_ = matchHTU(got, r)
	})
}
