package mtls

import (
	"strings"
	"testing"
)

// FuzzParseXFCC pounds the Envoy x-forwarded-client-cert parser with
// arbitrary strings. The contract:
//
//   - Never panics on attacker-controlled input (Envoy is a
//     trusted hop, but the header value is *always* attacker-influenced
//     because the upstream client picks the cert).
//   - Returns either (cert, nil) or (nil, err); never (cert, err).
//   - Returns nil, nil on a header that simply has no Cert= entry —
//     this lets the identifier surface ErrNoMatch upstream.
//
// The certificate-validity / SPIFFE-extraction path is exercised by
// the unit tests; here we only protect the parser perimeter against
// crafted XFCC values (escaped quotes, unbalanced PEM, oversized
// URL-encoding, embedded NULs, etc.).
func FuzzParseXFCC(f *testing.F) {
	seeds := []string{
		``,
		`By=spiffe://x;Hash=abc`,
		`By=spiffe://x;Cert=""`,
		`By=spiffe://x;Cert="not-a-pem"`,
		`Cert="-----BEGIN CERTIFICATE-----\nbad-base64\n-----END CERTIFICATE-----"`,
		`a;b;c`,
		`;;;`,
		`Cert=`,
		`Cert=,Cert=`,
		"Cert=\"\r\n\"",
		"\x00\x00",
		strings.Repeat("Cert=\"x\";", 64),
		strings.Repeat("a", 16384),
		`Cert="日本語"`,
		`Cert="%ZZ"`, // bad URL-escape
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 64*1024 {
			t.Skip()
		}

		cert, err := parseXFCC(s)
		if err != nil && cert != nil {
			t.Fatalf("parseXFCC(%q): both cert and err non-nil", s)
		}
	})
}
