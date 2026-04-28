package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// rawSign HMAC-SHA256s msg under the test secret and returns base64.
func rawSign(secret, msg []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(msg)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// newID builds an HMAC identifier with the canonical defaults.
func newID(t *testing.T) module.Identifier {
	t.Helper()
	id, err := factory("hmac", map[string]any{
		"keys": map[string]any{
			"abc": map[string]any{
				"secret":  base64.StdEncoding.EncodeToString([]byte("supersecret")),
				"subject": "service-a",
				"roles":   []any{"machine"},
			},
		},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return id
}

// signReq builds the canonical string the verifier expects, signs it
// under `secret`, and returns the Authorization header value.
func signReq(secret []byte, keyID string, r *module.Request, signedHeaders []string) string {
	canon := canonical(r, signedHeaders)
	sig := rawSign(secret, canon)
	return `HMAC-SHA256 keyId="` + keyID +
		`", signedHeaders="` + strings.Join(signedHeaders, ";") +
		`", signature="` + sig + `"`
}

func TestHMAC_Roundtrip(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	body := []byte(`{"x":1}`)
	r := &module.Request{
		Method: "POST",
		Host:   "api.example.com",
		Path:   "/things?id=42&amount=10",
		Body:   body,
		Headers: map[string][]string{
			"Date": {now},
			"Host": {"api.example.com"},
		},
	}
	r.Headers["Authorization"] = []string{
		signReq([]byte("supersecret"), "abc", r, []string{"date", "host"}),
	}

	got, err := id.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "service-a" {
		t.Errorf("subject = %q", got.Subject)
	}
	if got.Claims["keyId"] != "abc" {
		t.Errorf("keyId claim = %v", got.Claims["keyId"])
	}
}

// TestHMAC_QueryTamper is the regression test for HIGH-02 query
// tampering: a signature minted for ?amount=10 must fail to verify
// when replayed against ?amount=1000.
func TestHMAC_QueryTamper(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	signed := []string{"date", "host"}

	// Signer mints for amount=10.
	signerReq := &module.Request{
		Method: "GET", Host: "api.example.com", Path: "/transfer?id=1&amount=10",
		Headers: map[string][]string{"Date": {now}, "Host": {"api.example.com"}},
	}
	auth := signReq([]byte("supersecret"), "abc", signerReq, signed)

	// Attacker replays the same signature against amount=1000.
	attackerReq := &module.Request{
		Method: "GET", Host: "api.example.com", Path: "/transfer?id=1&amount=1000",
		Headers: map[string][]string{
			"Date":          {now},
			"Host":          {"api.example.com"},
			"Authorization": {auth},
		},
	}
	_, err := id.Identify(context.Background(), attackerReq)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (query tamper must fail)", err)
	}
}

// TestHMAC_HostTamper covers the second half of HIGH-02: a signature
// minted for one Host must fail to verify against another.
func TestHMAC_HostTamper(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	signed := []string{"date", "host"}

	signerReq := &module.Request{
		Method: "POST", Host: "internal.svc", Path: "/admin",
		Headers: map[string][]string{"Date": {now}, "Host": {"internal.svc"}},
	}
	auth := signReq([]byte("supersecret"), "abc", signerReq, signed)

	attackerReq := &module.Request{
		Method: "POST", Host: "public.svc", Path: "/admin",
		Headers: map[string][]string{
			"Date":          {now},
			"Host":          {"public.svc"},
			"Authorization": {auth},
		},
	}
	_, err := id.Identify(context.Background(), attackerReq)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (host tamper must fail)", err)
	}
}

// TestHMAC_BodyTamper: changing a single body byte must invalidate.
func TestHMAC_BodyTamper(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	signed := []string{"date", "host"}

	signerReq := &module.Request{
		Method: "POST", Host: "api.example.com", Path: "/things",
		Body:    []byte(`{"amount":10}`),
		Headers: map[string][]string{"Date": {now}, "Host": {"api.example.com"}},
	}
	auth := signReq([]byte("supersecret"), "abc", signerReq, signed)

	attackerReq := &module.Request{
		Method: "POST", Host: "api.example.com", Path: "/things",
		Body: []byte(`{"amount":1000}`),
		Headers: map[string][]string{
			"Date":          {now},
			"Host":          {"api.example.com"},
			"Authorization": {auth},
		},
	}
	_, err := id.Identify(context.Background(), attackerReq)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (body tamper must fail)", err)
	}
}

// TestHMAC_RequiredSignedHeaders rejects an Authorization header that
// omits host (or date) from signedHeaders, even if signature math is
// internally consistent. This blocks the "signer voluntarily drops
// host from the bound set" downgrade attack.
func TestHMAC_RequiredSignedHeaders(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)

	// Sign without binding `host`.
	signed := []string{"date"}
	r := &module.Request{
		Method: "GET", Host: "api.example.com", Path: "/x",
		Headers: map[string][]string{"Date": {now}, "Host": {"api.example.com"}},
	}
	r.Headers["Authorization"] = []string{signReq([]byte("supersecret"), "abc", r, signed)}

	_, err := id.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (missing required signedHeader)", err)
	}
}

func TestHMAC_ClockSkew(t *testing.T) {
	t.Parallel()
	id := newID(t)
	stale := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	signed := []string{"date", "host"}
	r := &module.Request{
		Method: "GET", Host: "h", Path: "/x",
		Headers: map[string][]string{"Date": {stale}, "Host": {"h"}},
	}
	r.Headers["Authorization"] = []string{signReq([]byte("supersecret"), "abc", r, signed)}
	_, err := id.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (skew)", err)
	}
}

func TestHMAC_UnknownKeyID(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	r := &module.Request{
		Method: "GET", Host: "h", Path: "/x",
		Headers: map[string][]string{"Date": {now}, "Host": {"h"}},
	}
	auth := `HMAC-SHA256 keyId="ghost", signedHeaders="date;host", signature="` +
		base64.StdEncoding.EncodeToString([]byte("x")) + `"`
	r.Headers["Authorization"] = []string{auth}
	_, err := id.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestHMAC_NoHeaderNoMatch(t *testing.T) {
	t.Parallel()
	id := newID(t)
	_, err := id.Identify(context.Background(), &module.Request{Method: "GET", Path: "/x"})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

// TestHMAC_MissingSignedHeadersInAuth: the canonical Authorization
// MUST include the signedHeaders parameter; the compact form is no
// longer accepted.
func TestHMAC_MissingSignedHeadersInAuth(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	r := &module.Request{
		Method: "GET", Host: "h", Path: "/x",
		Headers: map[string][]string{"Date": {now}, "Host": {"h"}},
	}
	auth := `HMAC-SHA256 keyId="abc", signature="` +
		base64.StdEncoding.EncodeToString([]byte("x")) + `"`
	r.Headers["Authorization"] = []string{auth}
	_, err := id.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// --- canonical unit checks ---------------------------------------------

func TestCanonical_QuerySortStable(t *testing.T) {
	t.Parallel()
	r := &module.Request{
		Method: "GET", Host: "h", Path: "/p?b=2&a=1&c=3",
		Headers: map[string][]string{"Date": {"x"}, "Host": {"h"}},
	}
	got := string(canonical(r, []string{"date", "host"}))
	// canonical query line is the 5th line of the canonical string.
	lines := strings.Split(got, "\n")
	if lines[4] != "a=1&b=2&c=3" {
		t.Errorf("query line = %q, want sorted a/b/c", lines[4])
	}
}

func TestCanonical_BodyHashHex(t *testing.T) {
	t.Parallel()
	want := sha256.Sum256([]byte("hello"))
	r := &module.Request{
		Method: "POST", Host: "h", Path: "/p",
		Body:    []byte("hello"),
		Headers: map[string][]string{"Date": {"x"}, "Host": {"h"}},
	}
	got := string(canonical(r, []string{"date", "host"}))
	last := got[strings.LastIndexByte(got, '\n')+1:]
	if last != hex.EncodeToString(want[:]) {
		t.Errorf("body hash line = %q, want %s", last, hex.EncodeToString(want[:]))
	}
}
