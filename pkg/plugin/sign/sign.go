// Package sign implements the F-PLUGIN-2 plugin-response signature
// scheme: a plugin can attach an HMAC-SHA256 signature to its
// IdentifyResponse, AuthorizePluginResponse, or MutateResponse, and
// the host verifies it before trusting the result.
//
// Why this exists. The v1.0 trust model was "the plugin process is
// part of the operator TCB; identity is asserted by socket-path
// ownership" (see DESIGN.md §"Plugin model" / F-PLUGIN-2 in the v1.0
// review). That's correct for a single-tenant pod where the operator
// controls the entire image, but is **defense-in-depth weak** when:
//
//   - The plugin runs over a Unix domain socket on a host where
//     other tenants can write to the socket directory (a path-race
//     attacker can swap the socket between dial and call).
//   - The plugin runs over plaintext loopback TCP and another
//     process on the same host can win an IP-stack race.
//   - The operator wants to ship a signed plugin binary and have the
//     gateway refuse to honour anything that isn't signed by the
//     accompanying key — independent of the transport choice.
//
// Wire shape. The signature, key id, and algorithm travel as gRPC
// trailing metadata so the response proto messages don't need a
// security-only field (and so old plugins remain wire-compatible).
// The signed payload is a deterministic, language-independent,
// length-prefixed canonical encoding of the response — see
// CanonicalIdentifyResponse, CanonicalAuthorizeResponse, and
// CanonicalMutateResponse below.
//
// Crypto choice. v1.1 ships HMAC-SHA256 only, which covers every
// "operator wants integrity over a private channel" use case while
// keeping key distribution trivial. X.509 / asymmetric signatures are
// a follow-up; the trailer scheme is forward-compatible because the
// `lwauth-alg` trailer is part of the protected payload's prefix.
package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
)

// Trailer keys used by the signature scheme. Plugins that adopt
// signing MUST set these as gRPC response trailers; the host reads
// them from `grpc.Trailer(...)` on the call site.
//
// Names are lowercase because gRPC normalizes header names to
// lowercase and rejects "-bin" suffixes for non-bytes values.
const (
	TrailerKeyID = "lwauth-kid"
	TrailerAlg   = "lwauth-alg"
	// TrailerSig is the hex-encoded HMAC. We deliberately do NOT use
	// the "-bin" suffix (which would make it a binary trailer) so
	// non-Go plugins that can't easily set binary trailers can still
	// participate by hex-encoding the digest.
	TrailerSig = "lwauth-sig"
)

// AlgHMACSHA256 is the only algorithm v1.1 understands. Future
// algorithms will be added as additional constants; the host's
// signing config gates which ones are accepted.
const AlgHMACSHA256 = "hmac-sha256"

// version prefix on every canonical payload. Bumping this is how we
// introduce a wire-incompatible canonicalization change without
// risking a quiet downgrade attack — a v2 host won't accept a v1
// signature and vice versa.
const canonicalVersion = "lwauth-plugin-sig-v1"

// Sign returns the hex-encoded HMAC-SHA256 of payload under secret.
// The caller is responsible for passing the bytes returned by one of
// the Canonical*Response functions in this package; mixing payload
// formats across the host/plugin boundary is the easiest way to make
// signatures verify-but-mean-nothing.
func Sign(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify constant-time-compares a hex-encoded signature against a
// freshly-computed HMAC of payload under secret. It returns nil on
// match and a non-nil error otherwise. Callers must treat any error
// as "fail closed" — never as "ok except".
func Verify(secret, payload []byte, sigHex string) error {
	want, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("plugin/sign: signature is not hex: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	got := mac.Sum(nil)
	if !hmac.Equal(want, got) {
		return errors.New("plugin/sign: signature mismatch")
	}
	return nil
}

// CanonicalIdentifyResponse returns the deterministic byte stream
// signed/verified for an IdentifyResponse. Field order, type tags,
// and length prefixes are part of the wire contract — never reorder.
//
// Layout (all length-prefixed, ints big-endian uint32):
//
//	[len][version="lwauth-plugin-sig-v1"]
//	[len][type="IdentifyResponse"]
//	[len][alg]                                // e.g. "hmac-sha256"
//	[len][key_id]
//	[1 byte][no_match flag]
//	[len][identity.subject]                   // empty if identity is nil
//	[len][identity.source]
//	[uint32][N claims]
//	  for each claim sorted by key:
//	    [len][k][len][v]
//	[len][error]
func CanonicalIdentifyResponse(alg, keyID string, resp *pluginv1.IdentifyResponse) []byte {
	w := newCanon()
	w.writeString(canonicalVersion)
	w.writeString("IdentifyResponse")
	w.writeString(alg)
	w.writeString(keyID)
	w.writeBool(resp.GetNoMatch())
	writeIdentity(w, resp.GetIdentity())
	w.writeString(resp.GetError())
	return w.buf
}

// CanonicalAuthorizeResponse — same scheme as CanonicalIdentifyResponse
// for AuthorizePluginResponse. Header maps are sorted-by-key so the
// host and plugin produce identical bytes regardless of map-iteration
// order.
func CanonicalAuthorizeResponse(alg, keyID string, resp *pluginv1.AuthorizePluginResponse) []byte {
	w := newCanon()
	w.writeString(canonicalVersion)
	w.writeString("AuthorizePluginResponse")
	w.writeString(alg)
	w.writeString(keyID)
	w.writeBool(resp.GetAllow())
	w.writeUint32(uint32(resp.GetHttpStatus())) //nolint:gosec // status fits.
	writeStringMap(w, resp.GetUpstreamHeaders())
	writeStringMap(w, resp.GetResponseHeaders())
	w.writeString(resp.GetDenyReason())
	w.writeString(resp.GetError())
	return w.buf
}

// CanonicalMutateResponse — same scheme for MutateResponse. The
// mutator is the simplest of the three: it only emits header diffs
// and an optional error.
func CanonicalMutateResponse(alg, keyID string, resp *pluginv1.MutateResponse) []byte {
	w := newCanon()
	w.writeString(canonicalVersion)
	w.writeString("MutateResponse")
	w.writeString(alg)
	w.writeString(keyID)
	writeStringMap(w, resp.GetUpstreamHeaders())
	writeStringMap(w, resp.GetResponseHeaders())
	w.writeString(resp.GetError())
	return w.buf
}

// writeIdentity serializes an authv1.Identity (or its zero/nil shape)
// into the canon stream. Nil and empty are distinct: a nil identity
// writes a single 0xFF marker byte; an empty-but-present identity
// writes a 0x00 marker followed by zero-length subject/source/claims.
// This prevents a tampered response from swapping nil for empty.
func writeIdentity(w *canon, id *authv1.Identity) {
	if id == nil {
		w.buf = append(w.buf, 0xFF)
		return
	}
	w.buf = append(w.buf, 0x00)
	w.writeString(id.GetSubject())
	w.writeString(id.GetSource())
	writeStringMap(w, id.GetClaims())
}

// writeStringMap writes a map<string,string> as [N][k1][v1]...[kN][vN]
// with keys sorted lexicographically. The sort makes the encoding
// deterministic across Go runtime map-iteration randomness.
func writeStringMap(w *canon, m map[string]string) {
	w.writeUint32(uint32(len(m))) //nolint:gosec // map size fits.
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w.writeString(k)
		w.writeString(m[k])
	}
}

// canon is the tiny length-prefix writer used by the Canonical*
// functions. Kept private because callers should never assemble the
// payload by hand — the only supported entry points are the three
// Canonical*Response functions.
type canon struct{ buf []byte }

func newCanon() *canon { return &canon{buf: make([]byte, 0, 256)} }

func (w *canon) writeUint32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *canon) writeString(s string) {
	w.writeUint32(uint32(len(s))) //nolint:gosec // bounded by message size.
	w.buf = append(w.buf, s...)
}

func (w *canon) writeBool(b bool) {
	if b {
		w.buf = append(w.buf, 1)
	} else {
		w.buf = append(w.buf, 0)
	}
}
