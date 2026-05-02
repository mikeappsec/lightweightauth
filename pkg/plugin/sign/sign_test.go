// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
)

// secret is a 32-byte HMAC key used by every test in this file. The
// hex-decoded form lives next to the canonical-vector tests so a
// future cross-language conformance harness can reproduce them
// byte-for-byte.
var secret, _ = hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

// TestSignVerify_RoundTrip pins the basic property: sign(payload)
// then Verify(same payload, same secret) returns nil. Without this
// the rest of the test file is untrustworthy.
func TestSignVerify_RoundTrip(t *testing.T) {
	payload := []byte("hello world")
	sig := Sign(secret, payload)
	if err := Verify(secret, payload, sig); err != nil {
		t.Fatalf("Verify(matching): %v", err)
	}
}

// TestVerify_MismatchPayload rejects a signature that was made over
// different bytes. This is the property a plugin compromise would
// have to break.
func TestVerify_MismatchPayload(t *testing.T) {
	sig := Sign(secret, []byte("original"))
	if err := Verify(secret, []byte("tampered"), sig); err == nil {
		t.Fatal("Verify(tampered) returned nil; want signature mismatch")
	}
}

// TestVerify_MismatchSecret rejects a signature made under a
// different key. Closes the case where two operators share an HMAC
// scheme but use distinct keys per plugin.
func TestVerify_MismatchSecret(t *testing.T) {
	other, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	sig := Sign(secret, []byte("payload"))
	if err := Verify(other, []byte("payload"), sig); err == nil {
		t.Fatal("Verify(wrong-secret) returned nil; want mismatch")
	}
}

// TestVerify_NotHex rejects a malformed signature trailer rather
// than crashing or treating it as "ok".
func TestVerify_NotHex(t *testing.T) {
	if err := Verify(secret, []byte("p"), "not-hex!!"); err == nil {
		t.Fatal("Verify(non-hex sig) returned nil; want hex decode error")
	}
}

// TestCanonicalIdentify_Deterministic — the canonical encoder MUST
// produce identical bytes for two equivalent IdentifyResponses
// regardless of map-iteration order. This is the keystone of the
// scheme: if the encoder is non-deterministic, signatures are a
// gamble.
func TestCanonicalIdentify_Deterministic(t *testing.T) {
	a := &pluginv1.IdentifyResponse{
		Identity: &authv1.Identity{
			Subject: "alice", Source: "saml",
			Claims: map[string]string{"email": "a@x", "role": "admin", "team": "core"},
		},
	}
	b := &pluginv1.IdentifyResponse{
		Identity: &authv1.Identity{
			Subject: "alice", Source: "saml",
			Claims: map[string]string{"team": "core", "role": "admin", "email": "a@x"},
		},
	}
	pa := CanonicalIdentifyResponse(AlgHMACSHA256, "k1", a)
	pb := CanonicalIdentifyResponse(AlgHMACSHA256, "k1", b)
	if !bytes.Equal(pa, pb) {
		t.Fatalf("canonical bytes diverged for equal inputs:\n  a=%x\n  b=%x", pa, pb)
	}
}

// TestCanonicalIdentify_DifferentInputsDifferentBytes — the dual of
// the determinism test. Any field change must change the canonical
// bytes, otherwise an attacker can swap field values "under" a
// signature.
func TestCanonicalIdentify_DifferentInputsDifferentBytes(t *testing.T) {
	base := &pluginv1.IdentifyResponse{
		Identity: &authv1.Identity{Subject: "alice", Source: "saml"},
	}
	mutations := map[string]*pluginv1.IdentifyResponse{
		"subject": {Identity: &authv1.Identity{Subject: "bob", Source: "saml"}},
		"source":  {Identity: &authv1.Identity{Subject: "alice", Source: "ldap"}},
		"claim_added": {Identity: &authv1.Identity{
			Subject: "alice", Source: "saml",
			Claims: map[string]string{"role": "admin"}},
		},
		"no_match_flipped": {NoMatch: true,
			Identity: &authv1.Identity{Subject: "alice", Source: "saml"}},
		"error_set": {Error: "boom",
			Identity: &authv1.Identity{Subject: "alice", Source: "saml"}},
	}
	baseBytes := CanonicalIdentifyResponse(AlgHMACSHA256, "k1", base)
	for label, m := range mutations {
		mb := CanonicalIdentifyResponse(AlgHMACSHA256, "k1", m)
		if bytes.Equal(baseBytes, mb) {
			t.Errorf("mutation %q produced identical canonical bytes", label)
		}
	}
}

// TestCanonicalIdentify_NilVsEmptyIdentity — nil identity and an
// empty (non-nil) identity must not collide. Without this distinction
// an attacker could swap "no identity, no_match=true" for "blank
// identity, no_match=false" and vice versa.
func TestCanonicalIdentify_NilVsEmptyIdentity(t *testing.T) {
	nilID := &pluginv1.IdentifyResponse{NoMatch: true}
	emptyID := &pluginv1.IdentifyResponse{NoMatch: true, Identity: &authv1.Identity{}}
	a := CanonicalIdentifyResponse(AlgHMACSHA256, "k", nilID)
	b := CanonicalIdentifyResponse(AlgHMACSHA256, "k", emptyID)
	if bytes.Equal(a, b) {
		t.Fatal("canonical encoder collapsed nil vs empty Identity; that's a substitution vector")
	}
}

// TestCanonicalIdentify_AlgKidInPayload — the alg and key-id are
// part of the canonical bytes, so an attacker can't swap them in
// the trailer without invalidating the signature.
func TestCanonicalIdentify_AlgKidInPayload(t *testing.T) {
	r := &pluginv1.IdentifyResponse{Identity: &authv1.Identity{Subject: "x", Source: "y"}}
	a := CanonicalIdentifyResponse("hmac-sha256", "k1", r)
	b := CanonicalIdentifyResponse("hmac-sha256", "k2", r)
	c := CanonicalIdentifyResponse("hmac-sha512", "k1", r)
	if bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(b, c) {
		t.Fatal("alg/key-id are not bound into the canonical payload; downgrade vector")
	}
}

// TestCanonicalIdentify_VersionPrefix — every payload starts with
// the version tag, length-prefixed. A v2 host must be able to
// unambiguously refuse a v1 signature.
func TestCanonicalIdentify_VersionPrefix(t *testing.T) {
	p := CanonicalIdentifyResponse(AlgHMACSHA256, "k", &pluginv1.IdentifyResponse{})
	// Decode the first length-prefixed string and check it.
	if len(p) < 4 {
		t.Fatalf("canonical too short: %d bytes", len(p))
	}
	n := uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
	if int(4+n) > len(p) {
		t.Fatalf("declared first-string length %d overruns buffer of %d", n, len(p))
	}
	v := string(p[4 : 4+n])
	if !strings.HasPrefix(v, "lwauth-plugin-sig-v") {
		t.Errorf("first canonical field = %q, want a version tag", v)
	}
}

// TestCanonicalAuthorize_HeaderMapsSorted — header maps in the
// AuthorizePluginResponse have to canonicalize independent of
// insertion order, both upstream and response sides.
func TestCanonicalAuthorize_HeaderMapsSorted(t *testing.T) {
	a := &pluginv1.AuthorizePluginResponse{
		Allow: true, HttpStatus: 200,
		UpstreamHeaders: map[string]string{"X-A": "1", "X-B": "2", "X-C": "3"},
		ResponseHeaders: map[string]string{"Y-A": "1", "Y-B": "2"},
	}
	b := &pluginv1.AuthorizePluginResponse{
		Allow: true, HttpStatus: 200,
		UpstreamHeaders: map[string]string{"X-C": "3", "X-A": "1", "X-B": "2"},
		ResponseHeaders: map[string]string{"Y-B": "2", "Y-A": "1"},
	}
	pa := CanonicalAuthorizeResponse(AlgHMACSHA256, "k", a)
	pb := CanonicalAuthorizeResponse(AlgHMACSHA256, "k", b)
	if !bytes.Equal(pa, pb) {
		t.Fatalf("authorize canonical bytes differ across header insertion order:\n  a=%x\n  b=%x", pa, pb)
	}
}

// TestCanonicalMutate_SmallestForm — sanity-check the simplest
// canonical: an empty MutateResponse still produces a valid signed
// payload with the version + type prefix in place.
func TestCanonicalMutate_SmallestForm(t *testing.T) {
	p := CanonicalMutateResponse(AlgHMACSHA256, "k", &pluginv1.MutateResponse{})
	if len(p) < 8 {
		t.Fatalf("MutateResponse canonical too short: %d bytes", len(p))
	}
	sig := Sign(secret, p)
	if err := Verify(secret, p, sig); err != nil {
		t.Errorf("MutateResponse round-trip: %v", err)
	}
}
