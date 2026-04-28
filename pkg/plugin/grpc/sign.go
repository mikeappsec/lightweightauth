package grpc

import (
	"encoding/hex"
	"errors"
	"fmt"

	"google.golang.org/grpc/metadata"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/plugin/sign"
)

// signingMode is the host-side enforcement policy for plugin-response
// signatures (F-PLUGIN-2).
//
//   - signingDisabled — never look at trailers; v1.0 behaviour. This is
//     the default so existing configs keep working unchanged.
//   - signingVerify   — verify the signature when one is present;
//     accept unsigned responses too. Useful when rolling out signing
//     across a fleet without flag-day cuts.
//   - signingRequire  — every response MUST be signed by a configured
//     key, otherwise the call fails closed with ErrUpstream. This is
//     the safe-by-default we recommend once a deployment has finished
//     rolling out signed plugins.
type signingMode int

const (
	signingDisabled signingMode = iota
	signingVerify
	signingRequire
)

// signingConfig is the parsed `signing` block from a grpc-plugin
// config. Keys are stored as raw bytes (hex-decoded by the parser) so
// the verify path doesn't have to re-decode on every call.
type signingConfig struct {
	mode signingMode
	// keys maps key-id -> raw HMAC secret. Empty when mode == signingDisabled.
	keys map[string][]byte
}

// parseSigning extracts the `signing` config block from raw config.
// Returns a zero-value signingConfig (mode=disabled) when the block
// is absent — the v1.0 default — so existing configs are unaffected.
//
// Schema:
//
//	signing:
//	  mode: disabled|verify|require        # default: disabled
//	  keys:
//	    - id: ops-2026-04                  # arbitrary stable string
//	      hmacSecret: <64-hex-chars>       # 32-byte HMAC-SHA256 key
//
// We require at least 16 bytes of key material per key (hex length
// >= 32) because shorter keys reduce the brute-force cost of the
// HMAC and there is no operational reason for them to exist.
func parseSigning(name string, raw map[string]any) (signingConfig, error) {
	var out signingConfig
	block, ok := raw["signing"].(map[string]any)
	if !ok {
		return out, nil
	}
	switch m, _ := block["mode"].(string); m {
	case "", "disabled":
		out.mode = signingDisabled
	case "verify":
		out.mode = signingVerify
	case "require":
		out.mode = signingRequire
	default:
		return out, fmt.Errorf("%w: grpc-plugin %q: signing.mode %q is not one of disabled|verify|require",
			module.ErrConfig, name, m)
	}

	keysAny, _ := block["keys"].([]any)
	if len(keysAny) == 0 && out.mode != signingDisabled {
		return out, fmt.Errorf("%w: grpc-plugin %q: signing.mode=%q requires at least one signing.keys entry",
			module.ErrConfig, name, modeName(out.mode))
	}
	if len(keysAny) > 0 {
		out.keys = make(map[string][]byte, len(keysAny))
	}
	for i, ke := range keysAny {
		entry, ok := ke.(map[string]any)
		if !ok {
			return out, fmt.Errorf("%w: grpc-plugin %q: signing.keys[%d] must be an object", module.ErrConfig, name, i)
		}
		id, _ := entry["id"].(string)
		if id == "" {
			return out, fmt.Errorf("%w: grpc-plugin %q: signing.keys[%d].id is required", module.ErrConfig, name, i)
		}
		secHex, _ := entry["hmacSecret"].(string)
		if secHex == "" {
			return out, fmt.Errorf("%w: grpc-plugin %q: signing.keys[%d].hmacSecret is required", module.ErrConfig, name, i)
		}
		secret, err := hex.DecodeString(secHex)
		if err != nil {
			return out, fmt.Errorf("%w: grpc-plugin %q: signing.keys[%d].hmacSecret is not hex: %v", module.ErrConfig, name, i, err)
		}
		if len(secret) < 16 {
			return out, fmt.Errorf("%w: grpc-plugin %q: signing.keys[%d].hmacSecret must be >= 16 bytes (32 hex chars)", module.ErrConfig, name, i)
		}
		if _, dup := out.keys[id]; dup {
			return out, fmt.Errorf("%w: grpc-plugin %q: signing.keys[%d].id %q duplicates an earlier entry", module.ErrConfig, name, i, id)
		}
		out.keys[id] = secret
	}
	return out, nil
}

func modeName(m signingMode) string {
	switch m {
	case signingVerify:
		return "verify"
	case signingRequire:
		return "require"
	default:
		return "disabled"
	}
}

// trailerSigInfo extracts the three signature trailers from the
// gRPC trailing metadata, normalising "absent" to ("","","").
// The trailers travel as plain text (not "-bin") so non-Go plugins
// can produce them with a hex encoding step rather than dealing with
// gRPC's binary-trailer rules.
func trailerSigInfo(md metadata.MD) (alg, keyID, sigHex string) {
	if v := md.Get(sign.TrailerAlg); len(v) > 0 {
		alg = v[0]
	}
	if v := md.Get(sign.TrailerKeyID); len(v) > 0 {
		keyID = v[0]
	}
	if v := md.Get(sign.TrailerSig); len(v) > 0 {
		sigHex = v[0]
	}
	return alg, keyID, sigHex
}

// trailerAlg returns just the alg value, or the default when absent.
// Used by the canonical-payload builders, which need to fold alg/kid
// into the payload BEFORE the signature is checked so a downgrade
// attempt (swap alg from hmac-sha256 to "") changes the canonical
// bytes and trips the verify.
func trailerAlg(md metadata.MD) string {
	if v := md.Get(sign.TrailerAlg); len(v) > 0 {
		return v[0]
	}
	return sign.AlgHMACSHA256
}

// trailerKeyID returns just the key id, "" when absent. The default
// is intentionally NOT substituted here: an attacker who strips the
// kid trailer must produce a signature that canonicalizes with
// keyID="", which won't match a real key entry on the host side.
func trailerKeyID(md metadata.MD) string {
	if v := md.Get(sign.TrailerKeyID); len(v) > 0 {
		return v[0]
	}
	return ""
}

// verifyTrailer enforces the signing policy for one plugin call.
// payload is the canonical bytes the plugin should have signed; the
// caller computes it via one of the sign.Canonical*Response helpers
// against the response struct it just received over the wire.
//
// The function fails closed: any irregularity (mode=require + no
// trailer, unknown key id, signature mismatch, unsupported alg) maps
// to a ErrUpstream-wrapped error so the pipeline reports the call as
// "plugin returned, but the host couldn't trust the answer".
func (s signingConfig) verifyTrailer(name string, md metadata.MD, payload []byte) error {
	if s.mode == signingDisabled {
		return nil
	}
	alg, keyID, sigHex := trailerSigInfo(md)
	if sigHex == "" {
		if s.mode == signingRequire {
			return fmt.Errorf("%w: grpc-plugin %q: signing.mode=require but plugin sent no %s trailer",
				module.ErrUpstream, name, sign.TrailerSig)
		}
		return nil // mode == verify, unsigned is allowed.
	}
	// Signature is present — we MUST verify it, regardless of mode.
	// Letting "verify" mode silently accept a *bad* signature would
	// be a downgrade vector.
	if alg == "" {
		alg = sign.AlgHMACSHA256 // backward-compat default; plugins should set it.
	}
	if alg != sign.AlgHMACSHA256 {
		return fmt.Errorf("%w: grpc-plugin %q: signing alg %q is not supported by this host", module.ErrUpstream, name, alg)
	}
	if keyID == "" {
		return fmt.Errorf("%w: grpc-plugin %q: signature trailer missing %s", module.ErrUpstream, name, sign.TrailerKeyID)
	}
	secret, ok := s.keys[keyID]
	if !ok {
		return fmt.Errorf("%w: grpc-plugin %q: signature key id %q is not in the configured key set", module.ErrUpstream, name, keyID)
	}
	if err := sign.Verify(secret, payload, sigHex); err != nil {
		return fmt.Errorf("%w: grpc-plugin %q: %v", module.ErrUpstream, name, err)
	}
	return nil
}

// errSigningRequiresMode is sentinel-style help for assertions in tests.
var errSigningRequiresMode = errors.New("grpc-plugin: signing config: mode required")
