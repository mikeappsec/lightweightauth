// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"context"
	"encoding/base64"
	"fmt"

	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Compile-time check.
var _ module.Rotatable = (*rotatableIdentifier)(nil)

// rotatableIdentifier wraps the DPoP identifier with rotation lifecycle
// tracking and server-side proof key pinning. When pinnedKeys are
// configured, only proofs signed by keys whose thumbprint matches an
// active or retiring entry in the KeySet are accepted — pending and
// retired keys are rejected. This enables zero-downtime key rotation.
type rotatableIdentifier struct {
	identifier
	pinned *keyrotation.KeySet[string] // thumbprint → kid mapping
}

// Identify overrides the embedded identifier.Identify to add pinned key
// enforcement. The DPoP proof is verified by the base identifier, then
// the proof key's thumbprint is checked against the pinned set.
func (ri *rotatableIdentifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	// If no pinned keys are configured, behave as plain identifier.
	if ri.pinned == nil || ri.pinned.Len() == 0 {
		return ri.identifier.Identify(ctx, r)
	}

	// We need the proof's JWK thumbprint to check against pinned set.
	// Extract and verify the proof first (duplicates some work from
	// identifier.Identify, but we need the JWK before calling inner).
	proof := r.Header(ri.cfg.ProofHeader)
	if proof == "" {
		if ri.cfg.Required {
			return nil, fmt.Errorf("%w: dpop: missing %s header", module.ErrInvalidCredential, ri.cfg.ProofHeader)
		}
		return ri.inner.Identify(ctx, r)
	}

	jwkProof, _, err := ri.verifyProof(ctx, proof, r)
	if err != nil {
		return nil, err
	}

	// Check the proof key against the pinned set.
	thumb, err := jwkThumbprintB64(jwkProof)
	if err != nil {
		return nil, fmt.Errorf("%w: dpop: pinned key thumbprint: %v", module.ErrInvalidCredential, err)
	}
	if !ri.isPinned(thumb) {
		return nil, fmt.Errorf("%w: dpop: proof key not in pinned set", module.ErrInvalidCredential)
	}

	// Pinned check passed — delegate to the full flow (which will
	// re-verify the proof, but the JTI replay cache will reject the
	// second parse). We need to work around this by using the base
	// identifier's logic directly without double-verifying.
	//
	// Instead, inline the rest of the flow here:
	innerReq := ri.rewriteAuthForInner(r)
	id, err := ri.inner.Identify(ctx, innerReq)
	if err != nil {
		return nil, err
	}

	// cnf.jkt binding.
	if jkt, ok := extractCnfJkt(id); ok {
		if thumb != jkt {
			return nil, fmt.Errorf("%w: dpop: cnf.jkt mismatch", module.ErrInvalidCredential)
		}
	}

	// ath binding.
	if at := bearerToken(r, ri.cfg.BearerHeader); at != "" {
		claims, _ := ri.proofClaims(ctx, proof)
		gotAth, _ := claims["ath"].(string)
		wantAth := base64.RawURLEncoding.EncodeToString(sha256sum(at))
		if gotAth == "" || gotAth != wantAth {
			return nil, fmt.Errorf("%w: dpop: ath mismatch", module.ErrInvalidCredential)
		}
	}

	return id, nil
}

// isPinned checks whether the given thumbprint matches any active or
// retiring key in the pinned set.
func (ri *rotatableIdentifier) isPinned(thumb string) bool {
	// Iterate all entries and match by thumbprint value (not kid).
	all := ri.pinned.All()
	now := ri.now()
	for _, meta := range all {
		if !meta.IsValid(now) {
			continue // pending or retired
		}
		// Get the stored thumbprint value for this kid.
		if stored, ok := ri.pinned.Get(meta.KID); ok {
			if stored == thumb {
				return true
			}
		}
	}
	return false
}

// proofClaims re-parses the proof to extract claims. This is only
// called after verifyProof has already validated the proof, so we
// trust the content. Used to access ath without modifying verifyProof's
// return signature.
func (ri *rotatableIdentifier) proofClaims(ctx context.Context, proof string) (map[string]any, error) {
	tok, err := jwtlib.ParseString(proof, jwtlib.WithVerify(false), jwtlib.WithValidate(false))
	if err != nil {
		return nil, err
	}
	return tok.AsMap(ctx)
}

func (ri *rotatableIdentifier) KeyStates() []module.KeyStateMeta {
	var out []module.KeyStateMeta

	// Report own pinned proof keys if any.
	if ri.pinned != nil {
		all := ri.pinned.All()
		now := ri.now()
		for _, m := range all {
			out = append(out, module.KeyStateMeta{
				KID:   m.KID,
				State: string(m.State(now)),
			})
		}
	}

	// Delegate to inner identifier if it's also Rotatable.
	if r, ok := ri.inner.(module.Rotatable); ok {
		out = append(out, r.KeyStates()...)
	}

	return out
}
