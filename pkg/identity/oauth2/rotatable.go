// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Compile-time check.
var _ module.Rotatable = (*rotatableIdentifier)(nil)

// rotatableIdentifier wraps the OAuth2 identifier with client-secret
// rotation lifecycle tracking. OAuth2 client secrets used for token
// exchange can be rotated using the shared secrets config format.
type rotatableIdentifier struct {
	*identifier
	keyset *keyrotation.KeySet[string] // keyed by kid, value is clientSecret
}

func (ri *rotatableIdentifier) KeyStates() []module.KeyStateMeta {
	all := ri.keyset.All()
	now := time.Now()
	out := make([]module.KeyStateMeta, len(all))
	for i, m := range all {
		out[i] = module.KeyStateMeta{
			KID:   m.KID,
			State: string(m.State(now)),
		}
	}
	return out
}

// buildRotatableIdentifier constructs an OAuth2 identifier whose client
// secret (used for token exchange, refresh, and device-poll calls) is
// resolved fresh from a KeySet on every request, using the shared secrets
// config format. clientId itself stays static — only the secret behind it
// rotates.
func buildRotatableIdentifier(base *identifier, entries []keyrotation.SecretEntry) *rotatableIdentifier {
	ks := keyrotation.NewKeySet[string](nil)
	for _, e := range entries {
		ks.Put(e.Meta, string(e.Secret))
	}
	base.resolveClientSecret = func() (string, bool) {
		return resolveActiveSecret(ks)
	}
	return &rotatableIdentifier{identifier: base, keyset: ks}
}

// resolveActiveSecret returns the current secret to authenticate with: the
// first active key, falling back to a retiring one so an in-flight
// rotation doesn't cause an outage while the new secret propagates to the
// IdP's side.
func resolveActiveSecret(ks *keyrotation.KeySet[string]) (string, bool) {
	if kids := ks.ActiveKIDs(); len(kids) > 0 {
		return ks.Get(kids[0])
	}
	if kids := ks.RetiringKIDs(); len(kids) > 0 {
		return ks.Get(kids[0])
	}
	return "", false
}
