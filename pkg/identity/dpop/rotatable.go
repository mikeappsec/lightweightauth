// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Compile-time check.
var _ module.Rotatable = (*rotatableIdentifier)(nil)

// rotatableIdentifier wraps the DPoP identifier with rotation lifecycle
// tracking. DPoP itself doesn't hold secrets, but its inner identifier
// may (e.g. an introspection endpoint client secret). When the inner
// identifier is Rotatable, rotatableIdentifier delegates to it.
// Additionally, if DPoP proof-signing keys are configured with rotation
// metadata (for server-side pinning scenarios), they are tracked here.
type rotatableIdentifier struct {
	identifier
	keyset *keyrotation.KeySet[[]byte] // optional pinned proof keys
}

func (ri *rotatableIdentifier) KeyStates() []module.KeyStateMeta {
	var out []module.KeyStateMeta

	// Report own pinned proof keys if any.
	if ri.keyset != nil {
		all := ri.keyset.All()
		now := time.Now()
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
