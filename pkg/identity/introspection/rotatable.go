package introspection

import (
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Compile-time check.
var _ module.Rotatable = (*rotatableIdentifier)(nil)

// rotatableIdentifier wraps identifier with client-secret rotation
// lifecycle tracking. The introspection module's client credentials
// (used to authenticate to the IdP's introspection endpoint) can be
// rotated using the shared secrets config format.
type rotatableIdentifier struct {
	identifier
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
