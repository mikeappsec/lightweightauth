package hmac

import (
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Compile-time check that identifier implements Rotatable when keys have
// rotation metadata.
var _ module.Rotatable = (*rotatableIdentifier)(nil)

// rotatableIdentifier wraps identifier with a KeySet for rotation-aware
// key lookup and lifecycle reporting.
type rotatableIdentifier struct {
	identifier
	keyset *keyrotation.KeySet[KeyEntry]
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

// buildRotatableIdentifier constructs an HMAC identifier backed by a
// KeySet, using the shared secrets config format.
func buildRotatableIdentifier(base *identifier, entries []keyrotation.SecretEntry) *rotatableIdentifier {
	ks := keyrotation.NewKeySet[KeyEntry](nil)
	keys := make(map[string]KeyEntry, len(entries))
	for _, e := range entries {
		ke := KeyEntry{
			Secret:  e.Secret,
			Subject: e.Subject,
			Roles:   e.Roles,
		}
		ks.Put(e.Meta, ke)
		keys[e.Meta.KID] = ke
	}
	base.keys = keys
	return &rotatableIdentifier{identifier: *base, keyset: ks}
}
