package apikey

import (
	"crypto/subtle"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Compile-time check.
var _ module.Rotatable = (*rotatableIdentifier)(nil)

// rotatableIdentifier wraps identifier with rotation lifecycle tracking.
type rotatableIdentifier struct {
	identifier
	keyset *keyrotation.KeySet[entry]
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

// buildRotatableStore constructs a store backed by a KeySet from the
// shared secrets config format. Each secret entry is treated as a
// plaintext API key with rotation metadata.
func buildRotatableStore(entries []keyrotation.SecretEntry) (*rotatableStore, *keyrotation.KeySet[entry]) {
	ks := keyrotation.NewKeySet[entry](nil)
	for _, e := range entries {
		ks.Put(e.Meta, entry{
			subject: e.Subject,
			roles:   e.Roles,
			keyID:   e.Meta.KID,
		})
	}
	return &rotatableStore{entries: entries, keyset: ks}, ks
}

// rotatableStore implements Store with rotation-aware lookup.
type rotatableStore struct {
	entries []keyrotation.SecretEntry
	keyset  *keyrotation.KeySet[entry]
}

func (rs *rotatableStore) Lookup(presented string) (entry, bool) {
	// Try each secret entry — the presented key must match the raw secret.
	for _, se := range rs.entries {
		if subtle.ConstantTimeCompare([]byte(presented), se.Secret) == 1 {
			e, ok := rs.keyset.Get(se.Meta.KID)
			return e, ok
		}
	}
	return entry{}, false
}
