package apikey

import (
	"crypto/sha256"
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

// secretHash is a fixed-length SHA-256 digest used for constant-time
// comparison. By hashing at load time, all comparisons are exactly 32
// bytes regardless of original secret length — eliminating the length
// oracle in subtle.ConstantTimeCompare.
type secretHash [sha256.Size]byte

func hashSecret(secret []byte) secretHash {
	return sha256.Sum256(secret)
}

// rotatableHashEntry pairs a precomputed fixed-length hash with the KID it belongs to.
type rotatableHashEntry struct {
	hash secretHash
	kid  string
}

// buildRotatableStore constructs a store backed by a KeySet from the
// shared secrets config format. Each secret entry is treated as a
// plaintext API key with rotation metadata. Secrets are hashed to a
// fixed 32-byte digest at load time for timing-safe comparison.
func buildRotatableStore(entries []keyrotation.SecretEntry) (*rotatableStore, *keyrotation.KeySet[entry]) {
	ks := keyrotation.NewKeySet[entry](nil)
	hashed := make([]rotatableHashEntry, len(entries))
	for i, e := range entries {
		ks.Put(e.Meta, entry{
			subject: e.Subject,
			roles:   e.Roles,
			keyID:   e.Meta.KID,
		})
		hashed[i] = rotatableHashEntry{hash: hashSecret(e.Secret), kid: e.Meta.KID}
	}
	return &rotatableStore{hashed: hashed, keyset: ks}, ks
}

// rotatableStore implements Store with rotation-aware lookup.
type rotatableStore struct {
	hashed []rotatableHashEntry
	keyset *keyrotation.KeySet[entry]
}

func (rs *rotatableStore) Lookup(presented string) (entry, bool) {
	// Hash the presented key to fixed 32 bytes — every ConstantTimeCompare
	// call now operates on equal-length inputs, eliminating the length
	// oracle. Early return is acceptable: each comparison is the
	// same fixed cost, so iteration count only leaks position (not length),
	// and that signal is buried in network noise for small key counts.
	h := hashSecret([]byte(presented))
	for _, he := range rs.hashed {
		if subtle.ConstantTimeCompare(h[:], he.hash[:]) == 1 {
			return rs.keyset.Get(he.kid)
		}
	}
	return entry{}, false
}
