package mtls

import (
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Compile-time check.
var _ module.Rotatable = (*rotatableIdentifier)(nil)

// rotatableIdentifier wraps identifier with CA rotation lifecycle tracking.
type rotatableIdentifier struct {
	identifier
	keyset  *keyrotation.KeySet[[]byte] // keyed by CA serial hex
	watcher *CABundleWatcher
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
