// Package keyrotation implements seamless verifier-side key rotation for
// all credential types (JWKS, HMAC, mTLS CA bundles). It provides:
//
//   - An overlap model so old and new keys are valid simultaneously
//     during a configurable transition window.
//   - Metrics (lwauth_key_verify_total, lwauth_key_refresh_total) that
//     prove when old keys have drained.
//   - Condition setters for IdentityProvider.status.conditions so
//     operators can kubectl-wait for rotation completion.
//
// The package is consumed by the identity modules (pkg/identity/jwt,
// pkg/identity/hmac, pkg/identity/mtls) and by the controller that
// manages IdentityProvider status.
//
// See docs/DESIGN.md §11.1 / D1 (ENT-KEYROT-1).
package keyrotation

import "time"

// KeyState represents the lifecycle state of a key in the rotation model.
type KeyState string

const (
	// KeyStateActive means the key is in normal use (within its
	// notBefore..notAfter window, or no window specified).
	KeyStateActive KeyState = "active"

	// KeyStatePending means the key's notBefore is in the future;
	// it is registered but not yet valid for verification.
	KeyStatePending KeyState = "pending"

	// KeyStateRetiring means the key's notAfter has passed but we are
	// still in the grace period to allow in-flight tokens. The overlap
	// model keeps it available for verification until drained.
	KeyStateRetiring KeyState = "retiring"

	// KeyStateRetired means the key is no longer valid for
	// verification and has been removed from the active set.
	KeyStateRetired KeyState = "retired"
)

// KeyMeta describes a single key in the rotation set. This is the
// common representation shared across credential types (HMAC kid,
// JWKS kid, mTLS CA serial).
type KeyMeta struct {
	// KID is the key identifier (HMAC keyId, JWK kid, CA serial hex).
	KID string `json:"kid" yaml:"kid"`

	// NotBefore is the earliest time this key is valid. Zero means
	// "valid immediately".
	NotBefore time.Time `json:"notBefore,omitempty" yaml:"notBefore,omitempty"`

	// NotAfter is the time after which this key should no longer be
	// used for verification. Zero means "no expiry".
	NotAfter time.Time `json:"notAfter,omitempty" yaml:"notAfter,omitempty"`

	// GracePeriod is how long after NotAfter the key remains available
	// for in-flight token verification. Defaults to 5 minutes.
	GracePeriod time.Duration `json:"gracePeriod,omitempty" yaml:"gracePeriod,omitempty"`
}

// DefaultGracePeriod is used when KeyMeta.GracePeriod is zero.
const DefaultGracePeriod = 5 * time.Minute

// State returns the current lifecycle state of the key.
func (k KeyMeta) State(now time.Time) KeyState {
	if !k.NotBefore.IsZero() && now.Before(k.NotBefore) {
		return KeyStatePending
	}
	if !k.NotAfter.IsZero() {
		grace := k.GracePeriod
		if grace == 0 {
			grace = DefaultGracePeriod
		}
		if now.After(k.NotAfter.Add(grace)) {
			return KeyStateRetired
		}
		if now.After(k.NotAfter) {
			return KeyStateRetiring
		}
	}
	return KeyStateActive
}

// IsValid returns true if the key can be used for verification at time now.
func (k KeyMeta) IsValid(now time.Time) bool {
	s := k.State(now)
	return s == KeyStateActive || s == KeyStateRetiring
}
