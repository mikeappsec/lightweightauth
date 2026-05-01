package controller

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
)

// Condition types for IdentityProvider.status.conditions.
const (
	// ConditionKeyRotation indicates whether a key rotation is in progress.
	ConditionKeyRotation = "KeyRotation"

	// ConditionKeysHealthy indicates all configured keys are valid.
	ConditionKeysHealthy = "KeysHealthy"
)

// Reasons for key rotation conditions.
const (
	ReasonRotationComplete   = "RotationComplete"
	ReasonRotationInProgress = "RotationInProgress"
	ReasonKeyExpired         = "KeyExpired"
	ReasonAllKeysValid       = "AllKeysValid"
	ReasonKeyPending         = "KeyPending"
)

// RotationCondition builds a metav1.Condition describing the current
// rotation state based on the KeySet contents.
func RotationCondition[T any](ks *keyrotation.KeySet[T], gen int64) metav1.Condition {
	now := time.Now()
	retiring := ks.RetiringKIDs()
	active := ks.ActiveKIDs()

	if len(retiring) > 0 {
		return metav1.Condition{
			Type:               ConditionKeyRotation,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gen,
			LastTransitionTime: metav1.Now(),
			Reason:             ReasonRotationInProgress,
			Message:            fmt.Sprintf("keys retiring: %v; active: %v", retiring, active),
		}
	}

	_ = now
	return metav1.Condition{
		Type:               ConditionKeyRotation,
		Status:             metav1.ConditionFalse,
		ObservedGeneration: gen,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonRotationComplete,
		Message:            fmt.Sprintf("all %d key(s) active, no keys retiring", len(active)),
	}
}

// HealthCondition builds a condition reporting whether all keys are healthy.
func HealthCondition[T any](ks *keyrotation.KeySet[T], gen int64) metav1.Condition {
	all := ks.All()
	now := time.Now()
	for _, m := range all {
		if m.State(now) == keyrotation.KeyStateRetired {
			return metav1.Condition{
				Type:               ConditionKeysHealthy,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: gen,
				LastTransitionTime: metav1.Now(),
				Reason:             ReasonKeyExpired,
				Message:            fmt.Sprintf("key %q is retired (past grace period)", m.KID),
			}
		}
	}
	return metav1.Condition{
		Type:               ConditionKeysHealthy,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gen,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonAllKeysValid,
		Message:            fmt.Sprintf("%d key(s) healthy", len(all)),
	}
}
