// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package module — RevocationChecker interface.

package module

// RevocationChecker is an OPTIONAL interface that an Identifier may
// implement. When a revocation store is configured and the active
// identifier implements this interface, the pipeline checks whether the
// credential is revoked after successful identification but before
// authorization/cache lookup.
//
// Each module derives keys in its own format so the revocation store
// remains format-agnostic:
//
//	jwt    → ["jti:<value>", "sub:<tenant>:<subject>"]
//	apikey → ["kid:<key-id>", "sub:<tenant>:<subject>"]
//	mtls   → ["fp:<sha256(cert)>", "sub:<tenant>:<subject>"]
//	hmac   → ["kid:<key-id>", "sub:<tenant>:<subject>"]
//
// The store simply answers "does key X exist?" — the intelligence of
// *how* to derive keys lives in the module.
//
// Return nil from RevocationKeys to skip the check for a particular
// identity (e.g. when the identity has no revocable claim).
type RevocationChecker interface {
	// RevocationKeys returns zero or more store keys to check for
	// revocation. The pipeline short-circuits to 401 if ANY key is
	// present in the revocation store.
	RevocationKeys(id *Identity, tenantID string) []string
}
