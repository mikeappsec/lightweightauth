package module

import "errors"

// Sentinel errors returned by modules and recognized by the pipeline.
//
// The pipeline maps these to HTTP status codes (see internal/pipeline) and
// uses them to decide whether a result is safe to negative-cache. See
// docs/ARCHITECTURE.md "Error taxonomy" for the rationale.
var (
	// ErrNoMatch means the identifier doesn't apply to this request
	// (e.g. JWT identifier saw no Authorization header). The pipeline
	// will try the next identifier.
	ErrNoMatch = errors.New("module: no match")

	// ErrInvalidCredential means a credential was found but failed
	// verification (bad signature, expired, wrong audience, ...). The
	// pipeline maps this to 401 and stops trying further identifiers
	// unless explicitly configured to layer them.
	ErrInvalidCredential = errors.New("module: invalid credential")

	// ErrForbidden means an authorizer rejected an established identity.
	// Maps to 403. Safe to negative-cache for short TTLs.
	ErrForbidden = errors.New("module: forbidden")

	// ErrUpstream means a dependency the module needs (JWKS endpoint,
	// introspection endpoint, OpenFGA, ...) was unreachable or returned
	// a non-deterministic error. Maps to 503; MUST NOT be cached.
	ErrUpstream = errors.New("module: upstream unavailable")

	// ErrConfig means the module was misconfigured. Surfaces at startup
	// or on hot-reload; should never happen at request time on a healthy
	// instance.
	ErrConfig = errors.New("module: configuration error")
)
