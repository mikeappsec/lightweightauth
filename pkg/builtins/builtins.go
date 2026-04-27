// Package builtins imports the built-in identifier, authorizer, and
// mutator packages purely for their init() side-effects, so that
// `import _ "github.com/mikeappsec/lightweightauth/pkg/builtins"` registers
// every default module with module.Register*.
//
// The cmd/lwauth main blank-imports this package; users embedding
// lightweightauth as a library can choose to import only the subset they
// want.
package builtins

import (
	_ "github.com/mikeappsec/lightweightauth/pkg/authz/composite"
	_ "github.com/mikeappsec/lightweightauth/pkg/authz/cel"
	_ "github.com/mikeappsec/lightweightauth/pkg/authz/opa"
	_ "github.com/mikeappsec/lightweightauth/pkg/authz/openfga"
	_ "github.com/mikeappsec/lightweightauth/pkg/authz/rbac"

	// Register the shared cache backend(s) for their side-effect.
	_ "github.com/mikeappsec/lightweightauth/internal/cache/valkey"
	_ "github.com/mikeappsec/lightweightauth/pkg/identity/apikey"
	_ "github.com/mikeappsec/lightweightauth/pkg/identity/dpop"
	_ "github.com/mikeappsec/lightweightauth/pkg/identity/hmac"
	_ "github.com/mikeappsec/lightweightauth/pkg/identity/introspection"
	_ "github.com/mikeappsec/lightweightauth/pkg/identity/jwt"
	_ "github.com/mikeappsec/lightweightauth/pkg/identity/mtls"
	_ "github.com/mikeappsec/lightweightauth/pkg/identity/oauth2"
	_ "github.com/mikeappsec/lightweightauth/pkg/mutator/headers"
	_ "github.com/mikeappsec/lightweightauth/pkg/mutator/jwtissue"
)
