// Package builtins imports the built-in identifier, authorizer, and
// mutator packages purely for their init() side-effects, so that
// `import _ "github.com/yourorg/lightweightauth/pkg/builtins"` registers
// every default module with module.Register*.
//
// The cmd/lwauth main blank-imports this package; users embedding
// lightweightauth as a library can choose to import only the subset they
// want.
package builtins

import (
	_ "github.com/yourorg/lightweightauth/pkg/authz/rbac"
	_ "github.com/yourorg/lightweightauth/pkg/identity/apikey"
	_ "github.com/yourorg/lightweightauth/pkg/identity/jwt"
)
