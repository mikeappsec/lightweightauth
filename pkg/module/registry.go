// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

// Kind is the pipeline stage a factory produces a module for.
type Kind int

const (
	KindIdentifier Kind = iota
	KindAuthorizer
	KindMutator
)

func (k Kind) String() string {
	switch k {
	case KindIdentifier:
		return "identifier"
	case KindAuthorizer:
		return "authorizer"
	case KindMutator:
		return "mutator"
	default:
		return "unknown"
	}
}

// Legacy type aliases — kept for backward compatibility with existing
// module init() functions that reference these types directly.
type (
	IdentifierFactory = ModuleFactory[Identifier]
	AuthorizerFactory = ModuleFactory[Authorizer]
	MutatorFactory    = ModuleFactory[ResponseMutator]
)

// ─── Backward-Compatible Registration Functions ───────────────────
// These delegate to the global generic registries. Existing modules
// continue to call module.RegisterIdentifier("jwt", factory) unchanged.

// RegisterIdentifier installs an identifier factory under the given type
// name (e.g. "jwt", "apikey"). Panics on duplicate registration.
func RegisterIdentifier(typeName string, f IdentifierFactory) {
	Identifiers.Register(typeName, f)
}

// RegisterAuthorizer installs an authorizer factory under the given type
// name (e.g. "rbac", "opa", "openfga", "composite").
func RegisterAuthorizer(typeName string, f AuthorizerFactory) {
	Authorizers.Register(typeName, f)
}

// RegisterMutator installs a response-mutator factory.
func RegisterMutator(typeName string, f MutatorFactory) {
	Mutators.Register(typeName, f)
}

// ─── Backward-Compatible Build Functions ──────────────────────────

// BuildIdentifier looks up a registered identifier factory and invokes it.
func BuildIdentifier(typeName, instanceName string, cfg map[string]any) (Identifier, error) {
	return Identifiers.Build(typeName, instanceName, cfg)
}

// BuildAuthorizer looks up a registered authorizer factory and invokes it.
func BuildAuthorizer(typeName, instanceName string, cfg map[string]any) (Authorizer, error) {
	return Authorizers.Build(typeName, instanceName, cfg)
}

// BuildMutator looks up a registered mutator factory and invokes it.
func BuildMutator(typeName, instanceName string, cfg map[string]any) (ResponseMutator, error) {
	return Mutators.Build(typeName, instanceName, cfg)
}

// RegisteredTypes returns the type names registered for a given Kind.
// Useful for `lwauthctl modules` and tests.
func RegisteredTypes(k Kind) []string {
	switch k {
	case KindIdentifier:
		return Identifiers.Types()
	case KindAuthorizer:
		return Authorizers.Types()
	case KindMutator:
		return Mutators.Types()
	default:
		return nil
	}
}
