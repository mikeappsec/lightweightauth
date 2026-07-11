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

// Legacy type aliases — the no-dependencies factory signature, kept so
// existing module init() functions register unchanged. Deps-aware modules
// use ModuleFactory[T] with the *WithDeps registration functions.
type (
	IdentifierFactory = SimpleFactory[Identifier]
	AuthorizerFactory = SimpleFactory[Authorizer]
	MutatorFactory    = SimpleFactory[ResponseMutator]
)

// ─── Registration Functions ───────────────────────────────────────
// The plain Register* functions take the legacy no-deps factory so existing
// modules call module.RegisterIdentifier("jwt", factory) unchanged. Modules
// that need host dependencies (cache pools, lifecycle context) register with
// the *WithDeps variants and receive a Deps argument.

// RegisterIdentifier installs a no-dependencies identifier factory under the
// given type name (e.g. "jwt", "apikey"). Panics on duplicate registration.
func RegisterIdentifier(typeName string, f IdentifierFactory) {
	Identifiers.RegisterSimple(typeName, f)
}

// RegisterAuthorizer installs a no-dependencies authorizer factory under the
// given type name (e.g. "rbac", "opa", "openfga", "composite").
func RegisterAuthorizer(typeName string, f AuthorizerFactory) {
	Authorizers.RegisterSimple(typeName, f)
}

// RegisterMutator installs a no-dependencies response-mutator factory.
func RegisterMutator(typeName string, f MutatorFactory) {
	Mutators.RegisterSimple(typeName, f)
}

// RegisterIdentifierWithDeps installs a dependency-aware identifier factory,
// which receives a [Deps] carrying cache pools and the engine context.
func RegisterIdentifierWithDeps(typeName string, f ModuleFactory[Identifier]) {
	Identifiers.Register(typeName, f)
}

// RegisterAuthorizerWithDeps installs a dependency-aware authorizer factory.
func RegisterAuthorizerWithDeps(typeName string, f ModuleFactory[Authorizer]) {
	Authorizers.Register(typeName, f)
}

// RegisterMutatorWithDeps installs a dependency-aware response-mutator factory.
func RegisterMutatorWithDeps(typeName string, f ModuleFactory[ResponseMutator]) {
	Mutators.Register(typeName, f)
}

// ─── Build Functions ──────────────────────────────────────────────

// BuildIdentifier builds a registered identifier with no injected
// dependencies. Hosts that wire caches use [BuildIdentifierWithDeps].
func BuildIdentifier(typeName, instanceName string, cfg map[string]any) (Identifier, error) {
	return Identifiers.Build(typeName, instanceName, cfg, Deps{})
}

// BuildAuthorizer builds a registered authorizer with no injected deps.
func BuildAuthorizer(typeName, instanceName string, cfg map[string]any) (Authorizer, error) {
	return Authorizers.Build(typeName, instanceName, cfg, Deps{})
}

// BuildMutator builds a registered mutator with no injected deps.
func BuildMutator(typeName, instanceName string, cfg map[string]any) (ResponseMutator, error) {
	return Mutators.Build(typeName, instanceName, cfg, Deps{})
}

// BuildIdentifierWithDeps builds a registered identifier, injecting deps.
func BuildIdentifierWithDeps(typeName, instanceName string, cfg map[string]any, deps Deps) (Identifier, error) {
	return Identifiers.Build(typeName, instanceName, cfg, deps)
}

// BuildAuthorizerWithDeps builds a registered authorizer, injecting deps.
func BuildAuthorizerWithDeps(typeName, instanceName string, cfg map[string]any, deps Deps) (Authorizer, error) {
	return Authorizers.Build(typeName, instanceName, cfg, deps)
}

// BuildMutatorWithDeps builds a registered mutator, injecting deps.
func BuildMutatorWithDeps(typeName, instanceName string, cfg map[string]any, deps Deps) (ResponseMutator, error) {
	return Mutators.Build(typeName, instanceName, cfg, deps)
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
