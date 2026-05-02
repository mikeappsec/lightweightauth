// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"fmt"
	"sync"
)

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

// Factory builds a typed module from a free-form config map. Built-ins
// register themselves via Register*Factory in their package init().
//
// The compile-time registry is the default plugin mechanism; an
// out-of-process gRPC plugin host (DESIGN.md §2) is implemented by
// registering a factory under the type name "grpc-plugin" that returns a
// remoteAdapter at runtime.
type (
	IdentifierFactory func(name string, cfg map[string]any) (Identifier, error)
	AuthorizerFactory func(name string, cfg map[string]any) (Authorizer, error)
	MutatorFactory    func(name string, cfg map[string]any) (ResponseMutator, error)
)

var (
	registryMu  sync.RWMutex
	identifiers = map[string]IdentifierFactory{}
	authorizers = map[string]AuthorizerFactory{}
	mutators    = map[string]MutatorFactory{}
)

// RegisterIdentifier installs an identifier factory under the given type
// name (e.g. "jwt", "apikey"). Panics on duplicate registration so that
// init-time mistakes are caught immediately.
func RegisterIdentifier(typeName string, f IdentifierFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := identifiers[typeName]; dup {
		panic(fmt.Sprintf("module: identifier %q already registered", typeName))
	}
	identifiers[typeName] = f
}

// RegisterAuthorizer installs an authorizer factory under the given type
// name (e.g. "rbac", "opa", "openfga", "composite").
func RegisterAuthorizer(typeName string, f AuthorizerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := authorizers[typeName]; dup {
		panic(fmt.Sprintf("module: authorizer %q already registered", typeName))
	}
	authorizers[typeName] = f
}

// RegisterMutator installs a response-mutator factory.
func RegisterMutator(typeName string, f MutatorFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := mutators[typeName]; dup {
		panic(fmt.Sprintf("module: mutator %q already registered", typeName))
	}
	mutators[typeName] = f
}

// BuildIdentifier looks up a registered identifier factory and invokes it.
func BuildIdentifier(typeName, instanceName string, cfg map[string]any) (Identifier, error) {
	registryMu.RLock()
	f, ok := identifiers[typeName]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown identifier type %q", ErrConfig, typeName)
	}
	return f(instanceName, cfg)
}

// BuildAuthorizer looks up a registered authorizer factory and invokes it.
func BuildAuthorizer(typeName, instanceName string, cfg map[string]any) (Authorizer, error) {
	registryMu.RLock()
	f, ok := authorizers[typeName]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown authorizer type %q", ErrConfig, typeName)
	}
	return f(instanceName, cfg)
}

// BuildMutator looks up a registered mutator factory and invokes it.
func BuildMutator(typeName, instanceName string, cfg map[string]any) (ResponseMutator, error) {
	registryMu.RLock()
	f, ok := mutators[typeName]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown mutator type %q", ErrConfig, typeName)
	}
	return f(instanceName, cfg)
}

// RegisteredTypes returns the type names registered for a given Kind.
// Useful for `lwauthctl modules` and tests.
func RegisteredTypes(k Kind) []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var src map[string]struct{}
	switch k {
	case KindIdentifier:
		src = keysOfIdent()
	case KindAuthorizer:
		src = keysOfAuthz()
	case KindMutator:
		src = keysOfMut()
	}
	names := make([]string, 0, len(src))
	for n := range src {
		names = append(names, n)
	}
	return names
}

func keysOfIdent() map[string]struct{} {
	out := make(map[string]struct{}, len(identifiers))
	for k := range identifiers {
		out[k] = struct{}{}
	}
	return out
}
func keysOfAuthz() map[string]struct{} {
	out := make(map[string]struct{}, len(authorizers))
	for k := range authorizers {
		out[k] = struct{}{}
	}
	return out
}
func keysOfMut() map[string]struct{} {
	out := make(map[string]struct{}, len(mutators))
	for k := range mutators {
		out[k] = struct{}{}
	}
	return out
}
