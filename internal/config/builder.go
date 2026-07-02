// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"

	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// PipelineBuilder constructs a pipeline.Engine by composing modules from
// registries with optional decorators. It provides a testable, composable
// alternative to the monolithic Compile() function.
//
// Usage:
//
//	b := NewPipelineBuilder()
//	b.WithIdentifierDecorator(observability.WrapIdentifier)
//	engine, err := b.Build(authConfig)
type PipelineBuilder struct {
	identifiers *module.Registry[module.Identifier]
	authorizers *module.Registry[module.Authorizer]
	mutators    *module.Registry[module.ResponseMutator]

	identifierDecorators []module.IdentifierDecorator
	authorizerDecorators []module.AuthorizerDecorator
	mutatorDecorators    []module.MutatorDecorator

	// deps carries host-provided capabilities (cache pools, engine context)
	// injected into every module at construction. The zero value is valid:
	// modules then see no caches and fall back to a no-op provider.
	deps module.Deps
}

// NewPipelineBuilder creates a builder using the global module registries.
func NewPipelineBuilder() *PipelineBuilder {
	return &PipelineBuilder{
		identifiers: module.Identifiers,
		authorizers: module.Authorizers,
		mutators:    module.Mutators,
	}
}

// WithIdentifierRegistry overrides the identifier registry (for testing).
func (b *PipelineBuilder) WithIdentifierRegistry(r *module.Registry[module.Identifier]) *PipelineBuilder {
	b.identifiers = r
	return b
}

// WithAuthorizerRegistry overrides the authorizer registry (for testing).
func (b *PipelineBuilder) WithAuthorizerRegistry(r *module.Registry[module.Authorizer]) *PipelineBuilder {
	b.authorizers = r
	return b
}

// WithMutatorRegistry overrides the mutator registry (for testing).
func (b *PipelineBuilder) WithMutatorRegistry(r *module.Registry[module.ResponseMutator]) *PipelineBuilder {
	b.mutators = r
	return b
}

// WithDeps sets the host dependencies (cache pools, logger, engine context)
// injected into every module built by this builder.
func (b *PipelineBuilder) WithDeps(deps module.Deps) *PipelineBuilder {
	b.deps = deps
	return b
}

// WithIdentifierDecorator adds a decorator applied to every identifier
// after construction.
func (b *PipelineBuilder) WithIdentifierDecorator(d module.IdentifierDecorator) *PipelineBuilder {
	b.identifierDecorators = append(b.identifierDecorators, d)
	return b
}

// WithAuthorizerDecorator adds a decorator applied to every authorizer.
func (b *PipelineBuilder) WithAuthorizerDecorator(d module.AuthorizerDecorator) *PipelineBuilder {
	b.authorizerDecorators = append(b.authorizerDecorators, d)
	return b
}

// WithMutatorDecorator adds a decorator applied to every mutator.
func (b *PipelineBuilder) WithMutatorDecorator(d module.MutatorDecorator) *PipelineBuilder {
	b.mutatorDecorators = append(b.mutatorDecorators, d)
	return b
}

// BuildModules constructs the identifier, authorizer, and mutator slices
// from an AuthConfig using the configured registries and decorators.
// This is the modular, testable core that Compile() delegates heavy
// lifting to.
func (b *PipelineBuilder) BuildModules(ac *AuthConfig) ([]module.Identifier, module.Authorizer, []module.ResponseMutator, error) {
	idents, err := b.buildIdentifiers(ac.Identifiers)
	if err != nil {
		return nil, nil, nil, err
	}
	az, err := b.buildAuthorizer(ac.Authorizers)
	if err != nil {
		return nil, nil, nil, err
	}
	muts, err := b.buildMutators(ac.Response)
	if err != nil {
		return nil, nil, nil, err
	}
	return idents, az, muts, nil
}

func (b *PipelineBuilder) buildIdentifiers(specs []ModuleSpec) ([]module.Identifier, error) {
	idents := make([]module.Identifier, 0, len(specs))
	for _, spec := range specs {
		m, err := b.identifiers.Build(spec.Type, spec.Name, spec.Config, b.deps)
		if err != nil {
			return nil, fmt.Errorf("identifier %q: %w", spec.Name, err)
		}
		for _, d := range b.identifierDecorators {
			m = d(m)
		}
		idents = append(idents, m)
	}
	return idents, nil
}

func (b *PipelineBuilder) buildAuthorizer(specs []ModuleSpec) (module.Authorizer, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("%w: no authorizers configured", module.ErrConfig)
	}
	az, err := b.authorizers.Build(specs[0].Type, specs[0].Name, specs[0].Config, b.deps)
	if err != nil {
		return nil, fmt.Errorf("authorizer %q: %w", specs[0].Name, err)
	}
	for _, d := range b.authorizerDecorators {
		az = d(az)
	}
	return az, nil
}

func (b *PipelineBuilder) buildMutators(specs []ModuleSpec) ([]module.ResponseMutator, error) {
	muts := make([]module.ResponseMutator, 0, len(specs))
	for _, spec := range specs {
		m, err := b.mutators.Build(spec.Type, spec.Name, spec.Config, b.deps)
		if err != nil {
			return nil, fmt.Errorf("mutator %q: %w", spec.Name, err)
		}
		for _, d := range b.mutatorDecorators {
			m = d(m)
		}
		muts = append(muts, m)
	}
	return muts, nil
}

// Ensure PipelineBuilder doesn't import pipeline directly for the full
// Build — that stays in Compile(). This keeps PipelineBuilder focused
// on module construction only, avoiding the circular dependency risk.
var _ = pipeline.Options{} // compile-time import verification
