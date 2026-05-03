// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package wasm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

var (
	globalRuntime     *Runtime
	globalRuntimeOnce sync.Once
	globalRuntimeErr  error
)

// globalRT lazily initializes the shared WASM runtime.
func globalRT() (*Runtime, error) {
	globalRuntimeOnce.Do(func() {
		globalRuntime, globalRuntimeErr = NewRuntime(context.Background())
	})
	return globalRuntime, globalRuntimeErr
}

func init() {
	module.RegisterIdentifier("wasm", identifierFactory)
	module.RegisterAuthorizer("wasm", authorizerFactory)
	module.RegisterMutator("wasm", mutatorFactory)
}

func identifierFactory(name string, cfg map[string]any) (module.Identifier, error) {
	rt, err := globalRT()
	if err != nil {
		return nil, err
	}
	wcfg, err := parseConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("wasm identifier %q: %w", name, err)
	}
	mod, err := rt.Load(context.Background(), name, wcfg)
	if err != nil {
		return nil, err
	}
	return NewIdentifier(mod), nil
}

func authorizerFactory(name string, cfg map[string]any) (module.Authorizer, error) {
	rt, err := globalRT()
	if err != nil {
		return nil, err
	}
	wcfg, err := parseConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("wasm authorizer %q: %w", name, err)
	}
	mod, err := rt.Load(context.Background(), name, wcfg)
	if err != nil {
		return nil, err
	}
	return NewAuthorizer(mod), nil
}

func mutatorFactory(name string, cfg map[string]any) (module.ResponseMutator, error) {
	rt, err := globalRT()
	if err != nil {
		return nil, err
	}
	wcfg, err := parseConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("wasm mutator %q: %w", name, err)
	}
	mod, err := rt.Load(context.Background(), name, wcfg)
	if err != nil {
		return nil, err
	}
	return NewMutator(mod), nil
}

func parseConfig(cfg map[string]any) (Config, error) {
	var c Config

	if v, ok := cfg["path"].(string); ok {
		c.Path = v
	} else {
		return c, fmt.Errorf("'path' is required and must be a string")
	}

	if v, ok := cfg["maxMemoryMB"]; ok {
		switch n := v.(type) {
		case int:
			c.MaxMemoryMB = uint32(n)
		case float64:
			c.MaxMemoryMB = uint32(n)
		}
	}

	if v, ok := cfg["maxFuel"]; ok {
		switch n := v.(type) {
		case int:
			c.MaxFuel = uint64(n)
		case float64:
			c.MaxFuel = uint64(n)
		}
	}

	if v, ok := cfg["timeout"].(string); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("invalid timeout %q: %w", v, err)
		}
		c.Timeout = d
	}

	if v, ok := cfg["kind"].(string); ok {
		c.Kind = v
	}

	return c, nil
}
