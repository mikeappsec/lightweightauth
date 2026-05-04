// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// DecodeConfig decodes the free-form config map into a typed struct T.
// It uses JSON round-trip for reliable type coercion (YAML numbers come
// in as float64/int, booleans, strings — all handled by encoding/json).
//
// Unknown keys are rejected automatically (replacing manual
// CheckUnknownKeys calls). Fields are matched by their `yaml` tag, with
// fallback to the JSON tag and then the lowercased field name.
//
// Example usage in a factory:
//
//	type Config struct {
//	    HeaderName string   `yaml:"headerName"`
//	    Required   bool     `yaml:"required"`
//	    Issuers    []string `yaml:"trustedIssuers"`
//	}
//
//	func factory(name string, raw map[string]any) (module.Identifier, error) {
//	    var cfg Config
//	    if err := module.DecodeConfig(raw, &cfg); err != nil {
//	        return nil, err
//	    }
//	    // use cfg.HeaderName, cfg.Required, etc.
//	}
func DecodeConfig(raw map[string]any, dest any) error {
	// Build the set of known keys from struct tags.
	known := knownKeysFromStruct(dest)

	// Check for unknown keys.
	var bad []string
	for k := range raw {
		if _, ok := known[k]; !ok {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: unknown config key(s): %s", ErrConfig, strings.Join(bad, ", "))
	}

	// JSON round-trip: map[string]any → JSON bytes → typed struct.
	// This handles all the numeric/bool/string coercions that YAML
	// parsing produces.
	b, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("%w: marshal config: %v", ErrConfig, err)
	}
	if err := json.Unmarshal(b, dest); err != nil {
		return fmt.Errorf("%w: decode config: %v", ErrConfig, err)
	}
	return nil
}

// knownKeysFromStruct extracts the set of acceptable config keys from
// the struct tags of dest. It looks at `yaml`, `json`, then falls back
// to the lowercased field name.
func knownKeysFromStruct(dest any) map[string]struct{} {
	t := reflect.TypeOf(dest)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	known := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		// Try yaml tag first, then json tag, then lowercased name.
		key := tagName(f, "yaml")
		if key == "" {
			key = tagName(f, "json")
		}
		if key == "" {
			// lowercase first char
			key = strings.ToLower(f.Name[:1]) + f.Name[1:]
		}
		known[key] = struct{}{}
	}
	return known
}

func tagName(f reflect.StructField, tag string) string {
	v := f.Tag.Get(tag)
	if v == "" || v == "-" {
		return ""
	}
	// Strip options (e.g. "name,omitempty")
	if idx := strings.Index(v, ","); idx != -1 {
		v = v[:idx]
	}
	if v == "-" {
		return ""
	}
	return v
}
