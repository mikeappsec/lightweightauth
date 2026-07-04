// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"time"
)

// Codec marshals values to and from the byte slices a [Cache] stores. It is
// a pool-level setting so a single backend is never read with mismatched
// encodings.
type Codec interface {
	// Name identifies the codec ("gob", "json") for diagnostics.
	Name() string
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
}

// Gob is the default codec: compact and Go-native, suited to an internal
// cache where every reader and writer is lwauth itself.
var Gob Codec = gobCodec{}

// JSON is the opt-in codec for operators who need cross-language readers or
// wire-debuggable values.
var JSON Codec = jsonCodec{}

type gobCodec struct{}

func (gobCodec) Name() string { return "gob" }

func (gobCodec) Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return nil, fmt.Errorf("cache: gob marshal: %w", err)
	}
	return buf.Bytes(), nil
}

func (gobCodec) Unmarshal(data []byte, v any) error {
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(v); err != nil {
		return fmt.Errorf("cache: gob unmarshal: %w", err)
	}
	return nil
}

type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cache: json marshal: %w", err)
	}
	return data, nil
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("cache: json unmarshal: %w", err)
	}
	return nil
}

// CodecByName resolves a pool's configured codec name to a [Codec],
// defaulting to [Gob] when empty.
func CodecByName(name string) (Codec, error) {
	switch name {
	case "", "gob":
		return Gob, nil
	case "json":
		return JSON, nil
	default:
		return nil, fmt.Errorf("%w: unknown codec %q (want gob or json)", ErrConfig, name)
	}
}

// Typed is a generic wrapper over a [Cache] that removes per-module
// marshaling boilerplate and centralizes the codec. Most modules cache
// structs (claims, decisions, keysets) rather than raw bytes.
type Typed[T any] struct {
	c     Cache
	codec Codec
}

// NewTyped wraps c with a typed codec. A nil codec defaults to [Gob].
func NewTyped[T any](c Cache, codec Codec) *Typed[T] {
	if codec == nil {
		codec = Gob
	}
	return &Typed[T]{c: c, codec: codec}
}

// Get returns the decoded value for key. ok=false is a clean miss.
func (t *Typed[T]) Get(ctx context.Context, key string) (T, bool, error) {
	var zero T
	raw, ok, err := t.c.Get(ctx, key)
	if err != nil || !ok {
		return zero, ok, err
	}
	var v T
	if err := t.codec.Unmarshal(raw, &v); err != nil {
		return zero, false, err
	}
	return v, true, nil
}

// Set encodes v and stores it under key for ttl.
func (t *Typed[T]) Set(ctx context.Context, key string, v T, ttl time.Duration) error {
	raw, err := t.codec.Marshal(v)
	if err != nil {
		return err
	}
	return t.c.Set(ctx, key, raw, ttl)
}

// Delete removes key from the underlying cache.
func (t *Typed[T]) Delete(ctx context.Context, key string) error {
	return t.c.Delete(ctx, key)
}
