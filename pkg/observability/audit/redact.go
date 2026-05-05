// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// RedactionField specifies how a single audit event field is redacted.
// This mirrors config.RedactionField to avoid import cycles.
type RedactionField struct {
	Name   string
	Action RedactionAction
}

// RedactionAction is the transformation applied to a PII field.
type RedactionAction string

const (
	// RedactHash replaces the field value with HMAC-SHA-256.
	RedactHash RedactionAction = "hash"
	// RedactDrop replaces the field value with an empty string.
	RedactDrop RedactionAction = "drop"
)

// RedactingSink wraps an inner Sink, applying per-field PII redaction
// before forwarding events. Each event is shallow-copied so the
// original is never mutated (downstream sinks and metrics still see
// the raw values).
type RedactingSink struct {
	inner   Sink
	fields  []RedactionField
	hmacKey []byte
}

// NewRedactingSink creates a sink that applies the given redaction rules
// before forwarding to inner. hmacKey is used for "hash" actions; if
// empty, a zero-length key is used (still valid HMAC, but operators
// should set a real key for production correlation resistance).
func NewRedactingSink(inner Sink, fields []RedactionField, hmacKey []byte) *RedactingSink {
	return &RedactingSink{
		inner:   inner,
		fields:  fields,
		hmacKey: hmacKey,
	}
}

// Record shallow-copies the event, applies redaction, then forwards.
func (r *RedactingSink) Record(ctx context.Context, e *Event) {
	if len(r.fields) == 0 {
		r.inner.Record(ctx, e)
		return
	}
	// Shallow copy — all fields are value types (string, int, bool, time.Time).
	redacted := *e
	for _, f := range r.fields {
		r.applyField(&redacted, f)
	}
	r.inner.Record(ctx, &redacted)
}

func (r *RedactingSink) applyField(e *Event, f RedactionField) {
	ptr := r.fieldPtr(e, f.Name)
	if ptr == nil || *ptr == "" {
		return
	}
	switch f.Action {
	case RedactDrop:
		*ptr = ""
	case RedactHash:
		*ptr = r.hmacHash(*ptr)
	}
}

// fieldPtr returns a pointer to the named string field on Event, or nil
// if the field name is not recognised.
func (r *RedactingSink) fieldPtr(e *Event, name string) *string {
	switch name {
	case "subject":
		return &e.Subject
	case "path":
		return &e.Path
	case "host":
		return &e.Host
	case "deny_reason":
		return &e.DenyReason
	case "identity_source":
		return &e.IdentitySource
	case "trace_id":
		return &e.TraceID
	default:
		return nil
	}
}

// hmacHash returns the hex-encoded HMAC-SHA-256 of val.
func (r *RedactingSink) hmacHash(val string) string {
	mac := hmac.New(sha256.New, r.hmacKey)
	mac.Write([]byte(val))
	return hex.EncodeToString(mac.Sum(nil))
}
