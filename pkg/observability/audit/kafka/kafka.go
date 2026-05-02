// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package kafka implements an audit.Sink that produces events to an
// Apache Kafka topic. Events are serialized as JSON and sent
// asynchronously. The sink is non-blocking and drops on back-pressure.
//
// This package uses a minimal Kafka producer interface so the actual
// client library (confluent-kafka-go, segmentio/kafka-go, etc.) can be
// injected by the operator.
package kafka

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// Producer is the minimal interface a Kafka client must satisfy.
// This decouples the audit sink from any specific Kafka library.
type Producer interface {
	// Produce sends a message to the configured topic. Implementations
	// must be safe for concurrent use. Errors are best-effort (the sink
	// will not retry).
	Produce(ctx context.Context, key, value []byte) error
}

// Config for the Kafka audit sink.
type Config struct {
	// Topic is the Kafka topic to produce to.
	Topic string
	// Producer is the Kafka client.
	Producer Producer
	// KeyFunc extracts the partition key from an event.
	// Default: tenant + subject (for locality).
	KeyFunc func(*audit.Event) []byte
}

// Sink produces audit events to Kafka.
type Sink struct {
	cfg Config
}

// New creates a Kafka audit sink.
func New(cfg Config) *Sink {
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = defaultKey
	}
	return &Sink{cfg: cfg}
}

// Record implements audit.Sink. Non-blocking best-effort.
func (s *Sink) Record(ctx context.Context, e *audit.Event) {
	value, err := json.Marshal(e)
	if err != nil {
		return
	}
	key := s.cfg.KeyFunc(e)
	// Best-effort: ignore errors to never block the auth hot path.
	_ = s.cfg.Producer.Produce(ctx, key, value)
}

// defaultKey returns a hashed partition key to avoid PII exposure.
func defaultKey(e *audit.Event) []byte {
	h := sha256.Sum256([]byte(e.Tenant + "/" + e.Subject))
	return []byte(hex.EncodeToString(h[:8]))
}
