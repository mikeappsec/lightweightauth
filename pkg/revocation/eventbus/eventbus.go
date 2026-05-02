// Package eventbus provides a cross-replica event fan-out mechanism
// using Valkey Pub/Sub. It carries typed events (revocation, cache
// invalidation, config updates) on a single shared channel so all
// replicas can react to state changes.
//
// This is the foundation for E2 (revocation) and will be extended by
// E3 (tag-based invalidation) — both share the same subscriber goroutine.
package eventbus

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
)

// EventType identifies the kind of event being published.
type EventType string

const (
	// EventRevoke signals that a credential has been revoked.
	EventRevoke EventType = "revoke"

	// EventInvalidate signals that cache entries should be purged.
	// Used by E3 (tag-based invalidation).
	EventInvalidate EventType = "invalidate"
)

// Event is the wire format published on the shared channel.
type Event struct {
	Type EventType `json:"type"`

	// Key is the revocation key (for EventRevoke).
	Key string `json:"key,omitempty"`

	// Keys is a batch of keys (for bulk operations).
	Keys []string `json:"keys,omitempty"`

	// Tags are cache invalidation tags (for EventInvalidate, E3).
	Tags []string `json:"tags,omitempty"`
}

// Handler is a callback invoked for each received event.
type Handler func(Event)

// Bus is the cross-replica event bus. In Valkey mode it publishes and
// subscribes on a shared Pub/Sub channel. In memory mode (for tests /
// single-replica), events are dispatched synchronously to local handlers.
type Bus struct {
	client  valkey.Client
	channel string
	logger  *slog.Logger
	hmacKey []byte // HMAC-SHA256 signing key for message authentication

	mu       sync.RWMutex
	handlers []Handler

	cancel context.CancelFunc
	done   chan struct{}
}

// Config configures the event bus.
type Config struct {
	// Addr is the Valkey server address. Empty means memory-only mode.
	Addr string

	// Username for ACL authentication (optional).
	Username string

	// Password for authentication (optional).
	Password string

	// TLS enables TLS connections.
	TLS bool

	// Channel is the Pub/Sub channel name. Defaults to "lwauth/events".
	Channel string

	// HMACSecret is the shared secret used to sign and verify Pub/Sub
	// messages. When non-empty, messages are signed on publish and
	// verified on subscribe — unsigned or tampered messages are dropped.
	// When empty, a random 32-byte secret is generated at startup
	// (single-replica only — cross-replica requires a shared secret).
	HMACSecret []byte

	// Logger for subscription errors. Defaults to slog.Default().
	Logger *slog.Logger
}

// New creates an event bus. If cfg.Addr is empty, creates a local-only
// bus (events only reach handlers on this replica). Otherwise connects
// to Valkey for cross-replica fan-out.
func New(cfg Config) (*Bus, error) {
	if cfg.Channel == "" {
		cfg.Channel = "lwauth/events"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Derive HMAC key: use provided secret, or generate a random one.
	hmacKey := cfg.HMACSecret
	if len(hmacKey) == 0 {
		hmacKey = make([]byte, 32)
		if _, err := rand.Read(hmacKey); err != nil {
			return nil, fmt.Errorf("eventbus: generate hmac key: %w", err)
		}
	}

	b := &Bus{
		channel: cfg.Channel,
		logger:  cfg.Logger,
		hmacKey: hmacKey,
		done:    make(chan struct{}),
	}

	if cfg.Addr == "" {
		// Local-only mode — no Valkey connection.
		return b, nil
	}

	opt := valkey.ClientOption{
		InitAddress: []string{cfg.Addr},
		Username:    cfg.Username,
		Password:    cfg.Password,
	}
	if cfg.TLS {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("eventbus: dial %s: %w", cfg.Addr, err)
	}
	b.client = client

	// Start the subscription loop.
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	go b.subscribe(ctx)

	return b, nil
}

// Subscribe registers a handler that is called for every event
// received on this bus (both local and remote).
func (b *Bus) Subscribe(h Handler) {
	b.mu.Lock()
	b.handlers = append(b.handlers, h)
	b.mu.Unlock()
}

// Publish sends an event. In Valkey mode this publishes to the channel
// so all replicas receive it. In local-only mode it dispatches directly
// to registered handlers. Messages are HMAC-signed to prevent forgery.
func (b *Bus) Publish(ctx context.Context, e Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("eventbus: marshal: %w", err)
	}

	if b.client == nil {
		// Local-only: dispatch directly (no signing needed).
		b.dispatch(e)
		return nil
	}

	// Sign the message: payload.hmac-hex
	signed := b.sign(data)

	cmd := b.client.B().Publish().Channel(b.channel).Message(signed).Build()
	if err := b.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("eventbus: publish: %w", err)
	}
	return nil
}

// Close stops the subscriber and releases resources.
func (b *Bus) Close() error {
	if b.cancel != nil {
		b.cancel()
	}
	// Wait for subscriber to exit.
	select {
	case <-b.done:
	case <-time.After(5 * time.Second):
	}
	if b.client != nil {
		b.client.Close()
	}
	return nil
}

// subscribe is the background Pub/Sub listener. It reconnects on error.
func (b *Bus) subscribe(ctx context.Context) {
	defer close(b.done)

	for {
		if ctx.Err() != nil {
			return
		}
		err := b.client.Receive(ctx, b.client.B().Subscribe().Channel(b.channel).Build(),
			func(msg valkey.PubSubMessage) {
				// Verify HMAC signature before processing.
				payload, ok := b.verify(msg.Message)
				if !ok {
					b.logger.Warn("eventbus: dropped message with invalid signature")
					return
				}
				var e Event
				if err := json.Unmarshal(payload, &e); err != nil {
					b.logger.Warn("eventbus: unmarshal event", "err", err)
					return
				}
				b.dispatch(e)
			},
		)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			b.logger.Warn("eventbus: subscribe error, reconnecting", "err", err)
			// Back off before reconnect.
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
	}
}

// sign produces "base64-payload.hmac-hex" for the given data.
func (b *Bus) sign(data []byte) string {
	mac := hmac.New(sha256.New, b.hmacKey)
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))
	return string(data) + "." + sig
}

// verify checks a signed message and returns the raw payload if valid.
func (b *Bus) verify(msg string) ([]byte, bool) {
	idx := strings.LastIndex(msg, ".")
	if idx < 0 || idx == len(msg)-1 {
		return nil, false
	}
	payload := []byte(msg[:idx])
	sigHex := msg[idx+1:]

	expectedMac := hmac.New(sha256.New, b.hmacKey)
	expectedMac.Write(payload)
	expected := hex.EncodeToString(expectedMac.Sum(nil))

	if !hmac.Equal([]byte(sigHex), []byte(expected)) {
		return nil, false
	}
	return payload, true
}

// dispatch fans out an event to all registered handlers.
func (b *Bus) dispatch(e Event) {
	b.mu.RLock()
	handlers := b.handlers
	b.mu.RUnlock()
	for _, h := range handlers {
		h(e)
	}
}
