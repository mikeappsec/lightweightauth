package revocation

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
)

// ValkeyStore is a revocation store backed by a shared Valkey instance.
// Each revocation entry is stored as a key with a TTL (SET + EX), and
// existence checks use EXISTS. This allows multiple LightweightAuth
// replicas to share revocation state.
type ValkeyStore struct {
	client     valkey.Client
	keyPrefix  string
	defaultTTL time.Duration
}

// ValkeyConfig configures the Valkey revocation backend.
type ValkeyConfig struct {
	// Addr is the Valkey server address (host:port).
	Addr string

	// Username for ACL authentication (optional).
	Username string

	// Password for authentication (optional).
	Password string

	// TLS enables TLS connections to Valkey.
	TLS bool

	// KeyPrefix namespaces revocation keys (e.g. "lwauth/rev/").
	KeyPrefix string

	// DefaultTTL is the default lifetime for revocation entries.
	// Defaults to 24h.
	DefaultTTL time.Duration
}

// NewValkeyStore creates a Valkey-backed revocation store.
func NewValkeyStore(cfg ValkeyConfig) (*ValkeyStore, error) {
	if cfg.Addr == "" {
		return nil, errors.New("revocation/valkey: addr is required")
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 24 * time.Hour
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "lwauth/rev/"
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
		return nil, fmt.Errorf("revocation/valkey: dial %s: %w", cfg.Addr, err)
	}

	// Fail fast on misconfiguration.
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Do(pingCtx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("revocation/valkey: ping %s: %w", cfg.Addr, err)
	}

	return &ValkeyStore{
		client:     client,
		keyPrefix:  cfg.KeyPrefix,
		defaultTTL: cfg.DefaultTTL,
	}, nil
}

// NewValkeyStoreFromClient creates a ValkeyStore using a pre-built client.
// Used by tests and shared-client scenarios.
func NewValkeyStoreFromClient(client valkey.Client, keyPrefix string, defaultTTL time.Duration) *ValkeyStore {
	if defaultTTL <= 0 {
		defaultTTL = 24 * time.Hour
	}
	if keyPrefix == "" {
		keyPrefix = "lwauth/rev/"
	}
	return &ValkeyStore{client: client, keyPrefix: keyPrefix, defaultTTL: defaultTTL}
}

func (s *ValkeyStore) prefixed(key string) string {
	return s.keyPrefix + key
}

// Add records a revocation in Valkey as a key with TTL.
// The value stored is the reason (or empty string).
func (s *ValkeyStore) Add(ctx context.Context, e Entry) error {
	ttl := e.TTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	val := e.Reason
	if val == "" {
		val = "revoked"
	}
	cmd := s.client.B().Set().
		Key(s.prefixed(e.Key)).
		Value(val).
		PxMilliseconds(ttl.Milliseconds()).
		Build()
	if err := s.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("revocation/valkey: add %s: %w", e.Key, err)
	}
	return nil
}

// Exists checks whether a revocation key is present.
func (s *ValkeyStore) Exists(ctx context.Context, key string) (bool, error) {
	resp := s.client.Do(ctx, s.client.B().Exists().Key(s.prefixed(key)).Build())
	n, err := resp.AsInt64()
	if err != nil {
		return false, fmt.Errorf("revocation/valkey: exists %s: %w", key, err)
	}
	return n > 0, nil
}

// Remove deletes a revocation entry.
func (s *ValkeyStore) Remove(ctx context.Context, key string) error {
	if err := s.client.Do(ctx, s.client.B().Del().Key(s.prefixed(key)).Build()).Error(); err != nil {
		return fmt.Errorf("revocation/valkey: del %s: %w", key, err)
	}
	return nil
}

// List returns revocation entries matching the given prefix using SCAN,
// with pagination. Cursor is the Valkey SCAN cursor (as string). Limit
// caps results per page.
func (s *ValkeyStore) List(ctx context.Context, prefix string, limit int, cursor string) ([]Entry, string, error) {
	if limit <= 0 || limit > DefaultListLimit {
		limit = DefaultListLimit
	}
	pattern := s.prefixed(prefix) + "*"
	var entries []Entry

	// Parse cursor (Valkey SCAN cursor is uint64).
	var scanCursor uint64
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "%d", &scanCursor); err != nil {
			return nil, "", fmt.Errorf("revocation/valkey: invalid cursor: %w", err)
		}
	}

	resp := s.client.Do(ctx, s.client.B().Scan().Cursor(scanCursor).Match(pattern).Count(int64(limit)).Build())
	se, err := resp.AsScanEntry()
	if err != nil {
		return nil, "", fmt.Errorf("revocation/valkey: scan %s: %w", prefix, err)
	}
	for _, k := range se.Elements {
		if len(entries) >= limit {
			break
		}
		logicalKey := k
		if len(k) > len(s.keyPrefix) {
			logicalKey = k[len(s.keyPrefix):]
		}
		val, getErr := s.client.Do(ctx, s.client.B().Get().Key(k).Build()).ToString()
		reason := ""
		if getErr == nil {
			reason = val
		}
		entries = append(entries, Entry{Key: logicalKey, Reason: reason})
	}

	nextCursor := ""
	if se.Cursor != 0 {
		nextCursor = fmt.Sprintf("%d", se.Cursor)
	}
	return entries, nextCursor, nil
}

// Close releases the underlying Valkey client.
func (s *ValkeyStore) Close() error {
	if s.client != nil {
		s.client.Close()
	}
	return nil
}
