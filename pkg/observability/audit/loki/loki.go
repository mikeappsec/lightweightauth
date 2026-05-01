// Package loki implements an audit.Sink that pushes events to a Grafana
// Loki instance via the HTTP push API (/loki/api/v1/push).
//
// Events are batched by time or count (whichever comes first) and sent
// as JSON streams. The sink is non-blocking: it enqueues into an
// internal AsyncSink and flushes batches on a background goroutine.
package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// Config for the Loki audit sink.
type Config struct {
	// URL is the Loki push endpoint (e.g. "http://loki:3100/loki/api/v1/push").
	URL string
	// Labels are static Loki stream labels applied to all events.
	Labels map[string]string
	// BatchSize is the max events per push request (default 100).
	BatchSize int
	// BatchWait is the max time to wait before flushing a partial batch (default 1s).
	BatchWait time.Duration
	// TenantID is the X-Scope-OrgID header value (optional, for multi-tenant Loki).
	TenantID string
	// Client is the HTTP client to use (default http.DefaultClient).
	Client *http.Client
}

// Sink pushes audit events to Loki.
type Sink struct {
	cfg    Config
	client *http.Client
	labels string

	mu    sync.Mutex
	batch []*audit.Event
	timer *time.Timer
	done  chan struct{}
}

// New creates a Loki audit sink. Call Close() on shutdown.
func New(cfg Config) *Sink {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchWait <= 0 {
		cfg.BatchWait = time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Second}
	}
	s := &Sink{
		cfg:    cfg,
		client: cfg.Client,
		labels: buildLabels(cfg.Labels),
		batch:  make([]*audit.Event, 0, cfg.BatchSize),
		done:   make(chan struct{}),
	}
	s.timer = time.AfterFunc(cfg.BatchWait, s.flushTimer)
	return s
}

// Record implements audit.Sink.
func (s *Sink) Record(_ context.Context, e *audit.Event) {
	s.mu.Lock()
	s.batch = append(s.batch, e)
	if len(s.batch) >= s.cfg.BatchSize {
		batch := s.batch
		s.batch = make([]*audit.Event, 0, s.cfg.BatchSize)
		s.timer.Reset(s.cfg.BatchWait)
		s.mu.Unlock()
		go s.push(batch) //nolint:errcheck
		return
	}
	s.mu.Unlock()
}

// Close flushes remaining events and stops the background timer.
func (s *Sink) Close() {
	s.timer.Stop()
	s.mu.Lock()
	batch := s.batch
	s.batch = nil
	s.mu.Unlock()
	if len(batch) > 0 {
		s.push(batch) //nolint:errcheck
	}
}

func (s *Sink) flushTimer() {
	s.mu.Lock()
	batch := s.batch
	s.batch = make([]*audit.Event, 0, s.cfg.BatchSize)
	s.mu.Unlock()
	if len(batch) > 0 {
		go s.push(batch) //nolint:errcheck
	}
	s.timer.Reset(s.cfg.BatchWait)
}

// push sends a batch to Loki. Best-effort: errors are silently dropped
// (the audit hot path must never block).
func (s *Sink) push(batch []*audit.Event) error {
	values := make([][2]string, len(batch))
	for i, e := range batch {
		line, _ := json.Marshal(e)
		values[i] = [2]string{
			strconv.FormatInt(e.Timestamp.UnixNano(), 10),
			string(line),
		}
	}

	payload := lokiPush{
		Streams: []lokiStream{{
			Stream: s.labels,
			Values: values,
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", s.cfg.TenantID)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("loki push: HTTP %d", resp.StatusCode)
	}
	return nil
}

// --- Loki push API types ---------------------------------------------------

type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream string     `json:"stream"`
	Values [][2]string `json:"values"`
}

func buildLabels(m map[string]string) string {
	if len(m) == 0 {
		return `{job="lwauth"}`
	}
	buf := bytes.Buffer{}
	buf.WriteByte('{')
	first := true
	for k, v := range m {
		if !first {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, "%s=%q", k, v)
		first = false
	}
	buf.WriteByte('}')
	return buf.String()
}
