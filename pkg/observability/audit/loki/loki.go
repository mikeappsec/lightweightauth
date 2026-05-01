// Package loki implements an audit.Sink that pushes events to a Grafana
// Loki instance via the HTTP push API (/loki/api/v1/push).
//
// Events are batched by time or count (whichever comes first) and sent
// as JSON streams. The sink is non-blocking and uses a bounded worker
// pool for concurrent push requests.
package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// labelKeyRe matches valid Prometheus/Loki label keys.
var labelKeyRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Config for the Loki audit sink.
type Config struct {
	// URL is the Loki push endpoint. Must use HTTPS unless InsecurePlaintext
	// is explicitly set.
	URL string
	// InsecurePlaintext allows HTTP URLs (dev/test only). Default false.
	InsecurePlaintext bool
	// Labels are static Loki stream labels applied to all events.
	// Keys must match ^[a-zA-Z_][a-zA-Z0-9_]*$.
	Labels map[string]string
	// BatchSize is the max events per push request (default 100).
	BatchSize int
	// BatchWait is the max time to wait before flushing a partial batch (default 1s).
	BatchWait time.Duration
	// TenantID is the X-Scope-OrgID header value (optional, for multi-tenant Loki).
	TenantID string
	// Client is the HTTP client to use (default http.DefaultClient).
	Client *http.Client
	// MaxConcurrentPushes limits background push goroutines. Default 8.
	MaxConcurrentPushes int
}

// Sink pushes audit events to Loki.
type Sink struct {
	cfg    Config
	client *http.Client
	labels string

	mu    sync.Mutex
	batch []*audit.Event
	timer *time.Timer
	sem   chan struct{} // bounded worker pool
}

// New creates a Loki audit sink. Returns an error if the config is invalid.
// Call Close() on shutdown.
func New(cfg Config) (*Sink, error) {
	// Security: Validate URL scheme (HTTPS required).
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("loki: invalid URL: %w", err)
	}
	if u.Scheme != "https" && !cfg.InsecurePlaintext {
		return nil, fmt.Errorf("loki: URL must use HTTPS (got %q); set InsecurePlaintext=true for dev", u.Scheme)
	}
	// Security: Block SSRF to cloud metadata endpoints.
	if err := validateLokiHost(u.Hostname()); err != nil {
		return nil, err
	}
	// Validate label keys and values.
	for k, v := range cfg.Labels {
		if !labelKeyRe.MatchString(k) {
			return nil, fmt.Errorf("loki: invalid label key %q (must match %s)", k, labelKeyRe.String())
		}
		for _, c := range v {
			if c < 0x20 || c == 0x7f {
				return nil, fmt.Errorf("loki: label value for %q contains control characters", k)
			}
		}
	}

	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchWait <= 0 {
		cfg.BatchWait = time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.MaxConcurrentPushes <= 0 {
		cfg.MaxConcurrentPushes = 8
	}
	s := &Sink{
		cfg:    cfg,
		client: cfg.Client,
		labels: buildLabels(cfg.Labels),
		batch:  make([]*audit.Event, 0, cfg.BatchSize),
		sem:    make(chan struct{}, cfg.MaxConcurrentPushes),
	}
	s.timer = time.AfterFunc(cfg.BatchWait, s.flushTimer)
	return s, nil
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
		s.asyncPush(batch)
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

// asyncPush sends a batch using the bounded worker pool.
func (s *Sink) asyncPush(batch []*audit.Event) {
	select {
	case s.sem <- struct{}{}:
		go func() {
			defer func() { <-s.sem }()
			s.push(batch) //nolint:errcheck
		}()
	default:
		// All workers busy — drop batch (back-pressure).
	}
}

func (s *Sink) flushTimer() {
	s.mu.Lock()
	batch := s.batch
	s.batch = make([]*audit.Event, 0, s.cfg.BatchSize)
	s.mu.Unlock()
	if len(batch) > 0 {
		s.asyncPush(batch)
	}
	s.timer.Reset(s.cfg.BatchWait)
}

// push sends a batch to Loki. Best-effort: errors are silently dropped.
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
	// Drain body for HTTP/1.1 connection reuse.
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("loki push: HTTP %d", resp.StatusCode)
	}
	return nil
}

// --- SSRF protection --------------------------------------------------------

func validateLokiHost(host string) error {
	blocked := []string{
		"169.254.169.254",
		"metadata.google.internal",
		"metadata.internal",
	}
	for _, b := range blocked {
		if host == b {
			return fmt.Errorf("loki: URL host %q is blocked (SSRF protection)", host)
		}
	}
	return nil
}

// --- Loki push API types ---------------------------------------------------

type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream string      `json:"stream"`
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
		// Keys are pre-validated by New(); values are %q-escaped.
		fmt.Fprintf(&buf, "%s=%q", k, v)
		first = false
	}
	buf.WriteByte('}')
	return buf.String()
}
