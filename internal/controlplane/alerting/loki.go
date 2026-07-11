// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// LokiClient is a minimal HTTP client for the Loki /loki/api/v1/query_range
// endpoint. Like PromClient it intentionally avoids pulling in a
// Loki SDK (no official Go client outside Grafana's own tooling
// matches the stdlib ethos), and the engine only issues aggregate
// queries of the form `sum by (...) (count_over_time({...}[5m]))` —
// the loader query is a vector matrix per label set, so a single
// matrix parse is enough.
type LokiClient struct {
	BaseURL string
	HTTP    *http.Client
}

// Empty mirrors PromClient.Empty — true when no Loki URL was wired.
func (c *LokiClient) Empty() bool { return c == nil || c.BaseURL == "" }

// LokiStream is one stream result row from /loki/api/v1/query_range.
type LokiStream struct {
	Stream map[string]string `json:"stream"` // labels
	Values [][]any           `json:"values"` // [[unixNs, "line"], ...]
}

// lokiQueryRangeResponse is the /loki/api/v1/query_range response
// envelope. For matrix-valued queries (the only kind this client
// executes), the Result slice holds one LokiStream per label set
// expanded.
type lokiQueryRangeResponse struct {
	Status string       `json:"status"`
	Data   lokiDataBody `json:"data"`
	Error  string       `json:"error,omitempty"`
}

type lokiDataBody struct {
	ResultType string       `json:"resultType"` // "matrix" expected
	Result     []LokiStream `json:"result"`
}

// QueryRange issues a range LogQL query for the past step count of
// `window` and returns the matrix rows. The engine uses just the
// final sample of each row (the most recent measurement) so the math
// mirrors PromClient's instant-vector path.
func (c *LokiClient) QueryRange(ctx context.Context, query string, window time.Duration) ([]LokiStream, error) {
	if c.Empty() {
		return nil, ErrDegraded
	}
	end := time.Now()
	start := end.Add(-window)
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	q.Set("step", strconv.FormatInt(int64(window.Seconds())+1, 10)+"s")
	q.Set("limit", "1000")
	u := c.BaseURL + "/loki/api/v1/query_range?" + q.Encode()
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki query: status %d", resp.StatusCode)
	}
	var body lokiQueryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("loki decode: %w", err)
	}
	if body.Status != "success" {
		if body.Error != "" {
			return nil, fmt.Errorf("loki query: %s", body.Error)
		}
		return nil, fmt.Errorf("loki query: status %q", body.Status)
	}
	return body.Data.Result, nil
}

// LatestValue parses the last sample of a LokiStream.Values as a
// float64. Count/rate LogQL queries emit numeric line bodies, so the
// parse goes through strconv.ParseFloat and returns an error for
// non-numeric lines (these are not breaches; the caller treats them
// as zero).
func (s LokiStream) LatestValue() (float64, error) {
	if len(s.Values) == 0 {
		return 0, fmt.Errorf("loki stream: no samples")
	}
	last := s.Values[len(s.Values)-1]
	if len(last) < 2 {
		return 0, fmt.Errorf("loki stream: malformed sample")
	}
	switch v := last[1].(type) {
	case string:
		return strconv.ParseFloat(v, 64)
	case float64:
		return v, nil
	default:
		return 0, fmt.Errorf("loki stream: unexpected sample type %T", last[1])
	}
}

// ExtractScope filters the Loki stream's labels down to the rule's
// ScopeLabels, augmented with a synthetic "cluster" key when absent
// (mirror of PromVector.ExtractScope).
func (s LokiStream) ExtractScope(scopeLabels []string, cluster string) Scope {
	out := Scope{}
	for _, label := range scopeLabels {
		if label == "cluster" {
			if v, ok := s.Stream["cluster"]; ok {
				out["cluster"] = v
			} else {
				out["cluster"] = cluster
			}
			continue
		}
		if v, ok := s.Stream[label]; ok {
			out[label] = v
		}
	}
	return out
}