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

// PromClient is a minimal HTTP client for the Prometheus
// /api/v1/query endpoint. It intentionally avoids pulling in
// github.com/prometheus/client_golang/api (kept to stdlib per
// Simplicity First): the engine only needs instant-vector queries
// matching the form the rule templates use (rate() / sum() / histogram_quantile
// over a [window]). Range queries are not required because the tick
// loop performs recurring instant measurements.
type PromClient struct {
	BaseURL string
	HTTP   *http.Client
}

// Empty returns true when the client has no Prometheus URL
// configured. Callers should treat this as a soft-degraded condition
// rather than an evaluation failure — the engine marks all
// Prometheus-backed rules as disabled-nilpotent for the tick.
func (c *PromClient) Empty() bool { return c == nil || c.BaseURL == "" }

// PromVector is one vector result row from /api/v1/query. The metric
// labels are the row identity; Value is a [unixTimestamp,
// stringifiedFloat] pair per Prometheus's JSON schema.
type PromVector struct {
	Metric map[string]string `json:"metric"`
	Value  [2]any            `json:"value"`
}

// promQueryResponse is the /api/v1/query response envelope.
type promQueryResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string       `json:"resultType"`
		Result     []PromVector `json:"result"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

// Query issues an instant PromQL query and returns the result vector.
// Returns ErrDegraded when the client is unconfigured (caller wraps as
// a degraded-rule marker); returns a normal error for HTTP/parse
// failures so the engine can choose to log without aborting the tick.
func (c *PromClient) Query(ctx context.Context, query string) ([]PromVector, error) {
	if c.Empty() {
		return nil, ErrDegraded
	}
	u := c.BaseURL + "/api/v1/query?" + url.Values{"query": []string{query}}.Encode()
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus query: status %d", resp.StatusCode)
	}
	var body promQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("prometheus decode: %w", err)
	}
	if body.Status != "success" {
		if body.Error != "" {
			return nil, fmt.Errorf("prometheus query: %s", body.Error)
		}
		return nil, fmt.Errorf("prometheus query: status %q", body.Status)
	}
	return body.Data.Result, nil
}

// Float extracts the value column of a PromVector and parses it as
// float64. The Prometheus API returns the value as a JSON string in
// the second position of the Value array; some proxies coercively
// re-marshal as a number, so both branches are tolerated.
func (v PromVector) Float() (float64, error) {
	if len(v.Value) < 2 {
		return 0, fmt.Errorf("prometheus vector: missing value")
	}
	switch s := v.Value[1].(type) {
	case string:
		return strconv.ParseFloat(s, 64)
	case float64:
		return s, nil
	case int64:
		return float64(s), nil
	default:
		return 0, fmt.Errorf("prometheus vector: unexpected value type %T", v.Value[1])
	}
}

// ExtractScope filters the row's labels down to the rule's
// ScopeLabels, augmented with a synthetic "cluster" key when the
// provenance label is absent (the engine assigns cluster from the
// control-plane config so dedup is stable across multi-cluster
// deployments). Label keys not present in the metric are absent in
// the returned scope (no zero-key noise).
func (v PromVector) ExtractScope(scopeLabels []string, cluster string) Scope {
	out := Scope{}
	for _, label := range scopeLabels {
		if label == "cluster" {
			// Always set cluster (fall back to the CP's own
			// cluster name when the metric lacks the label —
			// scalably identifies the source even in
			// single-cluster installs where Prom has no `cluster`).
			if v, ok := v.Metric["cluster"]; ok {
				out["cluster"] = v
			} else {
				out["cluster"] = cluster
			}
			continue
		}
		if val, ok := v.Metric[label]; ok {
			out[label] = val
		}
	}
	return out
}