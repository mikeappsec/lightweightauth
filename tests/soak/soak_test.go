//go:build soak

// Package soak is the M12 sustained-load test promised by DESIGN.md §M12
// item 3. It drives the authorize hot path through both the HTTP
// (Door A) and gRPC native (Door B) servers at a configurable RPS for
// a configurable duration and asserts:
//
//   - zero non-deterministic errors (a 503 never occurs against an
//     in-process synthetic config);
//   - p99 end-to-end latency under a configurable bound;
//   - the Engine pointer in the holder doesn't drift to nil (regression
//     guard for swap-while-serving paths reaching the soak harness);
//   - the goroutine count is the same +- a small slack at end-of-soak
//     vs start-of-soak (catches hot-path leaks the per-package goleak
//     can't because we hit the live mux & gRPC stack).
//
// Build-tagged: a 30-minute soak is the wrong default for `go test`,
// and `go test -tags soak` is the same opt-in pattern envtest uses.
//
// Tunables (env):
//
//	SOAK_RPS         per-door target requests/sec   (default 1000)
//	SOAK_DURATION    e.g. "30s", "5m", "30m"        (default "10s")
//	SOAK_P99_MS      latency budget per request     (default 25)
//	SOAK_WORKERS     concurrent workers per door    (default 32)
//
// CI runs `make soak` with the defaults. A nightly job is expected to
// override SOAK_DURATION=30m for the headline 30-min run.
package soak_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDur(name, def string) time.Duration {
	d, err := time.ParseDuration(envOr(name, def))
	if err != nil {
		panic(err)
	}
	return d
}

// soakConfig is the in-process synthetic config: apikey + rbac + a
// 1-minute decision cache. No external services. The cache hit rate is
// effectively 100% (every request reuses the same key) so this also
// exercises the cache-on-hot-path code, which is what most production
// deployments will hit.
func soakConfig() *config.AuthConfig {
	return &config.AuthConfig{
		TenantID:   "soak",
		Identifier: config.IdentifierFirstMatch,
		Identifiers: []config.ModuleSpec{{
			Name: "apikey",
			Type: "apikey",
			Config: map[string]any{
				"headerName": "X-Api-Key",
				"static": map[string]any{
					"soak-key": map[string]any{"subject": "alice", "roles": []any{"admin"}},
				},
			},
		}},
		Authorizers: []config.ModuleSpec{{
			Name:   "rbac",
			Type:   "rbac",
			Config: map[string]any{"rolesFrom": "claim:roles", "allow": []any{"admin"}},
		}},
		Cache: &config.CacheSpec{
			TTL:         "60s",
			NegativeTTL: "1s",
		},
	}
}

type result struct {
	latencies []time.Duration
	errors    atomic.Int64
	denies    atomic.Int64
}

func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	idx := int(float64(len(ds)-1) * p)
	return ds[idx]
}

func runHTTPSoak(t *testing.T, srv *httptest.Server, rps, workers int, dur time.Duration) *result {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"method":   "GET",
		"host":     "soak.example",
		"path":     "/v1/things",
		"headers":  map[string][]string{"X-Api-Key": {"soak-key"}},
		"tenantId": "soak",
	})
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: workers,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	res := &result{latencies: make([]time.Duration, 0, rps*int(dur/time.Second)+1)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	perWorkerInterval := time.Second * time.Duration(workers) / time.Duration(rps)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(perWorkerInterval)
			defer ticker.Stop()
			for time.Now().Before(deadline) {
				<-ticker.C
				start := time.Now()
				resp, err := httpClient.Post(srv.URL+"/v1/authorize", "application/json", bytes.NewReader(body))
				lat := time.Since(start)
				if err != nil {
					res.errors.Add(1)
					continue
				}
				var ar struct{ Allow bool }
				_ = json.NewDecoder(resp.Body).Decode(&ar)
				resp.Body.Close()
				if !ar.Allow {
					res.denies.Add(1)
				}
				mu.Lock()
				res.latencies = append(res.latencies, lat)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return res
}

func runGRPCSoak(t *testing.T, cc *grpc.ClientConn, rps, workers int, dur time.Duration) *result {
	t.Helper()
	client := authv1.NewAuthClient(cc)
	req := &authv1.AuthorizeRequest{
		Method:   "GET",
		Resource: "/v1/things",
		Headers:  map[string]string{"X-Api-Key": "soak-key"},
		TenantId: "soak",
	}

	res := &result{latencies: make([]time.Duration, 0, rps*int(dur/time.Second)+1)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	perWorkerInterval := time.Second * time.Duration(workers) / time.Duration(rps)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(perWorkerInterval)
			defer ticker.Stop()
			for time.Now().Before(deadline) {
				<-ticker.C
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				start := time.Now()
				resp, err := client.Authorize(ctx, req)
				lat := time.Since(start)
				cancel()
				if err != nil {
					res.errors.Add(1)
					continue
				}
				if !resp.Allow {
					res.denies.Add(1)
				}
				mu.Lock()
				res.latencies = append(res.latencies, lat)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return res
}

// reportAndAssert prints headline numbers and fails the test on
// invariant violations.
func reportAndAssert(t *testing.T, door string, res *result, p99Budget time.Duration) {
	t.Helper()
	p50 := percentile(res.latencies, 0.50)
	p95 := percentile(res.latencies, 0.95)
	p99 := percentile(res.latencies, 0.99)
	t.Logf("[%s] %d ok / %d errors / %d denies | p50=%s p95=%s p99=%s",
		door, len(res.latencies), res.errors.Load(), res.denies.Load(), p50, p95, p99)

	if got := res.errors.Load(); got != 0 {
		t.Errorf("[%s] %d errors during soak; expected 0", door, got)
	}
	if got := res.denies.Load(); got != 0 {
		t.Errorf("[%s] %d denies during soak; the synthetic config allows everything", door, got)
	}
	if p99 > p99Budget {
		t.Errorf("[%s] p99=%s > budget=%s", door, p99, p99Budget)
	}
	if len(res.latencies) == 0 {
		t.Errorf("[%s] zero successful requests", door)
	}
}

// TestSoak_DoorA_HTTP soaks the HTTP /v1/authorize handler.
func TestSoak_DoorA_HTTP(t *testing.T) {
	rps := envInt("SOAK_RPS", 1000)
	workers := envInt("SOAK_WORKERS", 32)
	dur := envDur("SOAK_DURATION", "10s")
	p99Budget := time.Duration(envInt("SOAK_P99_MS", 25)) * time.Millisecond

	eng, err := config.Compile(soakConfig())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	holder := server.NewEngineHolder(eng)
	srv := httptest.NewServer(server.NewHTTPHandler(holder))
	defer srv.Close()

	startGoroutines := runtime.NumGoroutine()
	res := runHTTPSoak(t, srv, rps, workers, dur)
	reportAndAssert(t, "Door A / HTTP", res, p99Budget)

	if holder.Load() == nil {
		t.Errorf("engine pointer drifted to nil during soak")
	}
	// Allow generous slack: httptest's server, the http.Transport idle
	// pool, and Go's net poller all keep helper goroutines alive past
	// our last request. We only care about a clear runaway, so 256
	// is comfortably above the steady-state cost.
	if delta := runtime.NumGoroutine() - startGoroutines; delta > 256 {
		t.Errorf("goroutine count grew by %d during soak (start=%d, end=%d) -- possible leak",
			delta, startGoroutines, runtime.NumGoroutine())
	}
}

// TestSoak_DoorB_GRPC soaks the unary gRPC Authorize RPC.
func TestSoak_DoorB_GRPC(t *testing.T) {
	rps := envInt("SOAK_RPS", 1000)
	workers := envInt("SOAK_WORKERS", 32)
	dur := envDur("SOAK_DURATION", "10s")
	p99Budget := time.Duration(envInt("SOAK_P99_MS", 25)) * time.Millisecond

	eng, err := config.Compile(soakConfig())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	holder := server.NewEngineHolder(eng)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	authv1.RegisterAuthServer(gs, server.NewNativeAuthServer(holder))
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	cc, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	startGoroutines := runtime.NumGoroutine()
	res := runGRPCSoak(t, cc, rps, workers, dur)
	reportAndAssert(t, "Door B / gRPC", res, p99Budget)

	if holder.Load() == nil {
		t.Errorf("engine pointer drifted to nil during soak")
	}
	if delta := runtime.NumGoroutine() - startGoroutines; delta > 256 {
		t.Errorf("goroutine count grew by %d during soak (start=%d, end=%d) -- possible leak",
			delta, startGoroutines, runtime.NumGoroutine())
	}
}