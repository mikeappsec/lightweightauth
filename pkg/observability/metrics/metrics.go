// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package metrics is the lwauth Prometheus metrics surface (DESIGN.md M9).
//
// The package exposes a Recorder bundling every metric the pipeline,
// caches, and modules emit. A Recorder owns its own
// *prometheus.Registry so tests can assert on a clean surface; the
// process-wide default Recorder is what the pipeline reads on the hot
// path via Default().
//
// Naming follows Prometheus conventions:
//
//	lwauth_decisions_total{outcome,authorizer,tenant}
//	lwauth_decision_latency_seconds{outcome,authorizer,tenant}
//	lwauth_identifier_total{identifier,outcome}
//	lwauth_cache_hits_total{cache}
//	lwauth_cache_misses_total{cache}
//	lwauth_cache_evictions_total{cache}
//
// All histograms use seconds; all counters are monotonic.
package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mikeappsec/lightweightauth/pkg/buildinfo"
)

// Recorder bundles the lwauth metric set. The zero value is unusable;
// always construct via New.
type Recorder struct {
	registry *prometheus.Registry

	decisions            *prometheus.CounterVec
	decisionLatency      *prometheus.HistogramVec
	identifierTotal      *prometheus.CounterVec
	shadowDisagreements  *prometheus.CounterVec
	canaryAgreements     *prometheus.CounterVec
	revocationChecks     *prometheus.CounterVec
	cacheStaleServed     *prometheus.CounterVec
	cacheDistSF          *prometheus.CounterVec
	rateLimitDenied      *prometheus.CounterVec
}

// New constructs a Recorder against a fresh Registry. Pass the result to
// SetDefault to make the pipeline use it; tests typically construct an
// isolated Recorder, run a pipeline against it, and inspect the registry
// directly.
func New() *Recorder {
	reg := prometheus.NewRegistry()
	r := &Recorder{
		registry: reg,
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lwauth_decisions_total",
			Help: "Authorization decisions made by the pipeline.",
		}, []string{"outcome", "authorizer", "tenant"}),
		decisionLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "lwauth_decision_latency_seconds",
			Help:    "End-to-end latency of pipeline.Evaluate from request entry to decision.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16), // 100µs … ~3.3s
		}, []string{"outcome", "authorizer", "tenant"}),
		identifierTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lwauth_identifier_total",
			Help: "Identifier outcomes (match, no_match, error).",
		}, []string{"identifier", "outcome"}),
		shadowDisagreements: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lwauth_shadow_disagreement_total",
			Help: "Requests where a shadow policy would deny but production allows (D2).",
		}, []string{"policy_version", "tenant"}),
		canaryAgreements: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lwauth_canary_agreement_total",
			Help: "Canary vs production verdict agreement (D3).",
		}, []string{"policy_version", "tenant", "agreement"}),
		revocationChecks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lwauth_revocation_checks_total",
			Help: "Revocation checks performed by the pipeline (E2).",
		}, []string{"tenant", "result"}),
		cacheStaleServed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lwauth_cache_stale_served_total",
			Help: "Stale cache entries served during upstream outages (E3).",
		}, []string{"tenant", "decision"}),
		cacheDistSF: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lwauth_cache_distsf_total",
			Help: "Cross-replica singleflight outcomes (E4).",
		}, []string{"outcome"}),
		rateLimitDenied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lwauth_ratelimit_denied_total",
			Help: "Requests denied by per-tenant rate limiting / quota enforcement (E6).",
		}, []string{"tenant"}),
	}
	reg.MustRegister(r.decisions, r.decisionLatency, r.identifierTotal, r.shadowDisagreements, r.canaryAgreements, r.revocationChecks, r.cacheStaleServed, r.cacheDistSF, r.rateLimitDenied)

	// K-CRYPTO-2: lwauth_fips_enabled is a constant gauge (1 = the
	// running binary is using a FIPS 140-3 validated cryptographic
	// module, 0 = it is not). Operators alert on
	// `lwauth_fips_enabled{job="lwauth"} == 0` in regulated clusters
	// to catch a stock-image deploy slipping into a FIPS-only namespace.
	// Also exposes lwauth_build_info as a constant labelled gauge so
	// version / commit / go runtime are queryable via PromQL.
	fipsVal := 0.0
	if buildinfo.FIPSEnabled() {
		fipsVal = 1.0
	}
	fipsGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "lwauth_fips_enabled",
		Help: "1 if the running binary uses a FIPS 140-3 validated cryptographic module (GOFIPS140 or GOEXPERIMENT=boringcrypto build), 0 otherwise.",
	})
	fipsGauge.Set(fipsVal)
	buildGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "lwauth_build_info",
		Help: "Constant 1 with build attributes as labels.",
	}, []string{"version", "commit", "go_version", "fips"})
	buildGauge.WithLabelValues(
		buildinfo.Version,
		buildinfo.Commit,
		buildinfo.GoVersion(),
		boolLabel(buildinfo.FIPSEnabled()),
	).Set(1)
	reg.MustRegister(fipsGauge, buildGauge)
	return r
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Registry returns the underlying Prometheus registry. Useful for tests
// and for callers who want to embed lwauth metrics in their own scrape
// surface.
func (r *Recorder) Registry() *prometheus.Registry { return r.registry }

// Handler returns an http.Handler that serves the lwauth metrics in
// text/plain Prometheus format.
func (r *Recorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// ObserveDecision records one terminal pipeline decision.
//
// outcome is one of "allow", "deny", "error". authorizer is the name of
// the top-level authorizer module (or "" if the decision didn't reach
// the authorize stage). tenant is the request's TenantID; "" is fine.
func (r *Recorder) ObserveDecision(outcome, authorizer, tenant string, latency time.Duration) {
	if r == nil {
		return
	}
	r.decisions.WithLabelValues(outcome, authorizer, tenant).Inc()
	r.decisionLatency.WithLabelValues(outcome, authorizer, tenant).Observe(latency.Seconds())
}

// ObserveIdentifier records one identifier attempt.
//
// outcome is one of "match", "no_match", "error".
func (r *Recorder) ObserveIdentifier(identifier, outcome string) {
	if r == nil {
		return
	}
	r.identifierTotal.WithLabelValues(identifier, outcome).Inc()
}

// ObserveShadowDisagreement records a shadow-mode disagreement: the shadow
// pipeline would deny, but production allows. Tagged by policy_version and
// tenant so operators can pinpoint which policy revision triggers denials.
func (r *Recorder) ObserveShadowDisagreement(policyVersion, tenant string) {
	if r == nil {
		return
	}
	r.shadowDisagreements.WithLabelValues(policyVersion, tenant).Inc()
}

// ObserveCanaryAgreement records a canary vs production verdict comparison (D3).
// agreement is one of "match", "prod_allow_canary_deny", "prod_deny_canary_allow".
func (r *Recorder) ObserveCanaryAgreement(policyVersion, tenant, agreement string) {
	if r == nil {
		return
	}
	r.canaryAgreements.WithLabelValues(policyVersion, tenant, agreement).Inc()
}

// ObserveRevocationCheck records a revocation check (E2).
// result is one of "revoked", "not_revoked", "error".
func (r *Recorder) ObserveRevocationCheck(tenant, result string) {
	if r == nil {
		return
	}
	r.revocationChecks.WithLabelValues(tenant, result).Inc()
}

// ObserveCacheStaleServed records a stale cache entry being served during
// an upstream outage (E3). decision is "allow" or "deny".
func (r *Recorder) ObserveCacheStaleServed(tenant, decision string) {
	if r == nil {
		return
	}
	r.cacheStaleServed.WithLabelValues(tenant, decision).Inc()
}

// RecordCacheStaleServed is a package-level convenience that delegates to
// Default().ObserveCacheStaleServed.
func RecordCacheStaleServed(tenant, decision string) {
	Default().ObserveCacheStaleServed(tenant, decision)
}

// ObserveCacheDistSF records a distributed singleflight outcome (E4).
// outcome is "won" or "waited".
func (r *Recorder) ObserveCacheDistSF(outcome string) {
	if r == nil {
		return
	}
	r.cacheDistSF.WithLabelValues(outcome).Inc()
}

// RecordCacheDistSF is a package-level convenience that delegates to
// Default().ObserveCacheDistSF.
func RecordCacheDistSF(outcome string) {
	Default().ObserveCacheDistSF(outcome)
}

// ObserveRateLimitDenied records a request denied by rate limiting (E6).
func (r *Recorder) ObserveRateLimitDenied(tenant string) {
	if r == nil {
		return
	}
	r.rateLimitDenied.WithLabelValues(tenant).Inc()
}

// RecordRateLimitDenied is a package-level convenience that delegates to
// Default().ObserveRateLimitDenied.
func RecordRateLimitDenied(tenant string) {
	Default().ObserveRateLimitDenied(tenant)
}

// RecordRevocation is a package-level convenience that delegates to
// Default().ObserveRevocationCheck. Safe to call even if Default() is nil.
func RecordRevocation(tenant, result string) {
	Default().ObserveRevocationCheck(tenant, result)
}

// RegisterCacheStats wires a named cache's live atomic counters into the
// recorder using prometheus.CounterFunc — no polling, the registry pulls
// the current values at scrape time.
//
// Emits three series:
//
//	lwauth_cache_hits_total{cache=<name>}
//	lwauth_cache_misses_total{cache=<name>}
//	lwauth_cache_evictions_total{cache=<name>}
//
// Calling twice with the same name panics (Prometheus duplicate
// registration); callers wrap with recover() if they need idempotent
// registration across hot-reload.
func (r *Recorder) RegisterCacheStats(name string, hits, misses, evictions func() uint64) {
	if r == nil {
		return
	}
	r.registry.MustRegister(
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name:        "lwauth_cache_hits_total",
			Help:        "Cache hits by named cache.",
			ConstLabels: prometheus.Labels{"cache": name},
		}, func() float64 { return float64(hits()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name:        "lwauth_cache_misses_total",
			Help:        "Cache misses by named cache.",
			ConstLabels: prometheus.Labels{"cache": name},
		}, func() float64 { return float64(misses()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name:        "lwauth_cache_evictions_total",
			Help:        "Cache evictions by named cache.",
			ConstLabels: prometheus.Labels{"cache": name},
		}, func() float64 { return float64(evictions()) }),
	)
}

// RegisterTieredCacheStats wires a two-tier cache's per-layer counters into
// the recorder. Emits:
//
//	lwauth_cache_layer_hits_total{cache=<name>, layer="l1"|"l2"}
//	lwauth_cache_layer_misses_total{cache=<name>, layer="l1"|"l2"}
//
// These complement the aggregate lwauth_cache_hits_total / misses_total
// registered via RegisterCacheStats and let operators distinguish in-process
// hits from shared-store hits for capacity planning.
func (r *Recorder) RegisterTieredCacheStats(name string, l1Hits, l1Misses, l2Hits, l2Misses func() uint64) {
	if r == nil {
		return
	}
	r.registry.MustRegister(
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name:        "lwauth_cache_layer_hits_total",
			Help:        "Cache hits by named cache and layer.",
			ConstLabels: prometheus.Labels{"cache": name, "layer": "l1"},
		}, func() float64 { return float64(l1Hits()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name:        "lwauth_cache_layer_hits_total",
			Help:        "Cache hits by named cache and layer.",
			ConstLabels: prometheus.Labels{"cache": name, "layer": "l2"},
		}, func() float64 { return float64(l2Hits()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name:        "lwauth_cache_layer_misses_total",
			Help:        "Cache misses by named cache and layer.",
			ConstLabels: prometheus.Labels{"cache": name, "layer": "l1"},
		}, func() float64 { return float64(l1Misses()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name:        "lwauth_cache_layer_misses_total",
			Help:        "Cache misses by named cache and layer.",
			ConstLabels: prometheus.Labels{"cache": name, "layer": "l2"},
		}, func() float64 { return float64(l2Misses()) }),
	)
}

// --- process-wide default --------------------------------------------------

var (
	defaultMu sync.RWMutex
	def       *Recorder
)

// Default returns the process-wide Recorder. The first call to Default
// lazily creates one if SetDefault hasn't been called.
func Default() *Recorder {
	defaultMu.RLock()
	r := def
	defaultMu.RUnlock()
	if r != nil {
		return r
	}
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if def == nil {
		def = New()
	}
	return def
}

// SetDefault installs r as the process-wide Recorder. Pass nil to
// disable metrics emission entirely (the pipeline tolerates a nil
// Recorder).
func SetDefault(r *Recorder) {
	defaultMu.Lock()
	def = r
	defaultMu.Unlock()
}
