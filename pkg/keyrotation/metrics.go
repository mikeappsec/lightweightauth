package keyrotation

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics provides Prometheus instrumentation for key rotation.
// Register once per process; the identity modules increment counters
// on every verify attempt.
var Metrics = struct {
	VerifyTotal  *prometheus.CounterVec
	RefreshTotal *prometheus.CounterVec
	KeyState     *prometheus.GaugeVec
}{
	// VerifyTotal counts verification attempts per (module, kid, result).
	// result is "ok", "expired_key", "unknown_kid", "invalid_sig".
	VerifyTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lwauth",
		Subsystem: "key",
		Name:      "verify_total",
		Help:      "Verification attempts by module, kid, and result.",
	}, []string{"module", "kid", "result"}),

	// RefreshTotal counts JWKS/CA-bundle refresh events per (module, outcome).
	// outcome is "success", "error", "kid_miss_trigger".
	RefreshTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lwauth",
		Subsystem: "key",
		Name:      "refresh_total",
		Help:      "Key material refresh events by module and outcome.",
	}, []string{"module", "outcome"}),

	// KeyState tracks current key count by (module, state).
	// state is "active", "pending", "retiring", "retired".
	KeyState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "lwauth",
		Subsystem: "key",
		Name:      "state",
		Help:      "Number of keys in each lifecycle state by module.",
	}, []string{"module", "state"}),
}

func init() {
	// Use Register (not MustRegister) to avoid panics on duplicate
	// import in tests or plugin binaries (KR7).
	prometheus.Register(Metrics.VerifyTotal)  //nolint:errcheck
	prometheus.Register(Metrics.RefreshTotal) //nolint:errcheck
	prometheus.Register(Metrics.KeyState)     //nolint:errcheck
}
