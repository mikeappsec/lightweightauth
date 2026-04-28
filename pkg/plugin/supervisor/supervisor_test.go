package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain runs a sub-process branch when the LWAUTH_SUPERVISOR_HELPER
// env var is set; otherwise it runs the regular test suite. This lets
// the tests below exec a real child via os.Args[0] without shipping a
// separate helper binary.
func TestMain(m *testing.M) {
	switch os.Getenv("LWAUTH_SUPERVISOR_HELPER") {
	case "":
		os.Exit(m.Run())
	case "sleep":
		// Run forever (until killed by the supervisor).
		select {}
	case "sleep_then_exit":
		// Live for a configurable duration then exit cleanly. Lets
		// crash-restart tests deterministically observe a restart.
		ms, _ := strconv.Atoi(os.Getenv("LWAUTH_SUPERVISOR_HELPER_MS"))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		os.Exit(0)
	case "exit_immediately":
		os.Exit(0)
	case "exit_nonzero":
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper role: %q\n", os.Getenv("LWAUTH_SUPERVISOR_HELPER"))
		os.Exit(99)
	}
}

func helperConfig(role string, extraEnv ...string) Config {
	env := append(os.Environ(), "LWAUTH_SUPERVISOR_HELPER="+role)
	env = append(env, extraEnv...)
	return Config{
		Name:    "test-" + role,
		Command: os.Args[0],
		Args:    []string{"-test.run=^$"}, // suppress any sub-test discovery
		Env:     env,
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func quietConfig(c Config) Config {
	c.Logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	return c
}

// ----- validation ----------------------------------------------------

func TestValidate_RequiredFields(t *testing.T) {
	cases := map[string]Config{
		"name":     {Command: "x", HealthProbe: okProbe},
		"command":  {Name: "x", HealthProbe: okProbe},
		"probe":    {Name: "x", Command: "x"},
		"timeout>interval": {
			Name: "x", Command: "x", HealthProbe: okProbe,
			HealthCheck: HealthCheckConfig{Interval: 10 * time.Millisecond, Timeout: 100 * time.Millisecond, FailureThreshold: 1},
		},
		"jitter>1": {
			Name: "x", Command: "x", HealthProbe: okProbe,
			Restart: RestartConfig{Jitter: 1.5},
		},
		"maxBackoff<initial": {
			Name: "x", Command: "x", HealthProbe: okProbe,
			Restart: RestartConfig{InitialBackoff: time.Second, MaxBackoff: 100 * time.Millisecond},
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestValidate_AppliesDefaults(t *testing.T) {
	c := Config{Name: "x", Command: "x", HealthProbe: okProbe}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.GracefulTimeout != 5*time.Second {
		t.Errorf("GracefulTimeout default = %s", c.GracefulTimeout)
	}
	if c.HealthCheck.Interval != 5*time.Second {
		t.Errorf("Interval default = %s", c.HealthCheck.Interval)
	}
	if c.HealthCheck.Timeout != time.Second {
		t.Errorf("Timeout default = %s", c.HealthCheck.Timeout)
	}
	if c.HealthCheck.FailureThreshold != 3 {
		t.Errorf("FailureThreshold default = %d", c.HealthCheck.FailureThreshold)
	}
	if c.Restart.InitialBackoff != 200*time.Millisecond {
		t.Errorf("InitialBackoff default = %s", c.Restart.InitialBackoff)
	}
	if c.Restart.MaxBackoff != 30*time.Second {
		t.Errorf("MaxBackoff default = %s", c.Restart.MaxBackoff)
	}
}

func okProbe(ctx context.Context, _ string) error  { return nil }
func badProbe(ctx context.Context, _ string) error { return errors.New("nope") }

// ----- backoff -------------------------------------------------------

func TestComputeBackoff_ExponentialCappedAtMax(t *testing.T) {
	cfg := Config{
		Name: "x", Command: "x", HealthProbe: okProbe,
		Restart: RestartConfig{
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     1 * time.Second,
			Jitter:         0,
		},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1000 * time.Millisecond,
		1000 * time.Millisecond,
	}
	for i, w := range want {
		got := s.computeBackoff(i)
		if got != w {
			t.Errorf("attempt %d: got %s, want %s", i, got, w)
		}
	}
}

func TestComputeBackoff_JitterStaysWithinBand(t *testing.T) {
	cfg := Config{
		Name: "x", Command: "x", HealthProbe: okProbe,
		Restart: RestartConfig{
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     1 * time.Second,
			Jitter:         0.5,
		},
	}
	// Force deterministic random output.
	calls := 0
	cfg.rand = func() float64 {
		calls++
		// alternates 0 (→ -Jitter) and 1 (→ +Jitter)
		if calls%2 == 1 {
			return 0
		}
		return 1
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	low := s.computeBackoff(0)  // 100ms * (1 - 0.5) = 50ms
	high := s.computeBackoff(0) // 100ms * (1 + 0.5) = 150ms
	if low != 50*time.Millisecond {
		t.Errorf("low jitter = %s, want 50ms", low)
	}
	if high != 150*time.Millisecond {
		t.Errorf("high jitter = %s, want 150ms", high)
	}
}

// ----- supervise integration ----------------------------------------

func TestSupervisor_StartAndReady(t *testing.T) {
	cfg := quietConfig(helperConfig("sleep"))
	cfg.HealthProbe = okProbe
	cfg.HealthCheck = HealthCheckConfig{
		Interval:         50 * time.Millisecond,
		Timeout:          25 * time.Millisecond,
		FailureThreshold: 3,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	waitCtx, waitCancel := context.WithTimeout(ctx, 2*time.Second)
	defer waitCancel()
	if err := s.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if got := s.State(); got != StateRunning {
		t.Errorf("State after ready = %v, want StateRunning", got)
	}
}

func TestSupervisor_HealthFailureRestartsChild(t *testing.T) {
	cfg := quietConfig(helperConfig("sleep"))

	// Probe fails for the first child, succeeds for the second. We
	// flip behaviour the moment we see the first restart.
	var probeFails atomic.Int64
	probeFailing := atomic.Bool{}
	probeFailing.Store(true)
	cfg.HealthProbe = func(ctx context.Context, _ string) error {
		if probeFailing.Load() {
			probeFails.Add(1)
			return errors.New("simulated bad health")
		}
		return nil
	}
	cfg.HealthCheck = HealthCheckConfig{
		Interval:         20 * time.Millisecond,
		Timeout:          10 * time.Millisecond,
		FailureThreshold: 2,
	}
	cfg.Restart = RestartConfig{
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
		Jitter:         0,
	}
	cfg.GracefulTimeout = 200 * time.Millisecond

	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	// Wait for at least one restart, then flip probe to healthy.
	deadline := time.Now().Add(3 * time.Second)
	for s.RestartCount() < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("no restart observed; failures=%d", probeFails.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	probeFailing.Store(false)

	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	defer waitCancel()
	if err := s.WaitReady(waitCtx); err != nil {
		t.Fatalf("post-restart WaitReady: %v", err)
	}
	if got := s.State(); got != StateRunning {
		t.Errorf("State = %v, want StateRunning", got)
	}
}

func TestSupervisor_ChildCrashRestarts(t *testing.T) {
	cfg := quietConfig(helperConfig("sleep_then_exit", "LWAUTH_SUPERVISOR_HELPER_MS=80"))
	cfg.HealthProbe = okProbe
	cfg.HealthCheck = HealthCheckConfig{
		Interval:         500 * time.Millisecond,
		Timeout:          50 * time.Millisecond,
		FailureThreshold: 5,
	}
	cfg.Restart = RestartConfig{
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
		Jitter:         0,
	}
	cfg.GracefulTimeout = 100 * time.Millisecond

	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for s.RestartCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("expected >=2 restarts, got %d", s.RestartCount())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSupervisor_GiveUpAfterMaxRestarts(t *testing.T) {
	cfg := quietConfig(helperConfig("exit_nonzero"))
	cfg.HealthProbe = okProbe
	cfg.HealthCheck = HealthCheckConfig{
		Interval:         time.Second,
		Timeout:          50 * time.Millisecond,
		FailureThreshold: 5,
	}
	cfg.Restart = RestartConfig{
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		Jitter:         0,
		MaxRestarts:    2,
	}
	cfg.GracefulTimeout = 50 * time.Millisecond

	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for s.State() != StateGaveUp {
		if time.Now().After(deadline) {
			t.Fatalf("expected StateGaveUp, got %v (restarts=%d)", s.State(), s.RestartCount())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// WaitReady should now return promptly (give-up unblocks the channel).
	wctx, wc := context.WithTimeout(ctx, 200*time.Millisecond)
	defer wc()
	if err := s.WaitReady(wctx); err != nil {
		t.Errorf("WaitReady after give-up should return nil, got %v", err)
	}
}

func TestSupervisor_StopIsIdempotent(t *testing.T) {
	cfg := quietConfig(helperConfig("sleep"))
	cfg.HealthProbe = okProbe
	cfg.HealthCheck = HealthCheckConfig{
		Interval:         50 * time.Millisecond,
		Timeout:          25 * time.Millisecond,
		FailureThreshold: 3,
	}
	cfg.GracefulTimeout = 200 * time.Millisecond

	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	wctx, wc := context.WithTimeout(ctx, 2*time.Second)
	defer wc()
	if err := s.WaitReady(wctx); err != nil {
		t.Fatal(err)
	}
	s.Stop()
	s.Stop() // second call must not panic / hang
	if got := s.State(); got != StateStopped {
		t.Errorf("State after Stop = %v, want StateStopped", got)
	}
}

func TestSupervisor_DoubleStartReturnsError(t *testing.T) {
	cfg := quietConfig(helperConfig("sleep"))
	cfg.HealthProbe = okProbe
	cfg.GracefulTimeout = 100 * time.Millisecond
	cfg.HealthCheck = HealthCheckConfig{Interval: 100 * time.Millisecond, Timeout: 50 * time.Millisecond, FailureThreshold: 1}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if err := s.Start(ctx); err == nil {
		t.Fatal("second Start should error")
	}
}

func TestSupervisor_ProbeContextHonoursTimeout(t *testing.T) {
	cfg := quietConfig(helperConfig("sleep"))
	cfg.HealthCheck = HealthCheckConfig{
		Interval:         60 * time.Millisecond,
		Timeout:          20 * time.Millisecond,
		FailureThreshold: 3,
	}
	gotTimeout := atomic.Int64{}
	cfg.HealthProbe = func(ctx context.Context, _ string) error {
		dl, ok := ctx.Deadline()
		if !ok {
			return errors.New("no deadline on probe ctx")
		}
		// Deadline should be ≤ 20ms in the future at probe entry.
		if time.Until(dl) > cfg.HealthCheck.Timeout+5*time.Millisecond {
			return errors.New("probe deadline too far")
		}
		gotTimeout.Add(1)
		return nil
	}
	cfg.GracefulTimeout = 100 * time.Millisecond

	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	wctx, wc := context.WithTimeout(ctx, 2*time.Second)
	defer wc()
	if err := s.WaitReady(wctx); err != nil {
		t.Fatal(err)
	}
	if gotTimeout.Load() < 1 {
		t.Fatalf("expected at least one probe with a timeout, got %d", gotTimeout.Load())
	}
}

// ----- exec preflight (sanity) --------------------------------------

func TestSupervisor_BadCommandSurfacesError(t *testing.T) {
	cfg := Config{
		Name:    "bad",
		Command: "/this/does/not/exist/lwauth-supervisor-test",
		HealthProbe: okProbe,
		HealthCheck: HealthCheckConfig{
			Interval:         50 * time.Millisecond,
			Timeout:          25 * time.Millisecond,
			FailureThreshold: 1,
		},
		Restart: RestartConfig{
			InitialBackoff: 5 * time.Millisecond,
			MaxBackoff:     10 * time.Millisecond,
			MaxRestarts:    1,
		},
		GracefulTimeout: 50 * time.Millisecond,
	}
	cfg = quietConfig(cfg)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for s.State() != StateGaveUp {
		if time.Now().After(deadline) {
			t.Fatalf("expected StateGaveUp for missing binary, got %v", s.State())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// guard against the helper accidentally hijacking other go-test runs.
var _ = exec.Command
