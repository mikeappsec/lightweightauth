// Package supervisor is the M10-PLUGIN-LIFECYCLE process supervisor
// for [pkg/plugin/grpc] children.
//
// It is intentionally small: spawn → periodic gRPC health probe →
// exponential-backoff restart with jitter. Operators on Kubernetes /
// systemd / launchd keep the platform's restart policy and never
// instantiate a Supervisor at all (the v1.0 default). Operators who
// want lwauth itself to own the plugin process — common when running
// outside an orchestrator, or when the plugin is private to a single
// lwauth replica — opt in with a `lifecycle:` block on the
// `grpc-plugin` config.
//
// The supervisor never inspects the plugin's RPC payloads. That stays
// in [pkg/plugin/grpc]: F-PLUGIN-2 signature verification, timeout
// handling, ErrUpstream propagation. Restart decisions are based only
// on (a) child exit and (b) repeated health-probe failure. This keeps
// the trust boundary clean — a malicious plugin cannot trick the
// supervisor into *not* restarting it by emitting confusing payloads.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// Config describes one supervised plugin process. All durations must
// be > 0 unless documented otherwise; [Validate] enforces this so the
// engine fails at compile time, not at the first request.
type Config struct {
	// Name is the operator-chosen identifier of the grpc-plugin
	// config block. Used purely for log/metric attribution.
	Name string

	// Command is the absolute (or $PATH-resolvable) executable.
	Command string
	Args    []string
	Env     []string // os/exec semantics: nil = inherit, non-nil = replace.
	WorkDir string

	// GracefulTimeout is the window between the supervisor signalling
	// the child to terminate (SIGTERM on Unix; Kill on Windows where
	// graceful termination is not portable) and forcefully killing it.
	// Default 5s on [Validate].
	GracefulTimeout time.Duration

	HealthCheck HealthCheckConfig
	Restart     RestartConfig

	// HealthProbe is invoked once per HealthCheck.Interval while the
	// child is running. Returning nil means "serving"; any error means
	// "not serving" and counts toward FailureThreshold. The supervisor
	// supplies a context already bounded by HealthCheck.Timeout.
	//
	// The grpc-plugin adapter wires this to a grpc.health.v1.Health
	// client over the same transport credentials the plugin's data
	// path uses, so a probe failure means the same thing a real
	// request failure would.
	HealthProbe func(ctx context.Context, service string) error

	// Logger receives lifecycle events. Defaults to slog.Default().
	Logger *slog.Logger

	// Test seams. Production leaves these zero.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration)
	rand  func() float64
}

// HealthCheckConfig tunes the health-probe loop. The defaults applied
// by [Validate] are conservative — designed so a plugin GC pause or
// a slow Vault read does not trigger a restart, but a hung process
// is detected within a few seconds.
type HealthCheckConfig struct {
	// Service is the grpc.health.v1 service name. Empty = overall
	// server health (the convention in google.golang.org/grpc/health).
	Service string

	// Interval between consecutive probes. Default 5s.
	Interval time.Duration

	// Timeout per probe. Must be ≤ Interval. Default 1s.
	Timeout time.Duration

	// FailureThreshold is the number of consecutive failed probes
	// before the supervisor terminates and restarts the child.
	// Default 3.
	FailureThreshold int
}

// RestartConfig tunes the restart loop. Backoff is exponential
// (`initial * 2^n`) capped at MaxBackoff, with optional ±Jitter
// fraction. MaxRestarts == 0 means unlimited (the recommended default;
// a permanently-broken plugin should be diagnosed by an operator
// reading the log, not by the supervisor giving up silently).
type RestartConfig struct {
	InitialBackoff time.Duration // default 200ms
	MaxBackoff     time.Duration // default 30s
	Jitter         float64       // 0..1, default 0.2
	MaxRestarts    int           // 0 = unlimited (default)
}

// State is the supervisor's externally-observable state. Exposed for
// tests and for a future readiness endpoint; the data-plane RPCs do
// not consult it (gRPC's own connection state is the truth there).
type State int32

const (
	StateStopped State = iota // not yet started, or Stop returned
	StateStarting
	StateRunning  // child alive AND most recent health probe passed
	StateUnhealthy // child alive, FailureThreshold-1 or fewer fails so far
	StateBackoff  // child not running; waiting before next spawn
	StateGaveUp   // MaxRestarts exhausted
)

// Supervisor owns a single plugin child process. Safe for concurrent
// State / RestartCount reads; Start and Stop are not concurrent-safe
// against each other (call Start once, Stop once).
type Supervisor struct {
	cfg Config
	log *slog.Logger

	state        atomic.Int32 // State
	restartCount atomic.Int64

	// readyOnce closes ready exactly once on the first successful
	// health probe. WaitReady consumers see fast wake-up after restart
	// because the channel is reset on each successful spawn cycle.
	readyMu sync.Mutex
	ready   chan struct{}

	cancel context.CancelFunc
	done   chan struct{}
}

// New validates cfg and returns a stopped Supervisor. Call [Start] to
// spawn the child.
func New(cfg Config) (*Supervisor, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.sleep == nil {
		cfg.sleep = ctxSleep
	}
	if cfg.rand == nil {
		cfg.rand = rand.Float64
	}
	s := &Supervisor{
		cfg:   cfg,
		log:   cfg.Logger.With("plugin", cfg.Name),
		ready: make(chan struct{}),
	}
	return s, nil
}

func (cfg *Config) validate() error {
	if cfg.Name == "" {
		return errors.New("supervisor: Name is required")
	}
	if cfg.Command == "" {
		return errors.New("supervisor: Command is required")
	}
	if cfg.HealthProbe == nil {
		return errors.New("supervisor: HealthProbe is required")
	}
	if cfg.GracefulTimeout == 0 {
		cfg.GracefulTimeout = 5 * time.Second
	}
	if cfg.HealthCheck.Interval == 0 {
		cfg.HealthCheck.Interval = 5 * time.Second
	}
	if cfg.HealthCheck.Timeout == 0 {
		cfg.HealthCheck.Timeout = time.Second
	}
	if cfg.HealthCheck.FailureThreshold == 0 {
		cfg.HealthCheck.FailureThreshold = 3
	}
	if cfg.HealthCheck.Timeout > cfg.HealthCheck.Interval {
		return fmt.Errorf("supervisor: healthCheck.timeout (%s) must be <= interval (%s)", cfg.HealthCheck.Timeout, cfg.HealthCheck.Interval)
	}
	if cfg.HealthCheck.FailureThreshold < 1 {
		return fmt.Errorf("supervisor: healthCheck.failureThreshold must be >= 1")
	}
	if cfg.Restart.InitialBackoff == 0 {
		cfg.Restart.InitialBackoff = 200 * time.Millisecond
	}
	if cfg.Restart.MaxBackoff == 0 {
		cfg.Restart.MaxBackoff = 30 * time.Second
	}
	if cfg.Restart.MaxBackoff < cfg.Restart.InitialBackoff {
		return fmt.Errorf("supervisor: restart.maxBackoff (%s) must be >= initialBackoff (%s)", cfg.Restart.MaxBackoff, cfg.Restart.InitialBackoff)
	}
	if cfg.Restart.Jitter < 0 || cfg.Restart.Jitter > 1 {
		return fmt.Errorf("supervisor: restart.jitter must be in [0, 1]")
	}
	if cfg.Restart.MaxRestarts < 0 {
		return fmt.Errorf("supervisor: restart.maxRestarts must be >= 0")
	}
	return nil
}

// State returns the current externally-visible state.
func (s *Supervisor) State() State { return State(s.state.Load()) }

// RestartCount is the number of times the supervisor has spawned the
// child *after* the initial spawn. Useful for tests and metrics.
func (s *Supervisor) RestartCount() int64 { return s.restartCount.Load() }

// Start spawns the child and runs the supervise loop in a goroutine.
// It returns immediately; use [WaitReady] to block until the first
// successful health probe.
//
// ctx cancels the entire supervisor including any in-flight backoff
// timer. The supervised child is signalled and (after GracefulTimeout)
// killed when ctx is cancelled or [Stop] is called, whichever happens
// first.
func (s *Supervisor) Start(ctx context.Context) error {
	if !s.state.CompareAndSwap(int32(StateStopped), int32(StateStarting)) {
		return errors.New("supervisor: already started")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.run(runCtx)
	return nil
}

// Stop signals the child to terminate, waits for the supervise loop
// to exit, and returns. Idempotent.
func (s *Supervisor) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.done != nil {
		<-s.done
	}
	s.state.Store(int32(StateStopped))
}

// WaitReady blocks until the supervisor has observed a successful
// health probe (i.e. the child is fully up and serving), or ctx is
// cancelled, or the supervisor enters StateGaveUp.
func (s *Supervisor) WaitReady(ctx context.Context) error {
	s.readyMu.Lock()
	ch := s.ready
	s.readyMu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run is the supervise loop. One iteration = one spawn cycle.
func (s *Supervisor) run(ctx context.Context) {
	defer close(s.done)
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		exitErr := s.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		// Child exited. Decide whether to restart.
		s.log.Warn("plugin exited",
			"err", exitErr,
			"restart_count", s.restartCount.Load(),
		)
		if s.cfg.Restart.MaxRestarts > 0 && int(s.restartCount.Load()) >= s.cfg.Restart.MaxRestarts {
			s.state.Store(int32(StateGaveUp))
			s.log.Error("plugin gave up after max restarts",
				"max_restarts", s.cfg.Restart.MaxRestarts,
			)
			s.closeReadyOnGaveUp()
			return
		}
		s.state.Store(int32(StateBackoff))
		backoff := s.computeBackoff(attempt)
		attempt++
		s.log.Info("plugin restart scheduled", "backoff", backoff, "attempt", attempt)
		s.cfg.sleep(ctx, backoff)
		s.restartCount.Add(1)
		s.resetReady()
	}
}

// runOnce spawns the child, runs the health loop alongside it, and
// returns when the child exits (for any reason: clean exit, crash,
// signalled by health-loop, or supervisor cancellation).
func (s *Supervisor) runOnce(ctx context.Context) error {
	s.state.Store(int32(StateStarting))

	cmd := exec.Command(s.cfg.Command, s.cfg.Args...) //nolint:gosec // operator-controlled exec; same trust as a shell startup script.
	if s.cfg.Env != nil {
		cmd.Env = s.cfg.Env
	}
	if s.cfg.WorkDir != "" {
		cmd.Dir = s.cfg.WorkDir
	}
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	if err := cmd.Start(); err != nil {
		_ = stdoutW.Close()
		_ = stderrW.Close()
		_ = stdoutR.Close()
		_ = stderrR.Close()
		return fmt.Errorf("start: %w", err)
	}
	pid := cmd.Process.Pid
	s.log.Info("plugin started", "pid", pid)

	go pipeLines(s.log, "stdout", stdoutR)
	go pipeLines(s.log, "stderr", stderrR)

	s.state.Store(int32(StateUnhealthy))

	// Health loop signals stop via killCh; child-exit signals stop via
	// waitCh. Whichever fires first wins; we cancel the other path.
	healthCtx, cancelHealth := context.WithCancel(ctx)
	defer cancelHealth()
	go s.healthLoop(healthCtx, cmd, pid)

	// Watch for ctx cancellation (Stop() called) so we terminate the
	// child gracefully even if the supervisor is shutting down.
	go func() {
		<-ctx.Done()
		s.terminate(cmd, "supervisor stopping")
	}()

	waitErr := cmd.Wait()
	_ = stdoutW.Close()
	_ = stderrW.Close()
	return waitErr
}

// healthLoop probes the child every Interval and terminates it after
// FailureThreshold consecutive failures.
func (s *Supervisor) healthLoop(ctx context.Context, cmd *exec.Cmd, pid int) {
	consecutiveFailures := 0
	t := time.NewTicker(s.cfg.HealthCheck.Interval)
	defer t.Stop()

	// First probe runs immediately so WaitReady wakes promptly.
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		probeCtx, cancel := context.WithTimeout(ctx, s.cfg.HealthCheck.Timeout)
		err := s.cfg.HealthProbe(probeCtx, s.cfg.HealthCheck.Service)
		cancel()

		if err == nil {
			if consecutiveFailures > 0 {
				s.log.Info("plugin health recovered",
					"pid", pid,
					"prior_failures", consecutiveFailures,
				)
			}
			consecutiveFailures = 0
			s.state.Store(int32(StateRunning))
			s.signalReady()
		} else {
			consecutiveFailures++
			s.state.Store(int32(StateUnhealthy))
			s.log.Warn("plugin health probe failed",
				"pid", pid,
				"err", err,
				"consecutive_failures", consecutiveFailures,
				"threshold", s.cfg.HealthCheck.FailureThreshold,
			)
			if consecutiveFailures >= s.cfg.HealthCheck.FailureThreshold {
				s.log.Error("plugin health exceeded threshold; terminating",
					"pid", pid,
					"threshold", s.cfg.HealthCheck.FailureThreshold,
				)
				s.terminate(cmd, "health threshold exceeded")
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// terminate signals the child to exit and, if it does not within
// GracefulTimeout, kills it. Best-effort; both calls swallow errors
// because a child that has already exited is the success case.
func (s *Supervisor) terminate(cmd *exec.Cmd, reason string) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	s.log.Info("plugin terminating", "pid", pid, "reason", reason)
	if err := requestGracefulStop(cmd.Process); err != nil {
		s.log.Warn("plugin graceful signal failed", "pid", pid, "err", err)
	}
	// On Windows, requestGracefulStop already kills; the timer below
	// is a no-op there. On Unix, give the child GracefulTimeout to
	// cleanly close listeners before the SIGKILL.
	timer := time.AfterFunc(s.cfg.GracefulTimeout, func() {
		_ = cmd.Process.Kill()
		s.log.Warn("plugin force-killed after graceful timeout",
			"pid", pid,
			"timeout", s.cfg.GracefulTimeout,
		)
	})
	go func() {
		// Stop the timer once the wait completes elsewhere; we can't
		// observe Wait here without racing the run-loop, so we just
		// let the timer self-cleanup on the kill path. A successful
		// graceful stop simply makes the kill a no-op.
		_ = timer
	}()
}

// computeBackoff returns initial * 2^attempt, capped at MaxBackoff,
// with ±Jitter fraction (uniform). Pure function — separated for tests.
func (s *Supervisor) computeBackoff(attempt int) time.Duration {
	d := s.cfg.Restart.InitialBackoff
	for i := 0; i < attempt && d < s.cfg.Restart.MaxBackoff; i++ {
		next := d * 2
		if next < d || next > s.cfg.Restart.MaxBackoff {
			d = s.cfg.Restart.MaxBackoff
			break
		}
		d = next
	}
	if s.cfg.Restart.Jitter > 0 {
		// Symmetric jitter in [-Jitter, +Jitter].
		offset := (s.cfg.rand()*2 - 1) * s.cfg.Restart.Jitter
		d = time.Duration(float64(d) * (1 + offset))
		if d < 0 {
			d = 0
		}
	}
	return d
}

func (s *Supervisor) signalReady() {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	select {
	case <-s.ready:
		// already closed
	default:
		close(s.ready)
	}
}

func (s *Supervisor) resetReady() {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	select {
	case <-s.ready:
		// was closed — make a fresh channel for the next cycle.
		s.ready = make(chan struct{})
	default:
		// not yet ready in the previous cycle; keep the same channel
		// so any pending WaitReady continues to block until the
		// next-cycle's first successful probe.
	}
}

func (s *Supervisor) closeReadyOnGaveUp() {
	// On give-up we close ready so WaitReady returns instead of
	// hanging forever. Callers must still consult State() to
	// distinguish "ready" from "gave up".
	s.signalReady()
}

func ctxSleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func pipeLines(log *slog.Logger, stream string, r io.Reader) {
	buf := make([]byte, 4096)
	var carry []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			carry = append(carry, buf[:n]...)
			for {
				idx := indexNewline(carry)
				if idx < 0 {
					break
				}
				line := string(carry[:idx])
				carry = carry[idx+1:]
				if line != "" {
					log.Info("plugin "+stream, "line", line)
				}
			}
		}
		if err != nil {
			if len(carry) > 0 {
				log.Info("plugin "+stream, "line", string(carry))
			}
			return
		}
	}
}

func indexNewline(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}
