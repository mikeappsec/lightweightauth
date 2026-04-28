package grpc

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// ----- parseLifecycle ----------------------------------------------

func TestParseLifecycle_AbsentReturnsNil(t *testing.T) {
	lc, err := parseLifecycle("p", map[string]any{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if lc != nil {
		t.Fatalf("expected nil lifecycleConfig when block absent, got %+v", lc)
	}
}

func TestParseLifecycle_RequiresCommand(t *testing.T) {
	_, err := parseLifecycle("p", map[string]any{
		"lifecycle": map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for missing command")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("err should wrap ErrConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "lifecycle.command") {
		t.Errorf("err should mention lifecycle.command: %v", err)
	}
}

func TestParseLifecycle_FullSchema(t *testing.T) {
	raw := map[string]any{
		"lifecycle": map[string]any{
			"command":         "/bin/echo",
			"args":            []any{"-n", "hi"},
			"env":             []any{"FOO=bar"},
			"workDir":         "/tmp",
			"gracefulTimeout": "2s",
			"startTimeout":    "10s",
			"healthCheck": map[string]any{
				"service":          "myplugin",
				"interval":         "100ms",
				"timeout":          "50ms",
				"failureThreshold": 4,
			},
			"restart": map[string]any{
				"initialBackoff": "150ms",
				"maxBackoff":     "5s",
				"jitter":         0.3,
				"maxRestarts":    7,
			},
		},
	}
	lc, err := parseLifecycle("p", raw)
	if err != nil {
		t.Fatal(err)
	}
	if lc == nil {
		t.Fatal("nil lifecycleConfig")
	}
	if lc.command != "/bin/echo" {
		t.Errorf("command = %q", lc.command)
	}
	if len(lc.args) != 2 || lc.args[0] != "-n" {
		t.Errorf("args = %v", lc.args)
	}
	if len(lc.env) != 1 || lc.env[0] != "FOO=bar" {
		t.Errorf("env = %v", lc.env)
	}
	if lc.workDir != "/tmp" {
		t.Errorf("workDir = %q", lc.workDir)
	}
	if lc.gracefulTimeout != 2*time.Second {
		t.Errorf("gracefulTimeout = %s", lc.gracefulTimeout)
	}
	if lc.startTimeout != 10*time.Second {
		t.Errorf("startTimeout = %s", lc.startTimeout)
	}
	if lc.hcService != "myplugin" {
		t.Errorf("hcService = %q", lc.hcService)
	}
	if lc.hcInterval != 100*time.Millisecond {
		t.Errorf("hcInterval = %s", lc.hcInterval)
	}
	if lc.hcTimeout != 50*time.Millisecond {
		t.Errorf("hcTimeout = %s", lc.hcTimeout)
	}
	if lc.hcFailureThreshold != 4 {
		t.Errorf("hcFailureThreshold = %d", lc.hcFailureThreshold)
	}
	if lc.rsInitialBackoff != 150*time.Millisecond {
		t.Errorf("rsInitialBackoff = %s", lc.rsInitialBackoff)
	}
	if lc.rsMaxBackoff != 5*time.Second {
		t.Errorf("rsMaxBackoff = %s", lc.rsMaxBackoff)
	}
	if lc.rsJitter != 0.3 {
		t.Errorf("rsJitter = %f", lc.rsJitter)
	}
	if lc.rsMaxRestarts != 7 {
		t.Errorf("rsMaxRestarts = %d", lc.rsMaxRestarts)
	}
}

func TestParseLifecycle_StartTimeoutDefault(t *testing.T) {
	lc, err := parseLifecycle("p", map[string]any{
		"lifecycle": map[string]any{"command": "/bin/true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if lc.startTimeout != 30*time.Second {
		t.Errorf("startTimeout default = %s, want 30s", lc.startTimeout)
	}
}

func TestParseLifecycle_BadDuration(t *testing.T) {
	cases := []map[string]any{
		{"command": "/x", "gracefulTimeout": "ham"},
		{"command": "/x", "healthCheck": map[string]any{"interval": "ham"}},
		{"command": "/x", "restart": map[string]any{"maxBackoff": "ham"}},
	}
	for i, life := range cases {
		_, err := parseLifecycle("p", map[string]any{"lifecycle": life})
		if err == nil {
			t.Errorf("case %d: expected error", i)
			continue
		}
		if !errors.Is(err, module.ErrConfig) {
			t.Errorf("case %d: err should wrap ErrConfig: %v", i, err)
		}
	}
}

func TestParseLifecycle_BadArgsType(t *testing.T) {
	_, err := parseLifecycle("p", map[string]any{
		"lifecycle": map[string]any{
			"command": "/x",
			"args":    []any{"ok", 42},
		},
	})
	if err == nil || !errors.Is(err, module.ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

// ----- startSupervisorIfConfigured failure path --------------------

func TestStartSupervisor_NilLifecycleIsNoop(t *testing.T) {
	cfg := commonConfig{Address: "unix:///nope", Timeout: time.Second}
	if err := startSupervisorIfConfigured("p", cfg, nil); err != nil {
		t.Fatalf("nil lifecycle should be a no-op, got %v", err)
	}
}

func TestStartSupervisor_BadCommandSurfacesErrConfig(t *testing.T) {
	cfg := commonConfig{
		Address: "unix:///lwauth-supervisor-bad-cmd-test.sock",
		Timeout: time.Second,
	}
	lc := &lifecycleConfig{
		command:            "/this/does/not/exist/lwauth-cmd",
		gracefulTimeout:    50 * time.Millisecond,
		hcInterval:         50 * time.Millisecond,
		hcTimeout:          25 * time.Millisecond,
		hcFailureThreshold: 1,
		rsInitialBackoff:   5 * time.Millisecond,
		rsMaxBackoff:       10 * time.Millisecond,
		rsMaxRestarts:      1,
		startTimeout:       500 * time.Millisecond,
	}
	defer stopSupervisorForTest(cfg)

	err := startSupervisorIfConfigured("badcmd", cfg, lc)
	if err == nil {
		t.Fatal("expected error from bad command")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("err should wrap ErrConfig: %v", err)
	}
}

func TestStartSupervisor_PoolingDeDuplicates(t *testing.T) {
	// Two calls with identical cfg should result in a single
	// supervisor (refcount=2). We verify by inspecting the pool.
	cfg := commonConfig{
		Address: "unix:///lwauth-supervisor-pool-test.sock",
		Timeout: time.Second,
	}
	defer stopSupervisorForTest(cfg)

	// Use a config that will fail — we just want to confirm pooling
	// behaviour, not actual readiness. The first call errors out,
	// but a successful pooling test needs success path; emulate by
	// pre-seeding the pool.
	supervisorPool.mu.Lock()
	key := poolKey(cfg)
	supervisorPool.sups[key] = &pooledSupervisor{refs: 1}
	supervisorPool.mu.Unlock()

	lc := &lifecycleConfig{
		command:      "/anything",
		startTimeout: 100 * time.Millisecond,
	}
	if err := startSupervisorIfConfigured("p", cfg, lc); err != nil {
		t.Fatalf("pooled second call should succeed: %v", err)
	}
	supervisorPool.mu.Lock()
	got := supervisorPool.sups[key].refs
	supervisorPool.mu.Unlock()
	if got != 2 {
		t.Errorf("refs = %d, want 2", got)
	}
}
