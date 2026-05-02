// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	grpc "google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/plugin/supervisor"
)

// lifecycleConfig is the parsed `lifecycle` block on a grpc-plugin
// config. It is OPTIONAL: when absent, the v1.0 default applies and
// the host trusts the operator's external supervisor (kubelet,
// systemd, the sidecar's own restart policy) to keep the plugin
// running. When present, lwauth itself owns the plugin process via
// [pkg/plugin/supervisor].
//
// All durations and counts have sensible defaults; see
// [supervisor.Config] validation for the exact values.
type lifecycleConfig struct {
	command         string
	args            []string
	env             []string
	workDir         string
	gracefulTimeout time.Duration

	hcService          string
	hcInterval         time.Duration
	hcTimeout          time.Duration
	hcFailureThreshold int

	rsInitialBackoff time.Duration
	rsMaxBackoff     time.Duration
	rsJitter         float64
	rsMaxRestarts    int

	// startTimeout bounds how long dial() waits for the first
	// successful health probe before returning ErrConfig. Default 30s.
	startTimeout time.Duration
}

// parseLifecycle returns (nil, nil) when no `lifecycle` block is
// present (the v1.0 default — operator owns the process). Otherwise
// it returns a fully-validated lifecycleConfig.
//
// Schema:
//
//	lifecycle:
//	  command: /usr/local/bin/saml-plugin
//	  args: ["--listen", "/run/lwauth/saml.sock"]
//	  env: ["FOO=bar"]                     # optional; nil = inherit
//	  workDir: /run/lwauth                 # optional
//	  gracefulTimeout: 5s                  # SIGTERM grace before SIGKILL
//	  startTimeout: 30s                    # max wait for first ready probe
//	  healthCheck:
//	    service: ""                        # grpc.health.v1 service name
//	    interval: 5s
//	    timeout: 1s
//	    failureThreshold: 3
//	  restart:
//	    initialBackoff: 200ms
//	    maxBackoff: 30s
//	    jitter: 0.2
//	    maxRestarts: 0                     # 0 = unlimited
func parseLifecycle(name string, raw map[string]any) (*lifecycleConfig, error) {
	block, ok := raw["lifecycle"].(map[string]any)
	if !ok {
		return nil, nil
	}
	lc := &lifecycleConfig{}
	cmd, _ := block["command"].(string)
	if cmd == "" {
		return nil, fmt.Errorf("%w: grpc-plugin %q: lifecycle.command is required", module.ErrConfig, name)
	}
	lc.command = cmd

	if v, ok := block["args"].([]any); ok {
		for i, a := range v {
			s, ok := a.(string)
			if !ok {
				return nil, fmt.Errorf("%w: grpc-plugin %q: lifecycle.args[%d] must be a string", module.ErrConfig, name, i)
			}
			lc.args = append(lc.args, s)
		}
	}
	if v, ok := block["env"].([]any); ok {
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%w: grpc-plugin %q: lifecycle.env[%d] must be a string", module.ErrConfig, name, i)
			}
			lc.env = append(lc.env, s)
		}
	}
	if s, ok := block["workDir"].(string); ok {
		lc.workDir = s
	}

	d, err := optDuration(name, block, "gracefulTimeout")
	if err != nil {
		return nil, err
	}
	lc.gracefulTimeout = d

	d, err = optDuration(name, block, "startTimeout")
	if err != nil {
		return nil, err
	}
	if d == 0 {
		d = 30 * time.Second
	}
	lc.startTimeout = d

	if hc, ok := block["healthCheck"].(map[string]any); ok {
		if s, ok := hc["service"].(string); ok {
			lc.hcService = s
		}
		if d, err := optDuration(name, hc, "interval"); err == nil {
			lc.hcInterval = d
		} else {
			return nil, err
		}
		if d, err := optDuration(name, hc, "timeout"); err == nil {
			lc.hcTimeout = d
		} else {
			return nil, err
		}
		if v, ok := hc["failureThreshold"]; ok {
			n, err := asInt(v)
			if err != nil {
				return nil, fmt.Errorf("%w: grpc-plugin %q: lifecycle.healthCheck.failureThreshold: %v", module.ErrConfig, name, err)
			}
			lc.hcFailureThreshold = n
		}
	}

	if rs, ok := block["restart"].(map[string]any); ok {
		if d, err := optDuration(name, rs, "initialBackoff"); err == nil {
			lc.rsInitialBackoff = d
		} else {
			return nil, err
		}
		if d, err := optDuration(name, rs, "maxBackoff"); err == nil {
			lc.rsMaxBackoff = d
		} else {
			return nil, err
		}
		if v, ok := rs["jitter"]; ok {
			f, err := asFloat(v)
			if err != nil {
				return nil, fmt.Errorf("%w: grpc-plugin %q: lifecycle.restart.jitter: %v", module.ErrConfig, name, err)
			}
			lc.rsJitter = f
		}
		if v, ok := rs["maxRestarts"]; ok {
			n, err := asInt(v)
			if err != nil {
				return nil, fmt.Errorf("%w: grpc-plugin %q: lifecycle.restart.maxRestarts: %v", module.ErrConfig, name, err)
			}
			lc.rsMaxRestarts = n
		}
	}
	return lc, nil
}

func optDuration(plugin string, m map[string]any, key string) (time.Duration, error) {
	v, ok := m[key]
	if !ok {
		return 0, nil
	}
	switch t := v.(type) {
	case string:
		d, err := time.ParseDuration(t)
		if err != nil {
			return 0, fmt.Errorf("%w: grpc-plugin %q: %s: %v", module.ErrConfig, plugin, key, err)
		}
		return d, nil
	case time.Duration:
		return t, nil
	default:
		return 0, fmt.Errorf("%w: grpc-plugin %q: %s must be a duration string", module.ErrConfig, plugin, key)
	}
}

func asInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	}
	return 0, fmt.Errorf("must be an integer (got %T)", v)
}

func asFloat(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	}
	return 0, fmt.Errorf("must be a number (got %T)", v)
}

// ----- supervisor pool ----------------------------------------------

// supervisorPool de-duplicates supervisors across multiple module
// instances pointed at the same plugin process. The poolKey is shared
// with connPool, so the connection and the supervisor that owns the
// process behind it always agree on lifetime.
//
// Process-wide on purpose, like connPool: the registry is process-
// wide, the trust boundary is process-wide, the supervisor is
// process-wide.
var supervisorPool = struct {
	mu   sync.Mutex
	sups map[string]*pooledSupervisor
}{sups: map[string]*pooledSupervisor{}}

type pooledSupervisor struct {
	sup    *supervisor.Supervisor
	cancel context.CancelFunc
	refs   int
}

// startSupervisorIfConfigured spawns (or reuses) a supervisor for the
// given lifecycle config and waits for the first successful health
// probe before returning. When the lifecycle block is absent this is
// a no-op.
//
// The returned cleanup function is currently unused: lwauth has no
// graceful-shutdown hook for module-owned resources, so supervisors
// live for the lifetime of the process — same as connPool. We keep
// the function for tests and for a future module-shutdown wire-up.
func startSupervisorIfConfigured(name string, cfg commonConfig, lc *lifecycleConfig) error {
	if lc == nil {
		return nil
	}
	key := poolKey(cfg)

	supervisorPool.mu.Lock()
	if existing, ok := supervisorPool.sups[key]; ok {
		existing.refs++
		supervisorPool.mu.Unlock()
		return nil
	}
	supervisorPool.mu.Unlock()

	probe := func(ctx context.Context, service string) error {
		// Use the same dialer the data-plane uses so a probe failure
		// reflects what a real call would see (TLS, mTLS, sockets).
		cc, err := dial(name, cfg)
		if err != nil {
			return err
		}
		hc := healthpb.NewHealthClient(cc)
		resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: service})
		if err != nil {
			return err
		}
		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			return fmt.Errorf("plugin reported status %s", resp.GetStatus())
		}
		return nil
	}

	supCfg := supervisor.Config{
		Name:            name,
		Command:         lc.command,
		Args:            lc.args,
		Env:             lc.env,
		WorkDir:         lc.workDir,
		GracefulTimeout: lc.gracefulTimeout,
		HealthCheck: supervisor.HealthCheckConfig{
			Service:          lc.hcService,
			Interval:         lc.hcInterval,
			Timeout:          lc.hcTimeout,
			FailureThreshold: lc.hcFailureThreshold,
		},
		Restart: supervisor.RestartConfig{
			InitialBackoff: lc.rsInitialBackoff,
			MaxBackoff:     lc.rsMaxBackoff,
			Jitter:         lc.rsJitter,
			MaxRestarts:    lc.rsMaxRestarts,
		},
		HealthProbe: probe,
	}
	sup, err := supervisor.New(supCfg)
	if err != nil {
		return fmt.Errorf("%w: grpc-plugin %q: %v", module.ErrConfig, name, err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	if err := sup.Start(runCtx); err != nil {
		cancel()
		return fmt.Errorf("%w: grpc-plugin %q: supervisor start: %v", module.ErrConfig, name, err)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), lc.startTimeout)
	err = sup.WaitReady(waitCtx)
	waitCancel()
	if err != nil {
		sup.Stop()
		cancel()
		return fmt.Errorf("%w: grpc-plugin %q: plugin did not become healthy within %s", module.ErrConfig, name, lc.startTimeout)
	}
	if sup.State() == supervisor.StateGaveUp {
		sup.Stop()
		cancel()
		return fmt.Errorf("%w: grpc-plugin %q: plugin failed to start (supervisor gave up)", module.ErrConfig, name)
	}

	supervisorPool.mu.Lock()
	// Race: another goroutine may have populated the same key between
	// our miss and now. If so, drop ours and reuse theirs.
	if existing, ok := supervisorPool.sups[key]; ok {
		supervisorPool.mu.Unlock()
		sup.Stop()
		cancel()
		existing.refs++
		return nil
	}
	supervisorPool.sups[key] = &pooledSupervisor{
		sup:    sup,
		cancel: cancel,
		refs:   1,
	}
	supervisorPool.mu.Unlock()
	return nil
}

// stopSupervisorForTest tears down a pooled supervisor regardless of
// refcount. Production has no equivalent path because supervisors
// live for the process lifetime; tests need it to keep instances
// isolated.
func stopSupervisorForTest(cfg commonConfig) {
	key := poolKey(cfg)
	supervisorPool.mu.Lock()
	ps, ok := supervisorPool.sups[key]
	delete(supervisorPool.sups, key)
	supervisorPool.mu.Unlock()
	if ok {
		if ps.cancel != nil {
			ps.cancel()
		}
		if ps.sup != nil {
			ps.sup.Stop()
		}
	}
}

// nopGRPCConn is a tiny adapter so tests can drop a *grpc.ClientConn
// in without paying for a real dial. Currently unused; reserved for
// the wiring tests below.
var _ = (*grpc.ClientConn)(nil)
