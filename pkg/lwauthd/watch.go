package lwauthd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/fsnotify/fsnotify"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/mikeappsec/lightweightauth/internal/controller"
	"github.com/mikeappsec/lightweightauth/internal/server"
	"github.com/mikeappsec/lightweightauth/pkg/configstream"
)

// startCRDController boots a controller-runtime manager that watches the
// AuthConfig CR identified by Options.WatchNamespace + AuthConfigName
// and atomically swaps its compiled engine into holder.
//
// When LeaderElection is enabled (ENT-HA-1), only the elected leader
// runs the reconciler; follower replicas subscribe to the leader's
// configstream endpoint and receive compiled engine snapshots for
// active/active request serving.
//
// The manager starts in its own goroutine so HTTP/gRPC remain the
// authoritative lifecycle. If the manager exits with an error, errCh
// surfaces it so the main Run loop can shut everything down.
func startCRDController(ctx context.Context, log *slog.Logger, opts Options, holder *server.EngineHolder, errCh chan<- error) error {
	scheme := runtime.NewScheme()
	if err := controller.AddToScheme(scheme); err != nil {
		return fmt.Errorf("scheme: %w", err)
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("get kubeconfig: %w (is KUBECONFIG / in-cluster config available?)", err)
	}

	cacheOpts := cache.Options{}
	if opts.WatchNamespace != "" {
		cacheOpts.DefaultNamespaces = map[string]cache.Config{opts.WatchNamespace: {}}
	}

	// ENT-HA-1: leader election configuration.
	leaderElectionID := opts.LeaderElectionID
	if leaderElectionID == "" {
		leaderElectionID = "lwauth-controller-leader"
	}
	leaderElectionNS := opts.LeaderElectionNamespace
	if leaderElectionNS == "" {
		leaderElectionNS = opts.WatchNamespace
	}

	mgrOpts := manager.Options{
		Scheme:                        scheme,
		Cache:                         cacheOpts,
		HealthProbeBindAddress:        "0",
		Metrics:                       metricsserver.Options{BindAddress: "0"},
		LeaderElection:                opts.LeaderElection,
		LeaderElectionID:              leaderElectionID,
		LeaderElectionNamespace:       leaderElectionNS,
		LeaderElectionReleaseOnCancel: true,
	}
	if opts.LeaseDuration > 0 {
		mgrOpts.LeaseDuration = &opts.LeaseDuration
	}
	if opts.RenewDeadline > 0 {
		mgrOpts.RenewDeadline = &opts.RenewDeadline
	}
	if opts.RetryPeriod > 0 {
		mgrOpts.RetryPeriod = &opts.RetryPeriod
	}

	mgr, err := ctrl.NewManager(cfg, mgrOpts)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}

	// The Broker lets the leader push compiled config to followers via
	// configstream. If leader election is disabled (single-replica), the
	// broker is still created but never subscribed to.
	broker := configstream.NewBroker()

	r := &controller.AuthConfigReconciler{
		Client: mgr.GetClient(),
		Holder: holder,
		Watched: types.NamespacedName{
			Namespace: opts.WatchNamespace,
			Name:      opts.AuthConfigName,
		},
		Broker: broker,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	// ENT-HA-1: when leader election is on and a configstream address
	// is provided, start a follower subscription loop. This goroutine
	// receives config from the leader and swaps it into the holder,
	// enabling active/active serving. The loop runs continuously — when
	// this pod IS the leader, the gRPC call will self-connect (or fail
	// benignly) but the reconciler swap already keeps the engine current.
	if opts.LeaderElection && opts.ConfigStreamAddr != "" {
		go startFollowerSubscription(ctx, log, opts, holder)
	}

	go func() {
		log.Info("controller manager starting",
			"namespace", opts.WatchNamespace,
			"authconfig", opts.AuthConfigName,
			"leaderElection", opts.LeaderElection,
			"leaderElectionID", leaderElectionID)
		if err := mgr.Start(ctx); err != nil {
			errCh <- fmt.Errorf("manager: %w", err)
		}
	}()
	return nil
}

// startFileWatcher watches opts.ConfigPath with fsnotify and atomically
// swaps the engine on every successful reload. Used in non-K8s
// deployments and during local development.
//
// fsnotify quirks we handle:
//   - Editors often replace the file atomically (rename a tmpfile in),
//     so the watch on the old inode dies. We re-add after every event.
//   - Multiple events can fire for one save; debounce by 100 ms.
func startFileWatcher(ctx context.Context, log *slog.Logger, path string, holder *server.EngineHolder) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}
	if err := w.Add(path); err != nil {
		_ = w.Close()
		return fmt.Errorf("watch %s: %w", path, err)
	}

	go func() {
		defer w.Close()
		var debounce <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				// On atomic-replace (Rename/Remove) the watch path
				// vanishes; re-add so we keep getting events.
				if ev.Op&(fsnotify.Rename|fsnotify.Remove) != 0 {
					_ = w.Remove(path)
					_ = w.Add(path)
				}
				debounce = time.After(100 * time.Millisecond)
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Error("file watcher", "err", err)
			case <-debounce:
				debounce = nil
				eng, err := LoadEngine(path)
				if err != nil {
					log.Error("config reload failed; keeping previous engine",
						"path", path, "err", err)
					continue
				}
				holder.Swap(eng)
				log.Info("config reloaded", "path", path)
			}
		}
	}()
	return nil
}

// errOptionsConflict is returned when the operator asks for both file
// and CRD modes simultaneously. We pick one; future M11 may unify.
var errOptionsConflict = errors.New(
	"lwauthd: cannot use --watch-namespace together with --watch-config-file; choose one")

// StartFileWatcherForTest is the test-only entry point for the
// fsnotify-based file watcher. Production code goes through Run /
// Options.WatchConfigFile. Exposed so package-level tests can exercise
// the watcher without standing up the full HTTP/gRPC stack.
func StartFileWatcherForTest(ctx context.Context, path string, holder *server.EngineHolder) error {
	logger := slog.New(slog.NewTextHandler(stderrSink{}, nil))
	return startFileWatcher(ctx, logger, path, holder)
}

// stderrSink is a no-op io.Writer so tests don't spew log output.
type stderrSink struct{}

func (stderrSink) Write(p []byte) (int, error) { return len(p), nil }
