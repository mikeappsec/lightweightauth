package lwauthd_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yourorg/lightweightauth/internal/server"
	"github.com/yourorg/lightweightauth/pkg/lwauthd"

	_ "github.com/yourorg/lightweightauth/pkg/builtins"
)

const cfgV1 = `
identifierMode: firstMatch
identifiers:
  - name: dev-apikey
    type: apikey
    config:
      headerName: X-Api-Key
      static:
        k1: { subject: alice, roles: [admin] }
authorizers:
  - name: rbac
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [admin]
`

const cfgV2 = `
identifierMode: firstMatch
identifiers:
  - name: dev-apikey
    type: apikey
    config:
      headerName: X-Api-Key
      static:
        k2: { subject: bob, roles: [editor] }
authorizers:
  - name: rbac
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [editor]
`

// TestFileWatcher_Reload covers the fsnotify path: write a config,
// load it, overwrite the file, observe that the engine swap happens.
//
// This exercises lwauthd's exported StartFileWatcherForTest helper. The
// underlying mechanism is the same fsnotify watcher production uses.
func TestFileWatcher_Reload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfgV1), 0o600); err != nil {
		t.Fatalf("write v1: %v", err)
	}

	eng, err := lwauthd.LoadEngine(path)
	if err != nil {
		t.Fatalf("LoadEngine: %v", err)
	}
	holder := server.NewEngineHolder(eng)
	first := holder.Load()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	if err := lwauthd.StartFileWatcherForTest(ctx, path, holder); err != nil {
		t.Fatalf("StartFileWatcherForTest: %v", err)
	}

	// Overwrite the file.
	if err := os.WriteFile(path, []byte(cfgV2), 0o600); err != nil {
		t.Fatalf("write v2: %v", err)
	}

	// Wait up to 2s for the swap. fsnotify + 100 ms debounce + reload.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if holder.Load() != first {
			return // pass
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("engine was not swapped within 2s after config change")
}
