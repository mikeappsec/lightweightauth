// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package supervisor

import (
	"os"
	"syscall"
)

// requestGracefulStop sends SIGTERM. The child is expected to respond
// by closing its listener and exiting; if it doesn't within
// Config.GracefulTimeout the supervisor follows up with Process.Kill.
func requestGracefulStop(p *os.Process) error {
	return p.Signal(syscall.SIGTERM)
}
