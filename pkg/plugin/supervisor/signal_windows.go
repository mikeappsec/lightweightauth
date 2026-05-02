// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package supervisor

import "os"

// requestGracefulStop on Windows: there is no portable equivalent of
// SIGTERM for a non-console process, and CTRL_BREAK only reaches
// children that share the parent's console. We Kill directly — the
// GracefulTimeout in the supervisor still applies as a max-wait
// before the run loop returns, but no second signal is sent.
//
// Operators who need cleanup hooks on Windows should run the plugin
// as a service or on a platform with native signal support.
func requestGracefulStop(p *os.Process) error {
	return p.Kill()
}
