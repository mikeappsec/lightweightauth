// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package server

import "sync"

// ConfigApplyMu serializes live config application across runtime paths
// (controller reconcile, file reload, follower stream).
var ConfigApplyMu sync.Mutex
