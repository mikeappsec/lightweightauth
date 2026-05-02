// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import rand2 "math/rand/v2"

// rand2Float64 wraps the global concurrent-safe PRNG.
func rand2Float64() float64 { return rand2.Float64() }
