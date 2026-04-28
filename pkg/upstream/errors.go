package upstream

import "errors"

// ErrCircuitOpen is returned by Breaker.Allow and Guard.Do when the
// circuit breaker is in the open state and the cool-down has not yet
// elapsed. Callers should treat it as a transient upstream failure and
// surface module.ErrUpstream so M5's decision cache does not negative-
// cache the (possibly recoverable) deny.
var ErrCircuitOpen = errors.New("upstream: circuit breaker open")

// ErrRetryBudgetExceeded is returned when a retry attempt is denied
// because the retry budget was exhausted. The original failing error
// is wrapped so callers can still inspect the cause via errors.Is /
// errors.As; this sentinel is mainly useful for metrics labels.
var ErrRetryBudgetExceeded = errors.New("upstream: retry budget exceeded")
