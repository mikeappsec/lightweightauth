package server

import "net/http"

// publicReason maps a Decision (which may carry a verbose internal
// reason like "hmac: signature mismatch" or "rbac: subject not in
// allow-list 'editors'") to a generic, status-aligned client-facing
// message. The verbose reason is still recorded in the audit log via
// the engine's report() path -- operators can correlate by trace id
// without leaking policy or module internals to the network.
//
// The mapping is intentionally short and stable: any HTTP status that
// isn't explicitly listed falls through to "request denied" so a future
// policy that emits a novel status doesn't accidentally leak details.
func publicReason(httpStatus int, internal string) string {
	switch httpStatus {
	case http.StatusUnauthorized:
		return "unauthenticated"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusTooManyRequests:
		return "rate limit exceeded"
	case http.StatusServiceUnavailable:
		return "service unavailable"
	case http.StatusInternalServerError:
		return "internal error"
	}
	if httpStatus >= 500 {
		return "service unavailable"
	}
	return "request denied"
}
