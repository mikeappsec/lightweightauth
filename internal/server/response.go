package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// APIResponse is the standardized JSON envelope for all HTTP responses
// from the LightWeightAuth server. Every endpoint — including error
// paths — returns this shape so consuming APIs can parse responses
// uniformly without branching on content type.
//
// On success:
//
//	{
//	  "status": "success",
//	  "code": 200,
//	  "message": "authorized",
//	  "data": { ... },
//	  "timestamp": "2026-05-01T12:00:00Z",
//	  "requestId": "abc123"
//	}
//
// On error:
//
//	{
//	  "status": "error",
//	  "code": 400,
//	  "message": "bad json: duplicate key \"path\"",
//	  "error": { "type": "validation_error", "detail": "..." },
//	  "timestamp": "2026-05-01T12:00:00Z",
//	  "requestId": "abc123"
//	}
type APIResponse struct {
	// Status is "success" or "error".
	Status string `json:"status"`
	// Code is the HTTP status code (mirrored in the body for convenience).
	Code int `json:"code"`
	// Message is a short human-readable summary.
	Message string `json:"message"`
	// Data carries the response payload on success (nil on error).
	Data any `json:"data,omitempty"`
	// Error carries structured error details on failure (nil on success).
	Error *APIError `json:"error,omitempty"`
	// Timestamp is when the server produced this response.
	Timestamp string `json:"timestamp"`
	// RequestID is the trace/request ID for correlation. Populated from
	// the X-Request-ID header if provided, otherwise from the OTel trace.
	RequestID string `json:"requestId,omitempty"`
}

// APIError provides machine-readable error classification.
type APIError struct {
	// Type categorizes the error for programmatic handling.
	// One of: validation_error, authentication_error, authorization_error,
	// rate_limit_error, internal_error, unavailable_error, payload_too_large.
	Type string `json:"type"`
	// Detail is the full error message (may be empty for security reasons).
	Detail string `json:"detail,omitempty"`
}

// errorTypeFromStatus maps HTTP status codes to APIError.Type values.
func errorTypeFromStatus(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "validation_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "authorization_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusRequestEntityTooLarge:
		return "payload_too_large"
	case http.StatusMethodNotAllowed:
		return "validation_error"
	case http.StatusUnsupportedMediaType:
		return "validation_error"
	case http.StatusServiceUnavailable:
		return "unavailable_error"
	default:
		if code >= 500 {
			return "internal_error"
		}
		return "unknown_error"
	}
}

// writeJSON writes a structured JSON response with the given status code.
// Security headers are set on every response path.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// timeNowUTC returns the current time as an RFC3339 string.
func timeNowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// writeSuccess writes a success response with structured data.
func writeSuccess(w http.ResponseWriter, r *http.Request, code int, message string, data any) {
	writeJSON(w, code, APIResponse{
		Status:    "success",
		Code:      code,
		Message:   message,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: extractRequestID(r),
	})
}

// writeError writes a structured error response. All HTTP error paths
// should use this instead of http.Error to ensure a consistent JSON
// envelope for API consumers.
func writeError(w http.ResponseWriter, r *http.Request, code int, message string) {
	writeJSON(w, code, APIResponse{
		Status:  "error",
		Code:    code,
		Message: message,
		Error: &APIError{
			Type:   errorTypeFromStatus(code),
			Detail: message,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: extractRequestID(r),
	})
}

// extractRequestID pulls the request correlation ID from standard
// headers (X-Request-ID, X-Correlation-ID) or returns empty if not
// provided by the caller.
func extractRequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	if id := r.Header.Get("X-Correlation-ID"); id != "" {
		return id
	}
	return ""
}

// --- Public reason redaction ------------------------------------------------

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
