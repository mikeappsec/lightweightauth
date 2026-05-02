package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
	"unicode"

	"github.com/mikeappsec/lightweightauth/pkg/httputil"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
	"github.com/mikeappsec/lightweightauth/pkg/revocation"
	"github.com/mikeappsec/lightweightauth/pkg/revocation/eventbus"
)

// Revocation key validation constraints.
const (
	maxJTILength       = 256
	maxTokenHashLength = 128
	maxSubjectLength   = 256
	maxTenantLength    = 128
	maxReasonLength    = 512
	maxRevocationTTL   = 30 * 24 * time.Hour // 30 days
	adminBodyLimit     = 1 << 20             // 1 MB
)

// adminLimiter is the package-level rate limiter for admin endpoints.
// 10 requests/second per IP with a burst of 20.
var adminLimiter = httputil.NewTokenBucketLimiter(10, 20)

// flushLimiter is a stricter rate limiter for scope=all invalidation.
// 1 request per 60 seconds per IP with burst of 2 — prevents cache-busting DoS.
var flushLimiter = httputil.NewTokenBucketLimiter(1.0/60.0, 2)

// validScopes is the allowlist for cache invalidation scope (TC7).
var validScopes = map[string]bool{
	"all":     true,
	"tenant":  true,
	"subject": true,
}

// AdminDeps holds dependencies injected into admin handlers at startup.
type AdminDeps struct {
	// RevocationStore is the active revocation store (E2). Nil if disabled.
	RevocationStore revocation.Store

	// EventBus is the cross-replica event bus. Nil if no Valkey pub/sub.
	EventBus *eventbus.Bus

	// InvalidateFunc is called for local cache invalidation (E3).
	// Receives context and tags (nil = flush all). Returns evicted count.
	InvalidateFunc func(ctx context.Context, tags []string) int
}

// NewAdminMux returns an http.Handler that serves all /v1/admin/ endpoints,
// protected by the given middleware. If the middleware is nil or disabled,
// all routes return 404.
func NewAdminMux(mw *Middleware, deps *AdminDeps) http.Handler {
	mux := http.NewServeMux()

	if deps == nil {
		deps = &AdminDeps{}
	}

	if mw == nil || !mw.cfg.Enabled {
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			writeAdminError(w, http.StatusNotFound, "admin endpoints disabled")
		})
		return mux
	}

	// TC4: rate-limit all admin routes via shared httputil limiter.
	rl := func(next http.Handler) http.Handler {
		return httputil.RateLimitMiddleware(adminLimiter, httputil.IPKeyFunc, next)
	}

	// GET /v1/admin/status — engine and config status.
	mux.Handle("/v1/admin/status", rl(mw.Require(VerbReadStatus,
		http.HandlerFunc(handleStatus))))

	// POST /v1/admin/cache/invalidate — manual cache invalidation.
	mux.Handle("/v1/admin/cache/invalidate", rl(mw.Require(VerbInvalidateCache,
		http.HandlerFunc(makeInvalidateHandler(deps)))))

	// POST /v1/admin/revoke — token/session revocation (E2).
	mux.Handle("/v1/admin/revoke", rl(mw.Require(VerbRevokeToken,
		http.HandlerFunc(makeRevokeHandler(deps)))))

	// GET /v1/admin/audit — audit log query (stub for D4).
	mux.Handle("/v1/admin/audit", rl(mw.Require(VerbReadAudit,
		http.HandlerFunc(handleAuditQuery))))

	return mux
}

// handleStatus returns basic engine status.
// Full implementation will include appliedVersion, appliedDigest,
// uptime, replica count, etc.
func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"admin":  IdentityFromContext(r.Context()).Subject,
	})
}

// handleCacheInvalidate accepts a cache invalidation request.
// Body: {"scope": "tenant"|"subject"|"all", "tenant": "...", "subject": "..."}
// Publishes an EventInvalidate on the event bus so all replicas evict
// matching cache entries by tag (E3).
func makeInvalidateHandler(deps *AdminDeps) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAdminError(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		var req struct {
			Scope   string `json:"scope"`   // "all", "tenant", "subject"
			Tenant  string `json:"tenant"`
			Subject string `json:"subject"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, adminBodyLimit)).Decode(&req); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Scope == "" {
			req.Scope = "all"
		}
		// TC7: validate scope against allowlist.
		if !validScopes[req.Scope] {
			writeAdminError(w, http.StatusBadRequest, "invalid scope: must be one of all, tenant, subject")
			return
		}

		// TC4: stricter rate limit for scope=all (cache-busting DoS prevention).
		if req.Scope == "all" {
			key := httputil.IPKeyFunc(r)
			if !flushLimiter.Allow(key) {
				writeAdminError(w, http.StatusTooManyRequests, "scope=all rate limit exceeded (max 1/60s)")
				return
			}
		}

		// Validate scope-specific fields.
		switch req.Scope {
		case "tenant":
			if req.Tenant == "" {
				writeAdminError(w, http.StatusBadRequest, "tenant field required for scope=tenant")
				return
			}
			if len(req.Tenant) > maxTenantLength {
				writeAdminError(w, http.StatusBadRequest, "tenant too long")
				return
			}
			// TC6: character-set validation (consistent with revoke handler).
			if !isPrintableASCII(req.Tenant) {
				writeAdminError(w, http.StatusBadRequest, "tenant contains invalid characters")
				return
			}
		case "subject":
			if req.Subject == "" {
				writeAdminError(w, http.StatusBadRequest, "subject field required for scope=subject")
				return
			}
			if len(req.Subject) > maxSubjectLength {
				writeAdminError(w, http.StatusBadRequest, "subject too long")
				return
			}
			// TC6: character-set validation (consistent with revoke handler).
			if !isPrintableASCII(req.Subject) {
				writeAdminError(w, http.StatusBadRequest, "subject contains invalid characters")
				return
			}
		}

		// Build invalidation tags from scope.
		var tags []string
		switch req.Scope {
		case "tenant":
			tags = []string{"tenant:" + req.Tenant}
		case "subject":
			tags = []string{"subject:" + req.Subject}
		case "all":
			// "all" scope uses a nil tags slice — the handler interprets
			// this as a full cache flush rather than tag-based eviction.
		}

		// TC8: Perform local invalidation regardless of bus availability.
		localEvicted := 0
		if deps.InvalidateFunc != nil {
			localEvicted = deps.InvalidateFunc(r.Context(), tags)
		}

		// Publish via event bus for cross-replica fan-out.
		remotePublished := false
		if deps.EventBus != nil {
			evt := eventbus.Event{
				Type: eventbus.EventInvalidate,
				Tags: tags,
			}
			if err := deps.EventBus.Publish(r.Context(), evt); err != nil {
				slog.Warn("admin: failed to publish invalidation event", "err", err)
			} else {
				remotePublished = true
			}
		}

		// TC3: Formal audit event for cache invalidation (consistent with revoke).
		adminID := IdentityFromContext(r.Context())
		audit.Default().Record(r.Context(), &audit.Event{
			Timestamp:      time.Now(),
			Tenant:         req.Tenant,
			Subject:        req.Subject,
			IdentitySource: "admin:" + adminID.Subject,
			Decision:       "cache_invalidate",
			DenyReason:     "scope=" + req.Scope,
			Method:         r.Method,
			Path:           r.URL.Path,
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted":         true,
			"scope":            req.Scope,
			"tenant":           req.Tenant,
			"subject":          req.Subject,
			"local_evicted":    localEvicted,
			"remote_published": remotePublished,
		})
	}
}

// makeRevokeHandler returns a handler that writes to the revocation store (E2).
// Body: {"token_hash": "...", "jti": "...", "tenant": "...", "subject": "...", "reason": "...", "ttl": "2h"}
// At least one of jti, token_hash, or subject must be provided.
func makeRevokeHandler(deps *AdminDeps) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAdminError(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		if deps.RevocationStore == nil {
			writeAdminError(w, http.StatusServiceUnavailable, "revocation store not configured")
			return
		}

		// REV8: Bound request body to prevent memory exhaustion.
		r.Body = http.MaxBytesReader(w, r.Body, adminBodyLimit)

		var req struct {
			TokenHash string `json:"token_hash"`
			JTI       string `json:"jti"`
			Tenant    string `json:"tenant"`
			Subject   string `json:"subject"`
			Reason    string `json:"reason"`
			TTL       string `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Require at least one revocation target.
		if req.JTI == "" && req.TokenHash == "" && req.Subject == "" {
			writeAdminError(w, http.StatusBadRequest, "at least one of jti, token_hash, or subject is required")
			return
		}

		// REV1: Validate field lengths and character sets.
		if err := validateRevokeInput(req.JTI, req.TokenHash, req.Subject, req.Tenant, req.Reason); err != "" {
			writeAdminError(w, http.StatusBadRequest, err)
			return
		}

		// Parse and cap TTL.
		var ttl time.Duration
		if req.TTL != "" {
			var err error
			ttl, err = time.ParseDuration(req.TTL)
			if err != nil {
				writeAdminError(w, http.StatusBadRequest, "invalid ttl format")
				return
			}
			if ttl > maxRevocationTTL {
				ttl = maxRevocationTTL
			}
			if ttl <= 0 {
				writeAdminError(w, http.StatusBadRequest, "ttl must be positive")
				return
			}
		}

		// Build revocation entries and event keys.
		var keys []string
		if req.JTI != "" {
			keys = append(keys, "jti:"+req.JTI)
		}
		if req.TokenHash != "" {
			keys = append(keys, "hash:"+req.TokenHash)
		}
		if req.Subject != "" {
			prefix := "sub:"
			if req.Tenant != "" {
				prefix += req.Tenant + ":"
			}
			keys = append(keys, prefix+req.Subject)
		}

		// Write each key to the revocation store.
		for _, key := range keys {
			if err := deps.RevocationStore.Add(r.Context(), revocation.Entry{
				Key:       key,
				Reason:    req.Reason,
				TTL:       ttl,
				RevokedAt: time.Now(),
			}); err != nil {
				// REV5: Do not leak internal error details to the client.
				slog.Error("revocation store write failed", "key", key, "err", err)
				writeAdminError(w, http.StatusInternalServerError, "revocation store unavailable")
				return
			}
		}

		// Publish cross-replica event.
		if deps.EventBus != nil {
			for _, key := range keys {
				_ = deps.EventBus.Publish(r.Context(), eventbus.Event{
					Type: eventbus.EventRevoke,
					Key:  key,
				})
			}
		}

		// REV6: Emit audit event for every revocation action.
		adminID := IdentityFromContext(r.Context())
		audit.Default().Record(r.Context(), &audit.Event{
			Timestamp:      time.Now(),
			Tenant:         req.Tenant,
			Subject:        req.Subject,
			IdentitySource: "admin:" + adminID.Subject,
			Decision:       "revoke",
			DenyReason:     req.Reason,
			Method:         r.Method,
			Path:           r.URL.Path,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted": true,
			"keys":     keys,
			"admin":    adminID.Subject,
		})
	}
}

// validateRevokeInput enforces length and character-set constraints on
// revocation request fields. Returns an error message or "".
func validateRevokeInput(jti, tokenHash, subject, tenant, reason string) string {
	if jti != "" {
		if len(jti) > maxJTILength {
			return "jti exceeds maximum length"
		}
		if !isPrintableASCII(jti) {
			return "jti contains invalid characters"
		}
	}
	if tokenHash != "" {
		if len(tokenHash) > maxTokenHashLength {
			return "token_hash exceeds maximum length"
		}
		if !isHexOrBase64(tokenHash) {
			return "token_hash must be hex or base64 encoded"
		}
	}
	if subject != "" {
		if len(subject) > maxSubjectLength {
			return "subject exceeds maximum length"
		}
		if !isPrintableASCII(subject) {
			return "subject contains invalid characters"
		}
	}
	if tenant != "" {
		if len(tenant) > maxTenantLength {
			return "tenant exceeds maximum length"
		}
		if !isPrintableASCII(tenant) {
			return "tenant contains invalid characters"
		}
	}
	if len(reason) > maxReasonLength {
		return "reason exceeds maximum length"
	}
	return ""
}

// isPrintableASCII returns true if s contains only printable ASCII (0x20-0x7E).
func isPrintableASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// isHexOrBase64 validates that the string looks like hex or base64 output.
func isHexOrBase64(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '+' || r == '/' || r == '=' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// handleAuditQuery serves audit log queries.
// Full implementation lands in D4 (ENT-AUDIT-1).
func handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}

	// TODO(ENT-AUDIT-1): query audit sink backend.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"note": "audit query not yet implemented (Tier D4)",
	})
}
