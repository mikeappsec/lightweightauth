package admin

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// adminRateLimiter is a simple per-IP token bucket for admin endpoints (TC4).
type adminRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rps     float64
	burst   int
}

type bucket struct {
	tokens   float64
	lastTime time.Time
}

func newAdminRateLimiter(rps float64, burst int) *adminRateLimiter {
	return &adminRateLimiter{
		buckets: make(map[string]*bucket),
		rps:     rps,
		burst:   burst,
	}
}

func (rl *adminRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(rl.burst), lastTime: now}
		rl.buckets[ip] = b
	}

	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.rps
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastTime = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// validScopes is the allowlist for cache invalidation scope (TC7).
var validScopes = map[string]bool{
	"all":     true,
	"tenant":  true,
	"subject": true,
}

// adminLimiter is the package-level rate limiter for admin endpoints.
// 10 requests/second per IP with a burst of 20.
var adminLimiter = newAdminRateLimiter(10, 20)

// NewAdminMux returns an http.Handler that serves all /v1/admin/ endpoints,
// protected by the given middleware. If the middleware is nil or disabled,
// all routes return 404.
func NewAdminMux(mw *Middleware) http.Handler {
	mux := http.NewServeMux()

	if mw == nil || !mw.cfg.Enabled {
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			writeAdminError(w, http.StatusNotFound, "admin endpoints disabled")
		})
		return mux
	}

	// TC4: rate-limit wrapper applied to all admin routes.
	rateLimit := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if !adminLimiter.allow(ip) {
				w.Header().Set("Retry-After", "1")
				writeAdminError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	// GET /v1/admin/status — engine and config status.
	mux.Handle("/v1/admin/status", rateLimit(mw.Require(VerbReadStatus,
		http.HandlerFunc(handleStatus))))

	// POST /v1/admin/cache/invalidate — manual cache invalidation.
	mux.Handle("/v1/admin/cache/invalidate", rateLimit(mw.Require(VerbInvalidateCache,
		http.HandlerFunc(handleCacheInvalidate))))

	// POST /v1/admin/revoke — token/session revocation (stub for E2).
	mux.Handle("/v1/admin/revoke", rateLimit(mw.Require(VerbRevokeToken,
		http.HandlerFunc(handleRevoke))))

	// GET /v1/admin/audit — audit log query (stub for D4).
	mux.Handle("/v1/admin/audit", rateLimit(mw.Require(VerbReadAudit,
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
// Full implementation connects to the cache backend in E1/E3.
func handleCacheInvalidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		Scope   string `json:"scope"`   // "all", "tenant", "subject"
		Tenant  string `json:"tenant"`
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	// TODO(ENT-CACHE-2): wire into cache.Backend tag-based invalidation.
	// For now, log and acknowledge.
	id := IdentityFromContext(r.Context())
	_ = id // will be used in audit

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": true,
		"scope":    req.Scope,
		"tenant":   req.Tenant,
		"subject":  req.Subject,
	})
}

// handleRevoke accepts a token/session revocation request.
// Body: {"token_hash": "...", "jti": "...", "tenant": "...", "subject": "..."}
// Full implementation lands in E2 (M14-REVOCATION).
func handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		TokenHash string `json:"token_hash"`
		JTI       string `json:"jti"`
		Tenant    string `json:"tenant"`
		Subject   string `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// TODO(M14-REVOCATION): write to revocation store.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": true,
		"note":     "revocation store not yet implemented (Tier E2)",
	})
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
