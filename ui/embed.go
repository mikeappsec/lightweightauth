// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package ui provides the embedded SolidJS console for the control plane.
// During development, run `npm run dev` in ui/console/ and proxy from
// the Go server. For production, `npm run build` writes to ui/console/dist/
// which is embedded here.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed console/dist/*
var distFS embed.FS

// Handler returns an http.Handler that serves the embedded SPA.
// All non-API paths fall through to index.html for client-side routing.
func Handler() http.Handler {
	dist, err := fs.Sub(distFS, "console/dist")
	if err != nil {
		panic("ui: embedded dist not found: " + err.Error())
	}

	fileServer := http.FileServer(http.FS(dist))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// If the path looks like a static asset (has extension), serve directly.
		path := r.URL.Path
		if path == "/" || !hasFileExtension(path) {
			// SPA fallback: serve index.html for client-side routes.
			r.URL.Path = "/"
		}

		fileServer.ServeHTTP(w, r)
	})
}

func hasFileExtension(path string) bool {
	lastSlash := strings.LastIndex(path, "/")
	lastDot := strings.LastIndex(path, ".")
	return lastDot > lastSlash
}
