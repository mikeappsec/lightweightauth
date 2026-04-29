package server

// OpenAPI 3.1 handler. The spec lives at
// [api/openapi/lwauth.yaml](../../api/openapi/lwauth.yaml) and is
// embedded into the lwauthd binary via the [openapi] package, so the
// served document and the on-disk source are byte-identical.
//
// Two endpoints share one source: `GET /openapi.yaml` returns the
// bytes verbatim (preserves comments + ordering); `GET /openapi.json`
// returns a JSON-encoded equivalent for tooling that doesn't speak
// YAML. The JSON form is computed lazily on first request and cached.
//
// Tracked under DOC-OPENAPI-1.

import (
	"encoding/json"
	"net/http"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/mikeappsec/lightweightauth/api/openapi"
)

// openAPIJSONOnce caches the YAML->JSON conversion. The conversion is
// deterministic and the embedded YAML never changes at runtime, so we
// do it once on first request and reuse the bytes thereafter. Doing
// it lazily (rather than at package init) keeps process startup snappy
// and means tests that don't touch the endpoint don't pay for the
// parse.
var (
	openAPIJSONOnce sync.Once
	openAPIJSONBuf  []byte
	openAPIJSONErr  error
)

func openAPIJSON() ([]byte, error) {
	openAPIJSONOnce.Do(func() {
		// yaml.v3 decodes into map[string]any with string keys, so
		// the result is directly JSON-serialisable. MarshalIndent
		// gives a readable document on `curl | less`; the
		// whitespace cost is negligible against the 8-10 KiB body.
		var doc any
		if err := yaml.Unmarshal(openapi.Spec, &doc); err != nil {
			openAPIJSONErr = err
			return
		}
		buf, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			openAPIJSONErr = err
			return
		}
		openAPIJSONBuf = buf
	})
	return openAPIJSONBuf, openAPIJSONErr
}

// openAPIJSONHandler serves the embedded spec as JSON.
func openAPIJSONHandler(w http.ResponseWriter, _ *http.Request) {
	buf, err := openAPIJSON()
	if err != nil {
		// A failure here means the embedded YAML was malformed --
		// build-time bug, not a runtime condition. Surface 500
		// rather than panicking the live server.
		http.Error(w, "openapi spec unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(buf)
}

// openAPIYAMLHandler serves the embedded spec verbatim. The YAML form
// preserves comments and field ordering; the JSON form drops both.
func openAPIYAMLHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(openapi.Spec)
}
