// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package openapi embeds the LightweightAuth OpenAPI 3.1 document so
// it can be served by the HTTP handler and consumed by tests, codegen
// tools, and `lwauthctl`.
//
// The spec source lives next to this file at lwauth.yaml. The Go
// package is intentionally tiny — just enough to surface the bytes —
// because the spec itself is the contract; this is a transport detail.
//
// Tracked under DOC-OPENAPI-1.
package openapi

import _ "embed"

// Spec is the embedded OpenAPI 3.1 YAML document. It is identical to
// the on-disk lwauth.yaml so a running instance and the repo are
// guaranteed to agree.
//
//go:embed lwauth.yaml
var Spec []byte
