// Package grpc is the out-of-process plugin host runtime (DESIGN.md §2,
// M10). It registers three factories under the type name "grpc-plugin"
// — one per pipeline stage (identifier / authorizer / mutator) — so any
// config entry of the form
//
//	type: grpc-plugin
//	config:
//	  address: unix:///var/run/lwauth/saml.sock   # or "host:port"
//	  timeout: 200ms                              # per-call deadline (default 1s)
//
// instantiates a thin remote adapter that satisfies the corresponding
// pkg/module interface by calling the plugin over the gRPC services
// defined in api/proto/lightweightauth/plugin/v1/plugin.proto.
//
// Plugins implement one or more of:
//
//   - lightweightauth.plugin.v1.IdentifierPlugin
//   - lightweightauth.plugin.v1.AuthorizerPlugin
//   - lightweightauth.plugin.v1.MutatorPlugin
//
// and listen on a Unix-domain or TCP socket. The lwauth core treats
// them indistinguishably from built-in modules — the same pipeline,
// caching, observability, and audit emission apply.
//
// Security note: plugins run in a separate process so a buggy plugin
// cannot corrupt the auth core's heap, but they share the host's trust
// boundary (anything the plugin is told it can see, it sees). Run
// untrusted plugins under a restrictive kernel sandbox or in a
// dedicated pod.
//
// Lifecycle: today the host assumes the plugin process is supervised
// externally (systemd unit or sidecar container). Spawn / health-check
// / restart handling lives in M11 (resilience).
package grpc
